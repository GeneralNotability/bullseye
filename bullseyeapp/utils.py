import datetime
import json
import requests
from requests.exceptions import HTTPError

import shodan
from django.conf import settings
from django.contrib.gis.geoip2 import GeoIP2
from django.db.models import Model

from .models import CachedResult


def has_group(key, wikidict):
    return 'groups' in wikidict and key in wikidict['groups']

def get_userrights(request, context):
    user = request.user
    userrights = set()
    targetwikis = set()
    if not user.is_authenticated:
        context['userrights'] = userrights
        context['targetwikis'] = set(['enwiki'])
        return
    try:
        payload = {
            'action': 'query',
            'meta': 'globaluserinfo',
            'guiuser': user.username,
            'guiprop': 'groups|merged',
            'format': 'json'
        }
        r = requests.get('https://meta.wikimedia.org/w/api.php', params=payload)
        result = r.json()
        targetwikis.add(result['query']['globaluserinfo']['home'])
        acctwikis = result['query']['globaluserinfo']['merged']
        for w in acctwikis:
            if has_group('checkuser', w):
                userrights.add('checkuser')
                targetwikis.add(w['wiki'])
            elif has_group('sysop', w):
                userrights.add('sysop')
                targetwikis.add(w['wiki'])
        if 'steward' in result['query']['globaluserinfo']['groups']:
            userrights.add('steward')
        if 'global-sysop' in result['query']['globaluserinfo']['groups']:
            userrights.add('global-sysop')
    except HTTPError as e:
        print(e)
    context['targetwikis'] = targetwikis
    context['userrights'] = userrights

def get_blocks(ip, context):
    user = request.user
    userrights = ['anonymous']
    if not user.is_authenticated:
        return userrights
    try:
        payload = {
            'action': 'query',
            'meta': 'globaluserinfo',
            'guiuser': user.username,
            'guiprop': 'groups|merged',
            'format': 'json'
        }
        r = requests.get('https://www.mediawiki.org/w/api.php', params=payload)
        result = r.json()
        if any(has_group('sysop', x) for x in result['query']['globaluserinfo']['merged']):
            userrights.append('sysop')
        if 'global-sysop' in result['query']['globaluserinfo']['groups']:
            userrights.append('global-sysop')
        if any(has_group('checkuser', x) for x in result['query']['globaluserinfo']['merged']):
            userrights.append('checkuser')
        if 'steward' in result['query']['globaluserinfo']['groups']:
            userrights.append('steward')
    except HTTPError as e:
        print(e)
    return userrights

def get_cached(ip, source):
    try:
        cached = CachedResult.objects.get(ip_addr=ip, source=source)
        if cached.updated > datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(days=2):
            return cached.result
        return None
    except CachedResult.DoesNotExist:
        return None

def update_cached(ip, source, result):
    try:
        cached = CachedResult.objects.get(ip_addr=ip, source=source)
    except CachedResult.DoesNotExist:
        cached = CachedResult(ip_addr=ip, source=source)
    cached.result = result
    cached.save()

def get_whois_data(ip, context):
    result = get_cached(ip, 'whois')
    if not result:
        try:
            payload = {
                'ip': ip,
                'lookup': 'true',
                'format': 'json'
            }
            r = requests.get('https://whois-referral.toolforge.org/w/gateway.py', params=payload)
            r.raise_for_status()
            result = r.json()
            update_cached(ip, 'whois', result)
        except HTTPError as e:
            print(e)
            context['data_sources']['whois'] = False
            return

    context['whois'] = result
    context['isp'] = result['asn_description']
    context['range'] = result['asn_cidr']
    if 'geo_ipinfo' in result:
        context['location'] = result['geo_ipinfo']
    context['data_sources']['whois'] = True

def get_maxmind_data(ip, context):
    if hasattr(settings, 'GEOIP_PATH') and settings.GEOIP_PATH:
        result = get_cached(ip, 'maxmind')
        if not result:
            try:
                g = GeoIP2()
                result = g.city(ip)
                update_cached(ip, 'maxmind', result)
            except Exception as e:
                context['data_sources']['maxmind'] = False
                return

        context['maxmind'] = result
        context['data_sources']['maxmind'] = True
        context['geoips']['features'].append({
            'type': 'Feature',
            'geometry': {
                'type': 'Point',
                'coordinates': [
                    result['longitude'],
                    result['latitude']
                ]
            },
            'properties': {
                'description': 'Maxmind GeoLite2',
                'color': 'blue'
            }
        })
        context['location'] = f'{result["city"]}, {result["region"]}, {result["country_name"]}'
    else:
        context['data_sources']['maxmind'] = False

def get_ipcheck_data(ip, context):
    if hasattr(settings, 'IPCHECK_KEY') and settings.IPCHECK_KEY:
        result = get_cached(ip, 'ipcheck')
        if not result:
            try:
                r = requests.get(f'https://ipcheck.toolforge.org/index.php?ip={ip}&api=true&key={settings.IPCHECK_KEY}')
                r.raise_for_status()
                result = r.json()
                update_cached(ip, 'ipcheck', result)
            except HTTPError:
                context['data_sources']['ipcheck'] = False
                return

        context['ipcheck'] = result
        context['data_sources']['ipcheck'] = True

        # Summarize the important bits
        summary = []
        if result['webhost']['result']['webhost']:
            summary.append('webhost')
        if result['proxycheck']['result']['proxy']:
            summary.append('proxy (proxycheck)')
        if result['stopforumspam']['result']['appears']:
            summary.append('on SFS blacklist')
        if not result['computeHosts']['result']['cloud'].startswith('This IP is not'):
            summary.append(f"cloud ({result['computeHosts']['result']['cloud']})")
        if result['spamcop']['result']['listed']:
            summary.append('on SpamCop blacklist')
        if result['tor']['result']['tornode']:
            summary.append('TOR node')
        context['ipcheck']['summary'] = ', '.join(summary)
    else:
        context['data_sources']['ipcheck'] = False


def get_spur_data(ip, context):
    if hasattr(settings, 'SPUR_KEY') and settings.SPUR_KEY:
        result = get_cached(ip, 'spur')
        if not result:
            try:
                r = requests.get(f'https://api.spur.us/v1/context/{ip}', headers={'Token': settings.SPUR_KEY})
                r.raise_for_status()
                result = r.json()
                update_cached(ip, 'spur', result)
            except HTTPError as e:
                print(e)
                context['data_sources']['spur'] = False
                return
        context['spur'] = result
        context['data_sources']['spur'] = True
        if 'geoPrecision' in result and result['geoPrecision']['exists']:
            context['geoips']['features'].append({
                'type': 'Feature',
                'geometry': {
                    'type': 'Point',
                    'coordinates': [
                        result['geoPrecision']['point']['longitude'],
                        result['geoPrecision']['point']['latitude']
                    ]
                },
                'properties': {
                    'description': 'Spur (usage location)',
                    'color': 'red'
                }
            })
        summary = []
        if result['vpnOperators']['exists']:
            summary.append('VPN')
            # Prettify
            context['spur']['vpns'] = ', '.join([x['name'] for x in result['vpnOperators']['operators']])

        if result['deviceBehaviors']['exists']:
            context['spur']['behaviors'] = ', '.join([x['name'] for x in result['deviceBehaviors']['behaviors']])

        if result['proxiedTraffic']['exists']:
            summary.append('callback proxy')
            # Prettify
            context['spur']['proxies'] = ', '.join([f'{x["name"]} ({x["type"]})' for x in result['proxiedTraffic']['proxies']])

        if result['wifi']['exists']:
            summary.append('wifi')
            # Prettify
            context['spur']['ssids'] = ', '.join(result['wifi']['ssids'])

        context['spur']['summary'] = ', '.join(summary)

    else:
        context['data_sources']['spur'] = False


def get_shodan_data(ip, context):
    if hasattr(settings, 'SHODAN_KEY') and settings.SHODAN_KEY:
        result = get_cached(ip, 'shodan')
        result = None
        if not result:
            try:
                api = shodan.Shodan(settings.SHODAN_KEY)
                result = api.host(ip)
                update_cached(ip, 'shodan', result)
            except Exception as e:
                print(e)
                context['data_sources']['shodan'] = False
                return
        context['shodan'] = result
        context['data_sources']['shodan'] = True
        if 'isp' in result:
            context['isp'] = result['isp']

        if 'longitude' in result and 'latitude' in result:
            context['geoips']['features'].append({
                'type': 'Feature',
                'geometry': {
                    'type': 'Point',
                    'coordinates': [
                        result['longitude'],
                        result['latitude']
                    ]
                },
                'properties': {
                    'description': 'Shodan',
                    'color': 'orange'
                }
            })
        context['shodan']['open_ports'] = ', '.join([str(x) for x in result['ports']])
        context['shodan']['host_list'] = ', '.join(result['hostnames'])
        context['shodan']['domain_list'] = ', '.join(result['domains'])
        summary = []

        if 80 in result['ports'] or 443 in result['ports']:
            summary.append('webhost')
        if 1194 in result['ports']:
            summary.append('OpenVPN')
        if 3128 in result['ports']:
            summary.append('squid')

        context['shodan']['summary'] = ', '.join(summary)
    else:
        context['data_sources']['shodan'] = False

def get_sitematrix():

    sitematrix = get_cached('127.0.0.1', 'sitematrix')
    # Get/update sitematrix codes
    if not sitematrix:
        try:
            payload = {
                'action': 'sitematrix',
                'format': 'json'
            }
            r = requests.get('https://meta.wikimedia.org/w/api.php', params=payload)
            r.raise_for_status()
            sitematrix = r.json()
            update_cached('127.0.0.1', 'sitematrix', sitematrix)
        except HTTPError as e:
            print(e)
            return
    return sitematrix

def get_relevant_blocks(ip, context):
    matrix = get_sitematrix()
    context['blocks'] = {}
    # Global blocks
    get_globalblockstatus(ip, context)
    # Local blocks
    targets = []
    for entry in matrix['sitematrix']:
        if entry in ['specials', 'count']:
            continue
        for site in matrix['sitematrix'][entry]['site']:
            if site['dbname'] in context['targetwikis']:
                targets.append(site)
    for site in matrix['sitematrix']['specials']:
        if site['dbname'] in context['targetwikis']:
            targets.append(site)
    for target in targets:
        get_blockstatus(ip, context, target)
    summary = []
    if context['globalblocks']:
        summary.append('global block')
    for (wiki, block) in context['blocks'].items():
        if not block:
            continue
        blocktype = 'block'
        for blockentry in block:
            print(blockentry)
            if not blockentry['anononly']:
                blocktype = 'hardblock'
        summary.append(f'{wiki} {blocktype}')

        context['blocksummary'] = ', '.join(summary)

def get_blockstatus(ip, context, wiki):
    url = wiki['url']
    wikiname = wiki['dbname']
    try:
        payload = {
            'action': 'query',
            'list': 'blocks',
            'bkip': ip,
            'formatversion': 2,
            'format': 'json'
        }
        r = requests.get(url + '/w/api.php', params=payload)
        r.raise_for_status()
        result = r.json()
        blocks = result['query']['blocks']
        context['blocks'][wikiname] = blocks
    except HTTPError as e:
        print(e)

def get_globalblockstatus(ip, context):
    context['globalblocks'] = []
    try:
        payload = {
            'action': 'query',
            'list': 'globalblocks',
            'bgip': ip,
            'bgprop': 'address|range|reason|timestamp|by|expiry',
            'format': 'json'
        }
        r = requests.get('https://meta.wikimedia.org/w/api.php', params=payload)
        r.raise_for_status()
        result = r.json()
        context['globalblocks'] = result['query']['globalblocks']
    except HTTPError as e:
        print(e)
