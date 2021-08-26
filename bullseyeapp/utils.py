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

def get_userrights(request):
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
        print(cached.updated)
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
        #result = get_cached(ip, 'shodan')
        result = None
        if not result:
            try:
                api = shodan.Shodan(settings.SHODAN_KEY)
                result = api.host(ip)
                #update_cached(ip, 'shodan', result)
            except Exception as e:
                print(e)
                context['data_sources']['shodan'] = False
                return
        print(result)
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
        # summary = []

        # context['shodan']['summary'] = ', '.join(summary)
    else:
        context['data_sources']['shodan'] = False
