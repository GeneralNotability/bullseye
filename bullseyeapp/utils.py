import requests
from requests.exceptions import HTTPError

from django.conf import settings
from django.contrib.gis.geoip2 import GeoIP2


def has_group(key, wikidict):
    return 'groups' in wikidict and key in wikidict['groups']

def get_userrights(request, context):
    user = request.user
    userrights = ['anonymous']
    if not user.is_authenticated:
        return
    try:
        payload = {
            'action': 'query',
            'meta': 'globaluserinfo',
            'guiuser': user.username,
            'guiprop': 'groups|merged',
            'format': 'json'
        }
        r = requests.get('https://www.mediawiki.org/w/api.php', params=payload)
        results = r.json()
        if any(has_group('sysop', x) for x in results['query']['globaluserinfo']['merged']):
            userrights.append('sysop')
        if 'global-sysop' in results['query']['globaluserinfo']['groups']:
            userrights.append('global-sysop')
        if any(has_group('checkuser', x) for x in results['query']['globaluserinfo']['merged']):
            userrights.append('checkuser')
        if 'steward' in results['query']['globaluserinfo']['groups']:
            userrights.append('steward')
    except HTTPError as e:
        print(e)
    return userrights


def get_whois_data(ip, context):
    try:
        r = requests.get(f'https://whois.toolforge.org/w/{ip}/lookup/json')
        r.raise_for_status()
        context['whois'] = r.json()
        context['data_sources']['whois'] = True
    except HTTPError as e:
        print(e)
        context['data_sources']['whois'] = False

def get_maxmind_data(ip, context):
    if hasattr(settings, 'GEOIP_PATH') and settings.GEOIP_PATH:
        try:
            g = GeoIP2()
            context['maxmind'] = g.city(ip)
            context['data_sources']['maxmind'] = True
            context['geoips']['features'].append({
                'type': 'Feature',
                'geometry': {
                    'type': 'Point',
                    'coordinates': [
                        context['maxmind']['longitude'],
                        context['maxmind']['latitude']
                    ]
                },
                'properties': {
                    'description': 'Maxmind GeoLite2',
                    'color': 'blue'
                }
            })
        except Exception as e:
            context['data_sources']['maxmind'] = False
    else:
        context['data_sources']['maxmind'] = False

def get_ipcheck_data(ip, context):
    if hasattr(settings, 'IPCHECK_KEY') and settings.IPCHECK_KEY:
        try:
            r = requests.get(f'https://ipcheck.toolforge.org/index.php?ip={ip}&api=true&key={settings.IPCHECK_KEY}')
            r.raise_for_status()
            context['ipcheck'] = r.json()
            context['data_sources']['ipcheck'] = True

            # Summarize the important bits
            summary = []
            if context['ipcheck']['webhost']['result']['webhost']:
                summary.append('webhost')
            if context['ipcheck']['proxycheck']['result']['proxy']:
                summary.append('proxy (proxycheck)')
            if context['ipcheck']['stopforumspam']['result']['appears']:
                summary.append('on SFS blacklist')
            if not context['ipcheck']['computeHosts']['result']['cloud'].startswith('This IP is not'):
                summary.append(f"cloud ({context['ipcheck']['computeHosts']['result']['cloud']})")
            if context['ipcheck']['spamcop']['result']['listed']:
                summary.append('on SpamCop blacklist')
            if context['ipcheck']['tor']['result']['tornode']:
                summary.append('TOR node')
            context['ipcheck']['summary'] = ', '.join(summary)
        except HTTPError:
            context['data_sources']['ipcheck'] = False
    else:
        context['data_sources']['ipcheck'] = False
