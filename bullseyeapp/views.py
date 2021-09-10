import ipaddress
import socket

from django.conf import settings
from django.contrib.auth import logout
from django.http import HttpResponse
from django.shortcuts import redirect, render
from django.views.decorators.http import require_http_methods

from . import utils


def get_landing_page(request):
    return render(request, 'bullseye/index.html')

@require_http_methods(['GET', 'POST'])
def dartboard(request):
    if request.method == 'GET':
        return render(request, 'bullseye/dartboard.html')
    # guaranteed to be POST now
    context = {}
    context['cdnjs'] = settings.CDNJS
    if hasattr(settings, 'MAPSERVER') and settings.MAPSERVER:
        context['mapserver'] = settings.MAPSERVER
    form_data = request.POST
    geos = []
    ips, errors = utils.parse_ip_form(form_data['dartboardIPs'])
    print(ips, errors)
    context['errors'] = errors
    for ip in ips:
        if hasattr(settings, 'GEOIP_PATH') and settings.GEOIP_PATH:
            geos.append(utils.lookup_maxmind_dartboard(ip))

    context['geoips'] = {
        'type': 'FeatureCollection',
        'features': geos
    }
    context['ips'] = ips
    context['errors'] = errors
    return render(request, 'bullseye/dartboard-map.html', context)


def get_ip_info(request, ip):
    if not request.user.is_authenticated:
        return render(request, 'bullseye/notauthed.html')
    context = {}
    context['ip'] = ip
    context['data_sources'] = {}
    context['geoips'] = {
        'type': 'FeatureCollection',
        'features': []
    }

    # TODO: cache this in the User model somehow
    utils.get_userrights(request, context)

    utils.get_relevant_blocks(ip, context)

    utils.get_whois_data(ip, context)

    utils.get_maxmind_data(ip, context)

    utils.get_ipcheck_data(ip, context)

    spur_authorized_groups = set(['steward', 'checkuser'])

    if spur_authorized_groups.intersection(set(context['userrights'])) or\
            request.user.groups.filter(name='trusted').exists():
        utils.get_spur_data(ip, context)

    shodan_authorized_groups = set(['sysop', 'global-sysop', 'steward', 'checkuser'])

    if shodan_authorized_groups.intersection(set(context['userrights'])) or\
            request.user.groups.filter(name='trusted').exists():
        utils.get_shodan_data(ip, context)

    try:
        context['rdns'] = socket.gethostbyaddr(ip)[0]
    except socket.herror:
        pass

    context['cdnjs'] = settings.CDNJS
    if hasattr(settings, 'MAPSERVER') and settings.MAPSERVER:
        context['mapserver'] = settings.MAPSERVER
    return render(request, 'bullseye/ip.html', context)

def get_ip_range_info(request, ip, cidr):
    return HttpResponse(f'Details of {ip}/{cidr}')

def logout_view(request):
    logout(request)
    return redirect(get_landing_page)
