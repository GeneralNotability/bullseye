import socket

from django.conf import settings
from django.contrib.auth import logout
from django.http import HttpResponse
from django.shortcuts import redirect, render

from .utils import get_ipcheck_data, \
    get_maxmind_data, get_userrights, \
    get_whois_data


def get_landing_page(request):
    return render(request, 'bullseye/index.html')

def get_ip_info(request, ip):
    context = {}
    context['ip'] = ip
    context['data_sources'] = {}
    context['geoips'] = {
        'type': 'FeatureCollection',
        'features': []
    }

    # TODO: cache this in the User model somehow
    context['userrights'] = get_userrights(request)

    get_whois_data(ip, context)

    get_maxmind_data(ip, context)

    get_ipcheck_data(ip, context)

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
