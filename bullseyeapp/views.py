import socket

from django.conf import settings
from django.http import HttpResponse
from django.shortcuts import render

from .utils import get_ipcheck_data, \
    get_maxmind_data, get_whois_data

def get_ip_info(request, ip):
    context = {}
    context['ip'] = ip
    context['data_sources'] = {}
    context['geoips'] = {
        'type': 'FeatureCollection',
        'features': []
    }

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
