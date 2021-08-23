import socket

from django.conf import settings
from django.contrib.gis.geoip2 import GeoIP2
from django.http import HttpResponse
from django.shortcuts import render
from requests.exceptions import HTTPError

from .utils import get_whois_data
def get_ip_info(request, ip):
    context = {}
    context['ip'] = ip
    context['data_sources'] = {}

    try:
        whois_data = get_whois_data(ip)
        context['whois'] = whois_data
        context['data_sources']['whois'] = True
    # FIXME: bare except
    except HTTPError:
        context['data_sources']['whois'] = False

    if hasattr(settings, 'GEOIP_PATH') and settings.GEOIP_PATH:
        try:
            g = GeoIP2()
            context['maxmind'] = g.city(ip)
            context['data_sources']['maxmind'] = True
        except Exception as e:
            print(e)
            context['data_sources']['maxmind'] = False
    
    try:
        context['rdns'] = socket.gethostbyaddr(ip)[0]
    except socket.herror:
        pass

    return render(request, 'bullseye/ip.html', context)

def get_ip_range_info(request, ip, cidr):
    return HttpResponse(f'Details of {ip}/{cidr}')
