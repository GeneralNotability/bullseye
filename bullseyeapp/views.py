from django.http import HttpResponse
from django.shortcuts import render

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
    except:
        context['data_sources']['whois'] = False

    return render(request, 'bullseye/ip.html', context)

def get_ip_range_info(request, ip, cidr):
    return HttpResponse(f'Details of {ip}/{cidr}')
