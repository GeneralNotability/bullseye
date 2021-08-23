from django.http import HttpResponse
from django.shortcuts import render

# Create your views here.
def get_ip_info(request, ip):
    context = {}
    context['ip'] = ip
    return render(request, 'bullseye/ip.html', context)

def get_ip_range_info(request, ip, cidr):
    return HttpResponse(f'Details of {ip}/{cidr}')
