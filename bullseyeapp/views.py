from django.http import HttpResponse
from django.shortcuts import render

# Create your views here.
def get_ip_info(request, ip):
    return HttpResponse(f'Details of {ip}')

def get_ip_range_info(request, ip, cidr):
    return HttpResponse(f'Details of {ip}/{cidr}')
