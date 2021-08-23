import requests


def get_whois_data(ip):
    r = requests.get(f'https://whois-dev.toolforge.org/w/{ip}/lookup/json')
    r.raise_for_status()
    return r.json()
