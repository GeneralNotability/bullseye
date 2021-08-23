import requests


def get_whois_data(ip):
    r = requests.get(f'https://whois-dev.toolforge.org/w/{ip}/lookup/json')
    print(r.text)
    return r.json()
