import ipaddress

from deepmerge import always_merger
from multiprocessing.pool import ThreadPool

from django.conf import settings
from django.contrib.auth import logout
from django.db.models import Q
from django.http import HttpResponse
from django.shortcuts import redirect, render
from django.views.decorators.http import require_http_methods

from . import forms
from . import utils
from .models import ExtraUserData


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

    with ThreadPool() as pool:
        queries = []
        # TODO: cache this in the User model somehow
        userrights_query = pool.apply_async(utils.get_userrights, (request.user,))

        queries.append(pool.apply_async(utils.get_whois_data, (ip,)))
        queries.append(pool.apply_async(utils.get_maxmind_data, (ip,)))
        queries.append(pool.apply_async(utils.get_rdns, (ip,)))
        queries.append(pool.apply_async(utils.get_ipcheck_data, (ip,)))
        queries.append(pool.apply_async(utils.get_bgpview_data, (ip,)))
    
        # Need the wiki query to finish to get the target wikis and access rights
        userrights_ctx = userrights_query.get()
        always_merger.merge(context, userrights_ctx)
        if 'usergroups' in request.session and request.session['usergroups']:
            usergroups = request.session['usergroups']
        else:
            userdata = ExtraUserData.objects.get(user=request.user)
            usergroups = []
            # Convert to list - we can't serialize userdata as-is
            for group in userdata.userrights.all():
                usergroups.append(group.name)
            request.session['usergroups'] = usergroups
        queries.append(pool.apply_async(utils.get_relevant_blocks, (ip, context['targetwikis'])))
    
        if 'steward' in usergroups or 'checkuser' in usergroups or 'staff' in usergroups or \
                request.user.groups.filter(name='trusted').count():
            queries.append(pool.apply_async(utils.get_spur_data, (ip,)))
    
        if 'steward' in usergroups or 'checkuser' in usergroups or 'staff' in usergroups or 'sysop' in usergroups or 'global-sysop' in usergroups or \
                request.user.groups.filter(name='trusted').count():
            queries.append(pool.apply_async(utils.get_shodan_data, (ip,)))

        for query in queries:
            query_ctx = query.get()
            always_merger.merge(context, query_ctx)

        
    utils.increment_user_queries(request.user)
    context['cdnjs'] = settings.CDNJS
    if hasattr(settings, 'MAPSERVER') and settings.MAPSERVER:
        context['mapserver'] = settings.MAPSERVER
    return render(request, 'bullseye/ip.html', context)

def get_ip_range_info(request, ip, cidr):
    if not request.user.is_authenticated:
        return render(request, 'bullseye/notauthed.html')
    context = {}
    context['searched_range'] = ip + '/' + str(cidr)
    context['ip'] = ip
    context['data_sources'] = {}
    context['geoips'] = {
        'type': 'FeatureCollection',
        'features': []
    }

    with ThreadPool() as pool:
        queries = []
        # TODO: cache this in the User model somehow
        userrights_query = pool.apply_async(utils.get_userrights, (request.user,))

        queries.append(pool.apply_async(utils.get_whois_data, (ip,)))
        queries.append(pool.apply_async(utils.get_maxmind_data, (ip,)))
        queries.append(pool.apply_async(utils.get_rdns, (ip,)))
        queries.append(pool.apply_async(utils.get_ipcheck_data, (ip,)))
        queries.append(pool.apply_async(utils.get_bgpview_data, (ip,)))
    
        # Need the wiki query to finish to get the target wikis and access rights
        userrights_ctx = userrights_query.get()
        always_merger.merge(context, userrights_ctx)
        if 'usergroups' in request.session and request.session['usergroups']:
            usergroups = request.session['usergroups']
        else:
            userdata = ExtraUserData.objects.get(user=request.user)
            usergroups = []
            # Convert to list - we can't serialize userdata as-is
            for group in userdata.userrights.all():
                usergroups.append(group.name)
            request.session['usergroups'] = usergroups
        queries.append(pool.apply_async(utils.get_relevant_blocks, (ip, context['targetwikis'])))
    
        if 'steward' in usergroups or 'checkuser' in usergroups or 'staff' in usergroups or \
                request.user.groups.filter(name='trusted').count():
            queries.append(pool.apply_async(utils.get_spur_data, (ip,)))
    
        if 'steward' in usergroups or 'checkuser' in usergroups or 'staff' in usergroups or 'sysop' in usergroups or 'global-sysop' in usergroups or \
                request.user.groups.filter(name='trusted').count():
            queries.append(pool.apply_async(utils.get_shodan_data, (ip,)))

        for query in queries:
            query_ctx = query.get()
            always_merger.merge(context, query_ctx)

        
    utils.increment_user_queries(request.user)
    context['cdnjs'] = settings.CDNJS
    if hasattr(settings, 'MAPSERVER') and settings.MAPSERVER:
        context['mapserver'] = settings.MAPSERVER
    return render(request, 'bullseye/ip_range.html', context)

@require_http_methods(['GET', 'POST'])
def update_wiki_prefs(request):
    if not request.user.is_authenticated:
        return render(request, 'bullseye/notauthed.html')
    sitematrix = utils.get_sitematrix()
    sites_grouped = {}
    valid_sites = []
    for entry in sitematrix['sitematrix']:
        if entry in ['specials', 'count']:
            continue
        for site in sitematrix['sitematrix'][entry]['site']:
            if 'closed' in site or 'private' in site or 'fishbowl' in site:
                continue
            if not site['code'] in sites_grouped:
                sites_grouped[site['code']] = []
            sites_grouped[site['code']].append((site['dbname'], site['dbname']))
            valid_sites.append(site['dbname'])

    sites_grouped['special'] = []
    for site in sitematrix['sitematrix']['specials']:
        if 'closed' in site or 'private' in site or 'fishbowl' in site:
            continue
        sites_grouped['special'].append((site['dbname'], site['dbname']))
        valid_sites.append(site['dbname'])
    sites = []
    for k,v in sites_grouped.items():
        sites.append((k, v))
    userrights = utils.get_userrights(request.user)
    if request.method == 'POST':
        form = forms.WikiForm(data=request.POST, choices=sites, initial={'wikis': list(userrights['targetwikis'])})
        if form.is_valid():
            print(form.cleaned_data)
            print(form.cleaned_data['wikis'])
            userdata = ExtraUserData.objects.get(user=request.user)
            userdata.targetwikis = form.cleaned_data['wikis']
            userdata.save()
            return redirect(get_landing_page)
    else:
        # Doing this to force default group creation if needed
        form = forms.WikiForm(choices=sites, initial={'wikis': list(userrights['targetwikis'])})
    return render(request, 'bullseye/wikiprefs.html', {'form': form, 'cdnjs': settings.CDNJS})

def logout_view(request):
    logout(request)
    return redirect(get_landing_page)
