from django.urls import path

from . import views

urlpatterns = [
    path('', views.get_landing_page, name='landing_page'),
    path('wikiprefs', views.update_wiki_prefs, name='update_wiki_prefs'),
    path('logout', views.logout_view, name='logout'),
    path('dartboard', views.dartboard, name='dartboard'),
    path('ip/<str:ip>', views.render_ip_info, name='ip'),
    path('ip/<str:ip>/<int:cidr>', views.get_ip_range_info),
    path('api/ip/<str:ip>', views.rest_ip_info),
    path('api/bulk_ip', views.rest_bulk_ip_info)
]
