from django.urls import path

from . import views

urlpatterns = [
    path('', views.get_landing_page, name='landing_page'),
    path('wikiprefs', views.update_wiki_prefs, name='update_wiki_prefs'),
    path('logout', views.logout_view, name='logout'),
    path('dartboard', views.dartboard, name='dartboard'),
    path('ip/<str:ip>', views.get_ip_info, name='ip'),
    path('ip/<str:ip>/<int:cidr>', views.get_ip_range_info)
]
