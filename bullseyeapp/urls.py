from django.urls import path

from . import views

urlpatterns = [
    path('', views.get_landing_page),
    path('logout', views.logout, name='logout'),
    path('ip/<str:ip>', views.get_ip_info, name='ip'),
    path('ip/<str:ip>/<int:cidr>', views.get_ip_range_info)
]
