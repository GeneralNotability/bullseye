from django.urls import path

from . import views

urlpatterns = [
    path('', views.get_landing_page),
    path('logout', views.logout, name='logout'),
    path('<str:ip>', views.get_ip_info, name='ip'),
    path('<str:ip>/<int:cidr>', views.get_ip_range_info)
]
