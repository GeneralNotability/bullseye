from django.urls import path

from . import views

urlpatterns = [
    path('<str:ip>', views.get_ip_info),
    path('<str:ip>/<int:cidr>', views.get_ip_range_info),
]
