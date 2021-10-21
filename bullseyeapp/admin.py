from django.contrib import admin
from .models import ExtraUserData, MonthlyStats, UserRight

# Register your models here.
admin.site.register(ExtraUserData)
admin.site.register(MonthlyStats)
admin.site.register(UserRight)
