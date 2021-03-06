import datetime

from django.contrib.auth.models import User
from django.db import models
from django.db.models import UniqueConstraint
from django.utils import timezone
from picklefield.fields import PickledObjectField

class MonthlyStats(models.Model):
    name = models.CharField(null=False, blank=False, max_length=255)
    month = models.DateField(default=timezone.now().date().replace(day=1))
    count = models.IntegerField(default=0)

    unique_name_month = UniqueConstraint(name='unique_name_month', fields=['name', 'month'])

    def __str__(self):
        return f'{self.name} {self.month.month}/{self.month.year}: {self.count}'

    class Meta:
        verbose_name = 'Monthly Stats'
        verbose_name_plural = 'Monthly Stats'


class UserRight(models.Model):
    name = models.TextField()
    stats = models.ManyToManyField(MonthlyStats)

    def __str__(self):
        return self.name

    class Meta:
        verbose_name = 'User Right'
        verbose_name_plural = 'User Rights'


class ExtraUserData(models.Model):
    user = models.OneToOneField(User, on_delete=models.CASCADE)
    userrights = models.ManyToManyField(UserRight)
    targetwikis = PickledObjectField()
    last_updated = models.DateTimeField(auto_now=True)
    stats = models.ManyToManyField(MonthlyStats)

    def __str__(self):
        return self.user.username

    class Meta:
        verbose_name = 'Extra User Data'
        verbose_name_plural = 'Extra User Data'
