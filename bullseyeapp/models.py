import datetime

from django.contrib.auth.models import User
from django.db import models
from picklefield.fields import PickledObjectField

class MonthlyStats(models.Model):
    name = models.TextField()
    month = models.DateField(default=datetime.date.today().replace(day=1))
    count = models.IntegerField(default=0)

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
