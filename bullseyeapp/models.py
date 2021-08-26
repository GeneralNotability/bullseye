from django.db import models
from picklefield.fields import PickledObjectField

# Create your models here.
class CachedResult(models.Model):

    ip_addr = models.GenericIPAddressField(null=False)
    source = models.CharField(max_length=30, null=False)
    updated = models.DateTimeField(auto_now=True)
    result = PickledObjectField()

    unique_ip_source = models.UniqueConstraint(name='unique_ip_source',
                                               fields=['ip_addr', 'source'])

    class Meta:
        indexes = [
            models.Index(fields=['ip_addr', 'source'])
        ]
