from django.db import models

# Create your models here.
class CachedResult(models.Model):

    ip_addr = models.GenericIPAddressField()
    source = models.CharField(max_length=30)
    updated = models.DateField(auto_now=True)
    result = models.TextField()

    unique_ip_source = models.UniqueConstraint(name='unique_ip_source',
                                               fields=['ip_addr', 'source'])

    class Meta:
        indexes = [
            models.Index(fields=['ip_addr', 'source'])
        ]
