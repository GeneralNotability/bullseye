# Generated by Django 3.2.6 on 2021-08-26 15:13

from django.db import migrations, models
import picklefield.fields


class Migration(migrations.Migration):

    initial = True

    dependencies = [
    ]

    operations = [
        migrations.CreateModel(
            name='CachedResult',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('ip_addr', models.GenericIPAddressField()),
                ('source', models.CharField(max_length=30)),
                ('updated', models.DateTimeField(auto_now=True)),
                ('result', picklefield.fields.PickledObjectField(editable=False)),
            ],
        ),
        migrations.AddIndex(
            model_name='cachedresult',
            index=models.Index(fields=['ip_addr', 'source'], name='bullseyeapp_ip_addr_30677f_idx'),
        ),
    ]
