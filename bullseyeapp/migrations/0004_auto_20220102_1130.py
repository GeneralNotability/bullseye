# Generated by Django 3.2.6 on 2022-01-02 16:30

import datetime
from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('bullseyeapp', '0003_alter_monthlystats_month'),
    ]

    operations = [
        migrations.AlterField(
            model_name='monthlystats',
            name='month',
            field=models.DateField(default=datetime.date(2022, 1, 1)),
        ),
        migrations.AlterField(
            model_name='monthlystats',
            name='name',
            field=models.CharField(max_length=255),
        ),
    ]
