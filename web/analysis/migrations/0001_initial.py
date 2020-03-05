# -*- coding: utf-8 -*-
from __future__ import unicode_literals

from django.db import  migrations, models

from django.conf import settings


class Migration(migrations.Migration):

    dependencies = [
        migrations.swappable_dependency(settings.AUTH_USER_MODEL),
        ("auth","0006_require_contenttypes_0002")
    ]

    operations = [
        migrations.CreateModel(
            name='UsageLimits',
            fields=[
                ('id', models.AutoField(verbose_name='ID', serialize=False, auto_created=True, primary_key=True)),
                ('allowed_per_day', models.IntegerField(default=25)),
                ('used_today', models.IntegerField(default=0)),
                ('last_date_checked', models.DateField(auto_now=True)),
                ('user', models.OneToOneField(to=settings.AUTH_USER_MODEL)),
            ],
        ),
    ]
