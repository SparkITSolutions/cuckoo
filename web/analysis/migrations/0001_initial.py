# -*- coding: utf-8 -*-
from __future__ import unicode_literals

from django.contrib.auth.models import Group
from django.db import  migrations

from lib.phoenix import constants


class Migration(migrations.Migration):

    dependencies = [
    ]

    operations = [
        Group.objects.get_or_create(name=constants.PUBLISHERS_GROUP)
    ]
