# -*- coding: utf-8 -*-
from __future__ import unicode_literals

from django.conf import settings
from django.db import migrations

from lib.phoenix import constants


def forwards_func(apps, schema_editor):
    group = apps.get_model("auth","Group")
    db_alias = schema_editor.connection.alias
    group.objects.using(db_alias).get_or_create(name=constants.PUBLISHERS_GROUP)

def reverse_func(apps, schema_editor):
    group = apps.get_model("auth", "Group")
    db_alias = schema_editor.connection.alias
    group.objects.using(db_alias).filter(name=constants.PUBLISHERS_GROUP).delete()

class Migration(migrations.Migration):

    dependencies = [
        migrations.swappable_dependency(settings.AUTH_USER_MODEL),
        ("auth","0006_require_contenttypes_0002")
    ]

    operations = [
        migrations.RunPython(forwards_func, reverse_func)
    ]
