# Copyright (C) 2010-2013 Claudio Guarnieri.
# Copyright (C) 2014-2016 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file "docs/LICENSE" for copying permission.

from django.conf.urls import url

from . import views

urlpatterns = [
    url(r"^$", views.index),
    url(r"^submit/$", views.submit),
    url(r"^pcap/(?P<analysis_id>.+)/$", views.pcap, name="hunting_pcap"),
    url(r"^(?P<task_id>[a-zA-Z0-9\-]+)/$", views.report, name="hunting_report"),
    url(r"^status/(?P<task_id>.+)$", views.status),
    url(r"^yara_file/(?P<hunt_uuid>.+)$", views.yara_file, name="hunting_yara_file"),
    url(r"^yara_download/(?P<hunt_result_id>.+)/(?P<index>.+)$", views.yara_download, name="hunting_yara_download"),
    url(r"^suri_file/(?P<hunt_uuid>.+)$", views.suri_file, name="hunting_suri_file"),
    url(r"^ajax/hunt_data/(?P<task_id>.+)$", views.get_hunt_data),
    url(r"^(?P<hunt_uuid>[a-zA-Z0-9\-]+)/ajax/publish/$", views.publish)

]
