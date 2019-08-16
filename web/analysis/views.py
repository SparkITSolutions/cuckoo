# Copyright (C) 2010-2013 Claudio Guarnieri.
# Copyright (C) 2014-2016 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import calendar
import datetime
import fnmatch
import json
import mimetypes
import os
import random
import re
import sys
import urllib
import zipfile
import cProfile
import pandas as pd

from cStringIO import StringIO

from bson.objectid import ObjectId
from django.conf import settings
from django.http import HttpResponse, StreamingHttpResponse, FileResponse, JsonResponse
from django.contrib.auth.decorators import login_required, user_passes_test

from django.shortcuts import render, redirect
from django.views.decorators.http import require_safe
from django.views.decorators.csrf import csrf_exempt

import pymongo
from bson.objectid import ObjectId
from django.core.exceptions import PermissionDenied, ObjectDoesNotExist
from gridfs import GridFS
from web.tlp_methods import get_tlp_users, create_tlp_query

from lib.cuckoo.common.config import Config

sys.path.insert(0, settings.CUCKOO_PATH)

from lib.cuckoo.core.database import Database, TASK_PENDING, TASK_COMPLETED, TASK_REPORTED, Task
from lib.cuckoo.common.utils import store_temp_file, versiontuple
from lib.cuckoo.common.constants import CUCKOO_ROOT, LATEST_HTTPREPLAY
from lib.tldr.tldr import run_tldr
from lib.api_fingerprint.api_fingerprint import run_one as run_one_api
from lib.api_fingerprint.api_fingerprint import process_mongo_obj as process_mongo_obj_api
import modules.processing.network as network
from helpers import convert_hit_to_template
from pymongo import MongoClient, CursorType
from elasticsearch import Elasticsearch
from pymisp import PyMISP
import urlparse
import MySQLdb
import cProfile

config = Config("reporting")
options = config.get("z_misp")
misp_url = options["url"]
misp = PyMISP(misp_url, options["apikey"], False)

db = Database()

results_db = settings.MONGO
fs = GridFS(results_db)
domains = set()
for domain in open(os.path.join(CUCKOO_ROOT, "data", "whitelist", "domain.txt")):
    domains.add(domain.strip())


def getMongoObj(taskid_list):
    # TODO: Make Mongo host config-based
    client = settings.MONGO

    id_list = [int(taskid) for taskid in taskid_list]
    cursor = client.analysis.find({"info.id": {"$in": id_list}},
                                  {"behavior.processes.command_line": "1", "network.http_ex": "1",
                                   "network.https_ex": "1", "target.file.md5": "1", "behavior.generic": 1,
                                   "behavior.apistats": 1, "info.id": "1"})
    return cursor


@require_safe
@login_required
def index(request):
    # response_obj = get_data(request)

    list_images = os.listdir(os.path.join(os.path.dirname(__file__), "../static/img/loader_gifs"))
    image = random.choice(list_images)
    return render(request, "analysis/index.html", {"loading_image": image})


def search_data(request):
    num_records = int(request.GET.get('num_records', '25'))
    response_obj = get_data(request, num_records)
    return JsonResponse(response_obj)


def suri_data(request):
    suri_query = create_tlp_query(request.user, {"term": {"_type": "suricata"}})
    es = settings.ELASTIC
    tasks_surihunts = es.search(index="hunt-*", body=suri_query)
    suri_return = []
    analyses_surihunts = [convert_hit_to_template(c) for c in tasks_surihunts['hits']['hits']]

    if analyses_surihunts:
        df = pd.DataFrame(analyses_surihunts)
        df["signature"] = df["alert"].apply(lambda x: x.get("signature"))
        suri_return = json.loads(df.groupby(["uuid", "signature"]).first().reset_index().to_json(orient='records'))
    return JsonResponse({
        "suri_hunts": suri_return
    })


def yara_data(request):
    es = settings.ELASTIC
    yara_query = create_tlp_query(request.user, {"term": {"_type": "yara"}})
    # TODO: Make this aggregation happen in ES
    # yara_query["aggs"] = {"uuid": {"terms": {"field": "uuid.raw"}, "aggregations": {"rule": {"terms": {"field": "rule.raw"}}}}}
    tasks_yhunts = es.search(index="hunt-*", body=yara_query)
    yara_return = []
    analyses_yhunts = [convert_hit_to_template(c) for c in tasks_yhunts['hits']['hits']]

    if analyses_yhunts:
        analyses_yhunts.sort(reverse=True)
        df = pd.DataFrame(analyses_yhunts)
        yara_return = json.loads(df.groupby(["uuid", "rule"]).first().reset_index().to_json(orient='records'))
    return JsonResponse({
        "yara_hunts": yara_return
    })


def url_data(request):
    num_records = int(request.GET.get('num_records', '25'))

    tasks_urls = db.list_tasks(limit=num_records, order_by=Task.completed_on.desc(), category="url",
                               status=TASK_REPORTED, tlpuser=request.user.username,
                               tlpamberusers=get_tlp_users(request.user))

    analyses_urls = []
    for task in tasks_urls:
        new = task.to_dict()

        if db.view_errors(task.id):
            new["errors"] = True

        analyses_urls.append(new)
    return JsonResponse({"urls": analyses_urls})


def get_data(request, num_records):
    # pr = cProfile.Profile()
    # pr.enable()
    misp = PyMISP(misp_url, options["apikey"], False)
    # TODO: add stuff for when user is not logged in
    tasks_files = db.list_tasks(limit=num_records, order_by=Task.completed_on.desc(), category="file",
                                status=TASK_REPORTED, tlpuser=request.user.username,
                                tlpamberusers=get_tlp_users(request.user))

    analyses_files = []
    if tasks_files:
        misp_tags = check_misp_errors(misp.get_all_tags(), "Can't get tags from MISP")["Tag"]
        tags_dict = {misp_item["id"]: misp_item for misp_item in misp_tags}
        mysqldb = MySQLdb.connect(host=options["mysql_host"],
                                  user=options["mysql_user"],
                                  passwd=options["mysql_password"],
                                  db="misp")
        id_cur = mysqldb.cursor()
        eventinfos = {"\"Phoenix Sandbox analysis #{0}\"".format(task_file.id): int(task_file.id) for task_file in
                      tasks_files}
        id_cur.execute(
            'select max(id), info from events where info in ({0}) group by info'.format(",".join(eventinfos.keys())))

        misp_ids = {eventinfos["\"{0}\"".format(id[1])]: int(id[0]) for id in id_cur.fetchall()}
        misp_tags = {}
        misp_atts = {}
        if id_cur.rowcount:
            event_id_strings = ','.join(str(intid) for intid in misp_ids.values())
            # misp_ids = ','.join([id[0] for id in id_cur.fetch_all()])

            tag_cur = mysqldb.cursor()
            tag_cur.execute(
                'select t.name, t.id, et.event_id from event_tags et inner join tags t on et.tag_id = t.id where et.event_id in ({0})'.format(
                    event_id_strings))
            for rows in tag_cur.fetchall():
                if int(rows[2]) not in misp_tags:
                    misp_tags[int(rows[2])] = []
                misp_tags[int(rows[2])].append(dict(name=rows[0], id=rows[1]))

            att_cur = mysqldb.cursor()
            att_cur.execute(
                'select a.value1, a.type, o.event_id from objects o inner join attributes a on o.id = a.object_id where o.template_uuid in ("3c177337-fb80-405a-a6c1-1b2ddea8684a","b5acf82e-ecca-4868-82fe-9dbdf4d808c3") and o.event_id in ({0}) and a.id in (select max(a1.id) from attributes a1 where a1.event_id in ({0}) group by a1.event_id, type);'.format(
                    event_id_strings))

            for rows in att_cur.fetchall():
                if int(rows[2]) not in misp_atts:
                    misp_atts[int(rows[2])] = {}
                misp_atts[int(rows[2])][rows[1]] = rows[0]

        mysqldb.close()
        file_ids = [task.id for task in tasks_files]
        file_objects = {m["info"]["id"]: m for m in getMongoObj(file_ids)}
        # file_objects = list(getMongoObj(file_ids))
        for task_index, task in enumerate(tasks_files):
            if task.id not in file_objects:
                print "{0} not in objects returned from mongo".format(task.id)
                continue
            new = task.to_dict()
            # TODO: Degrease this please
            new["processes"] = []
            new["http"] = []
            new["yara_matches"] = []
            new["suri_matches"] = []
            new["api_matches"] = {}
            # new["sample"] = db.view_sample(new["sample_id"]).to_dict()
            analysis_id = new["id"]
            m = file_objects[analysis_id]
            # for m in mobj:
            if 'behavior' in m:
                new["processes"] = m["behavior"]["processes"]
            myhttp = []
            if ('network' in m) and ('https_ex' in m["network"]):
                for mht in list(m["network"]["https_ex"] + m["network"]["http_ex"])[:4]:
                    if mht["host"] not in domains:
                        full_url = mht["protocol"] + '://' + mht["host"] + '/' + mht["uri"]
                        # TODO: Fix Bluecoat
                        # mycat = bluecoat_sitereview(full_url)
                        mht["full_url"] = full_url
                        # mht["category"] = mycat
                        myhttp.append(mht)

            # if ('network' in m) and ('http_ex' in m["network"]):
            #     for mh in m["network"]["http_ex"]:
            #         if mh["host"] not in domains:
            #             full_url = mh["protocol"] + '://' + mh["host"] + '/' + mh["uri"]
            #             # TODO: Fix Bluecoat
            #             # mycat = bluecoat_sitereview(full_url)
            #             mh["full_url"] = full_url
            #             # mh["category"] = mycat
            #             myhttp.append(mh)

            new["http"] = myhttp
            filename = os.path.basename(new["target"])
            if "target" in m and "file" in m["target"] and "md5" in m["target"]["file"]:
                new["md5"] = m["target"]["file"]["md5"]

            new.update({"filename": filename})

            if db.view_errors(task.id):
                new["errors"] = True
            misp_id = misp_ids.get(analysis_id)
            if misp_id and misp_id in misp_atts:

                misp_att_dict = misp_atts[misp_id]
                suri_matches = []
                has_suri = False
                yara_matches = []
                has_yara = False
                if "yara" in misp_att_dict:
                    has_yara = True
                    yara_matches.append(misp_att_dict["yara"])
                if "snort" in misp_att_dict:
                    has_suri = True
                    suri_matches.append(misp_att_dict["snort"])
                if has_yara:
                    new.update({
                        "yara_matches":
                            {
                                "link": options["external_url"] + "/events/view/" + str(misp_ids[new["id"]]),
                                "matches": ",".join(yara_matches)
                            }
                    })

                if has_suri:
                    new.update({
                        "suri_matches":
                            {
                                "link": options["external_url"] + "/events/view/" + str(misp_ids[new["id"]]),
                                "matches": ",".join(suri_matches)
                            }
                    })

                # Tags only show up in "search_index"
            tags_to_add = []
            if misp_id and misp_id in misp_tags:
                for tag in misp_tags[misp_id]:
                    tag_id = str(tag["id"])
                    if tag_id not in tags_dict:
                        continue
                    tags_to_add.append({
                        "tag_name": tag["name"],
                        "tag_link": options["external_url"] + "/events/index/searchtag:{0}".format(tag_id)
                    })
            new.update({"tags": tags_to_add})
            new.update({"api_matches": process_mongo_obj_api(m)})
            analyses_files.append(new)

    # pr.disable()
    # pr.dump_stats('profile5.pstat')
    return {
        "files": analyses_files,
    }


def get_misp_event(analysis_id):
    # my_misp = misp_obj if misp_obj else self.misp
    misp = PyMISP(misp_url, options["apikey"], False)
    search_result = check_misp_errors(
        misp.search_index(eventinfo="Phoenix Sandbox analysis #" + str(analysis_id)),
        "Couldn't search MISP for {0}".format(str(
            analysis_id)))
    if search_result and "response" in search_result and search_result["response"]:
        return reduce(
            lambda x, y: y if y["timestamp"] > x["timestamp"] and y["info"] == "Phoenix Sandbox analysis #" + str(
                analysis_id) else x, search_result["response"])
    else:
        return None


@require_safe
@login_required
def pending(request):
    tasks = db.list_tasks(status=TASK_PENDING)

    pending = []
    for task in tasks:
        pending.append(task.to_dict())

    return render(request, "analysis/pending.html", {
        "tasks": pending,
    })


@require_safe
@login_required
def chunk(request, task_id, pid, pagenum):
    try:
        pid, pagenum = int(pid), int(pagenum) - 1
    except:
        raise PermissionDenied

    if not request.is_ajax():
        raise PermissionDenied

    record = results_db.analysis.find_one(
        {
            "info.id": int(task_id),
            "behavior.processes.pid": pid
        },
        {
            "behavior.processes.pid": 1,
            "behavior.processes.calls": 1
        }
    )

    if not record:
        raise ObjectDoesNotExist

    process = None
    for pdict in record["behavior"]["processes"]:
        if pdict["pid"] == pid:
            process = pdict

    if not process:
        raise ObjectDoesNotExist

    if pagenum >= 0 and pagenum < len(process["calls"]):
        objectid = process["calls"][pagenum]
        chunk = results_db.calls.find_one({"_id": ObjectId(objectid)})
        for idx, call in enumerate(chunk["calls"]):
            call["id"] = pagenum * 100 + idx
    else:
        chunk = dict(calls=[])

    return render(request, "analysis/behavior/_chunk.html", {
        "chunk": chunk,
    })


@require_safe
@login_required
def filtered_chunk(request, task_id, pid, category):
    """Filters calls for call category.
    @param task_id: cuckoo task id
    @param pid: pid you want calls
    @param category: call category type
    """
    if not request.is_ajax():
        raise PermissionDenied

    # Search calls related to your PID.
    record = results_db.analysis.find_one(
        {
            "info.id": int(task_id),
            "behavior.processes.pid": int(pid),
        },
        {
            "behavior.processes.pid": 1,
            "behavior.processes.calls": 1,
        }
    )

    if not record:
        raise ObjectDoesNotExist

    # Extract embedded document related to your process from response collection.
    process = None
    for pdict in record["behavior"]["processes"]:
        if pdict["pid"] == int(pid):
            process = pdict

    if not process:
        raise ObjectDoesNotExist

    # Create empty process dict for AJAX view.
    filtered_process = {
        "pid": pid,
        "calls": [],
    }

    # Populate dict, fetching data from all calls and selecting only appropriate category.
    for call in process["calls"]:
        chunk = results_db.calls.find_one({"_id": call})
        for call in chunk["calls"]:
            if call["category"] == category:
                filtered_process["calls"].append(call)

    return render(request, "analysis/behavior/_chunk.html", {
        "chunk": filtered_process,
    })


@csrf_exempt
@login_required
def search_behavior(request, task_id):
    if request.method != "POST":
        raise PermissionDenied

    query = request.POST.get("search")
    query = re.compile(query, re.I)
    results = []

    # Fetch analysis report.
    record = results_db.analysis.find_one(
        {
            "info.id": int(task_id),
        }
    )

    # Loop through every process
    for process in record["behavior"]["processes"]:
        process_results = []

        chunks = results_db.calls.find({
            "_id": {"$in": process["calls"]}
        })

        index = -1
        for chunk in chunks:
            for call in chunk["calls"]:
                index += 1

                if query.search(call["api"]):
                    call["id"] = index
                    process_results.append(call)
                    continue

                for key, value in call["arguments"].items():
                    if query.search(key):
                        call["id"] = index
                        process_results.append(call)
                        break

                    if isinstance(value, basestring) and query.search(value):
                        call["id"] = index
                        process_results.append(call)
                        break

                    if isinstance(value, (tuple, list)):
                        for arg in value:
                            if not isinstance(arg, basestring):
                                continue

                            if query.search(arg):
                                call["id"] = index
                                process_results.append(call)
                                break
                        else:
                            continue
                        break

        if process_results:
            results.append({
                "process": process,
                "signs": process_results
            })

    return render(request, "analysis/behavior/_search_results.html", {
        "results": results,
    })


@require_safe
@login_required
def report(request, task_id):
    report = results_db.analysis.find_one({"info.id": int(task_id)}, sort=[("_id", pymongo.DESCENDING)])

    if not report:
        return render(request, "error.html", {
            "error": "The specified analysis does not exist",
        })

    if not request.user.is_authenticated \
            or 'tlp' not in report['info'] \
            or not (report['info']['tlp'] == 'green'
                    or (
                            report['info']['tlp'] == 'amber' and report['info']['owner'] in get_tlp_users(
                        request.user)) \
                    or (report['info']['tlp'] == 'red' and report['info']['owner'] == request.user.username)):
        return render(request, "error.html", {
            "error": "You are not tall enough to ride the ride.",
        })

    # Creating dns information dicts by domain and ip.
    if "network" in report:
        if "domains" in report["network"]:
            domainlookups = dict((i["domain"], i["ip"]) for i in report["network"]["domains"])
            iplookups = dict((i["ip"], i["domain"]) for i in report["network"]["domains"])
            for i in report["network"]["dns"]:
                for a in i["answers"]:
                    iplookups[a["data"]] = i["request"]
        else:
            domainlookups = dict()
            iplookups = dict()
        if "hosts" in report["network"]:
            # Greasy hack to mitigate hundreds of thousands of hosts from worms
            report["network"]["hosts"] =report["network"]["hosts"][:50]
    else:
        domainlookups = dict()
        iplookups = dict()

    if "http_ex" in report["network"] or "https_ex" in report["network"]:
        HAVE_HTTPREPLAY = True
    else:
        HAVE_HTTPREPLAY = False

    try:
        import httpreplay
        httpreplay_version = getattr(httpreplay, "__version__", None)
    except ImportError:
        httpreplay_version = None

    # Is this version of httpreplay deprecated?
    deprecated = httpreplay_version and \
                 versiontuple(httpreplay_version) < versiontuple(LATEST_HTTPREPLAY)
    return render(request, "analysis/report.html", {
        "analysis": report,
        "domainlookups": domainlookups,
        "iplookups": iplookups,
        "tlp": report['info']['tlp'],
        "httpreplay": {
            "have": HAVE_HTTPREPLAY,
            "deprecated": deprecated,
            "current_version": httpreplay_version,
            "latest_version": LATEST_HTTPREPLAY,
        },
    })


@require_safe
@login_required
def latest_report(request):
    rep = results_db.analysis.find_one({}, sort=[("_id", pymongo.DESCENDING)])
    return report(request, rep["info"]["id"] if rep else 0)


@require_safe
@login_required
def idapro(request, analysis_id, pid, num):
    mem_path = os.path.join(settings.CUCKOO_PATH, "storage/analyses/{0}/memory".format(analysis_id))
    download_file = os.path.join(mem_path, "{0}-{1}.py.gz").format(pid, num)
    if os.path.isfile(download_file):
        filename = os.path.basename(download_file)
        response = FileResponse(open(download_file, 'rb'), content_type=mimetypes.guess_type(download_file)[0])
        response['Content-Length'] = os.path.getsize(download_file)
        response['Content-Disposition'] = "attachment; filename=%s" % filename
        return response

    else:
        return render(request, "error.html", {
            "error": "File not found",
        })


@require_safe
@login_required
def file(request, category, object_id):
    file_item = fs.get(ObjectId(object_id))

    if file_item:
        # Composing file name in format sha256_originalfilename.
        file_name = file_item.sha256 + "_" + file_item.filename

        # Managing gridfs error if field contentType is missing.
        try:
            content_type = file_item.contentType
        except AttributeError:
            content_type = "application/octet-stream"

        response = HttpResponse(file_item.read(), content_type=content_type)
        response["Content-Disposition"] = "attachment; filename=%s" % file_name

        return response
    else:
        return render(request, "error.html", {
            "error": "File not found",
        })


@require_safe
@login_required
def tldr(request, object_id):
    outStr = run_tldr(object_id, request.user.username, False)
    return HttpResponse(outStr, content_type="application/json")


@require_safe
@login_required
def misp(request, task_id):
    report = results_db.analysis.find_one({"info.id": int(task_id)}, sort=[("_id", pymongo.DESCENDING)])
    if report["info"]["tlp"] == "red":
        return serve_using_django_in_memory(request, "storage/analyses/{0}/mispreport.json".format(task_id))
    else:
        global misp
        misp = PyMISP(misp_url, options["apikey"], False)

        misp_event = get_misp_event(task_id)
        if misp_event:
            return redirect(options["external_url"] + "/events/view/" + misp_event["id"])
        else:
            return HttpResponse("No MISP Report found")


def serve_using_django_in_memory(request, filename):
    file_full_path = os.path.join(settings.CUCKOO_PATH, "{0}".format(filename))

    with open(file_full_path, 'r') as f:
        data = f.read()

    response = HttpResponse(data, content_type=mimetypes.guess_type(file_full_path)[0])
    response['Content-Disposition'] = "attachment; filename={0}".format(filename)
    response['Content-Length'] = os.path.getsize(file_full_path)
    return response


moloch_mapper = {
    "ip": "ip == %s",
    "host": "host == %s",
    "src_ip": "ip == %s",
    "src_port": "port == %s",
    "dst_ip": "ip == %s",
    "dst_port": "port == %s",
    "sid": 'tags == "sid:%s"',
    "reportid": 'tags == "cuckoo:%s"'
}


@require_safe
@login_required
def moloch(request, **kwargs):
    if not settings.MOLOCH_ENABLED:
        return render(request, "error.html", {
            "error": "Moloch is not enabled!",
        })

    query = []
    for key, value in kwargs.items():
        if value and value != "None" and key != "date":
            query.append(moloch_mapper[key] % value)

    if ":" in request.get_host():
        hostname = request.get_host().split(":")[0]
    else:
        hostname = request.get_host()

    if settings.MOLOCH_INSECURE:
        url = "http://"
    else:
        url = "https://"

    query_object = {
        "expression": " && ".join(query),
    }
    if kwargs.get("reportid"):
        task = db.view_task(kwargs["reportid"])
        query_object.update({"startTime": convert_to_epoch_time(task.started_on-datetime.timedelta(days=1))})
        query_object.update({"stopTime": convert_to_epoch_time(task.completed_on+datetime.timedelta(days=1))})
    else:
        query_object.update({"date": kwargs["date"] if kwargs.get("date") else "168"})

    url += "%s%s/?%s" % (
        settings.MOLOCH_HOST or hostname,
        ":" + settings.MOLOCH_PORT if settings.MOLOCH_PORT else "",
        urllib.urlencode(query_object),
    )
    return redirect(url)


@require_safe
@login_required
def full_memory_dump_file(request, analysis_number):
    file_path = os.path.join(CUCKOO_ROOT, "storage", "analyses", str(analysis_number), "memory.dmp")
    if os.path.exists(file_path):
        content_type = "application/octet-stream"
        response = HttpResponse(open(file_path, "rb").read(), content_type=content_type)
        response["Content-Disposition"] = "attachment; filename=memory.dmp"
        return response
    else:
        return render(request, "error.html", {
            "error": "File not found",
        })


def _search_helper(obj, k, value):
    r = []

    if isinstance(obj, dict):
        for k, v in obj.items():
            r += _search_helper(v, k, value)

    if isinstance(obj, (tuple, list)):
        for v in obj:
            r += _search_helper(v, k, value)

    if isinstance(obj, basestring):
        if re.search(value, obj, re.I):
            r.append((k, obj))

    return r


@csrf_exempt
@login_required
def search(request):
    """New Search API using ElasticSearch as backend."""
    if not settings.ELASTIC:
        return render(request, "error.html", {
            "error": "ElasticSearch is not enabled and therefore it is "
                     "not possible to do a global search.",
        })

    if request.method == "GET":
        return render(request, "analysis/search.html")

    value = request.POST["search"]

    match_value = ".*".join(re.split("[^a-zA-Z0-9]+", value.lower()))

    r = settings.ELASTIC.search(
        index=settings.ELASTIC_INDEX + "-*",
        body=create_tlp_query(request.user, {"query_string": {"query": "*%s*" % value}})

    )

    analyses = []
    for hit in r["hits"]["hits"]:
        # Find the actual matches in this hit and limit to 8 matches.
        matches = _search_helper(hit, "none", match_value)
        if not matches:
            continue

        analyses.append({
            "task_id": hit["_source"]["report_id"],
            "matches": matches[:16],
            "total": max(len(matches) - 16, 0),
        })

    if request.POST.get("raw"):
        return render(request, "analysis/search_results.html", {
            "analyses": analyses,
            "term": request.POST["search"],
        })

    return render(request, "analysis/search.html", {
        "analyses": analyses,
        "term": request.POST["search"],
        "error": None,
    })


@require_safe
@login_required
def remove(request, task_id):
    """Remove an analysis.
    @todo: remove folder from storage.
    """
    analyses = results_db.analysis.find({"info.id": int(task_id)})

    # Checks if more analysis found with the same ID, like if process.py
    # was run manually.
    if analyses.count() > 1:
        message = (
            "Multiple tasks with this ID deleted, thanks for all the fish "
            "(the specified analysis was present multiple times in mongo)."
        )
    elif analyses.count() == 1:
        message = "Task deleted, thanks for all the fish."

    if not analyses.count():
        return render(request, "error.html", {
            "error": "The specified analysis does not exist",
        })

    for analysis in analyses:
        # Delete sample if not used.
        if "file_id" in analysis["target"]:
            if results_db.analysis.find({"target.file_id": ObjectId(analysis["target"]["file_id"])}).count() == 1:
                fs.delete(ObjectId(analysis["target"]["file_id"]))

        # Delete screenshots.
        for shot in analysis["shots"]:
            if results_db.analysis.find({"shots": ObjectId(shot)}).count() == 1:
                fs.delete(ObjectId(shot))

        # Delete network pcap.
        if "pcap_id" in analysis["network"] and results_db.analysis.find(
                {"network.pcap_id": ObjectId(analysis["network"]["pcap_id"])}).count() == 1:
            fs.delete(ObjectId(analysis["network"]["pcap_id"]))

        # Delete sorted pcap
        if "sorted_pcap_id" in analysis["network"] and results_db.analysis.find(
                {"network.sorted_pcap_id": ObjectId(analysis["network"]["sorted_pcap_id"])}).count() == 1:
            fs.delete(ObjectId(analysis["network"]["sorted_pcap_id"]))

        # Delete mitmproxy dump.
        if "mitmproxy_id" in analysis["network"] and results_db.analysis.find(
                {"network.mitmproxy_id": ObjectId(analysis["network"]["mitmproxy_id"])}).count() == 1:
            fs.delete(ObjectId(analysis["network"]["mitmproxy_id"]))

        # Delete dropped.
        for drop in analysis.get("dropped", []):
            if "object_id" in drop and results_db.analysis.find(
                    {"dropped.object_id": ObjectId(drop["object_id"])}).count() == 1:
                fs.delete(ObjectId(drop["object_id"]))

        # Delete calls.
        for process in analysis.get("behavior", {}).get("processes", []):
            for call in process["calls"]:
                results_db.calls.remove({"_id": ObjectId(call)})

        # Delete analysis data.
        results_db.analysis.remove({"_id": ObjectId(analysis["_id"])})

    # Delete from SQL db.
    db.delete_task(task_id)

    return render(request, "success.html", {
        "message": message,
    })


@require_safe
@login_required
def pcapstream(request, task_id, conntuple):
    """Get packets from the task PCAP related to a certain connection.
    This is possible because we sort the PCAP during processing and remember offsets for each stream.
    """
    src, sport, dst, dport, proto = conntuple.split(",")
    sport, dport = int(sport), int(dport)

    conndata = results_db.analysis.find_one(
        {
            "info.id": int(task_id),
        },
        {
            "network.tcp": 1,
            "network.udp": 1,
            "network.sorted_pcap_id": 1,
        },
        sort=[("_id", pymongo.DESCENDING)])

    if not conndata:
        return render(request, "standalone_error.html", {
            "error": "The specified analysis does not exist",
        })

    try:
        if proto == "udp":
            connlist = conndata["network"]["udp"]
        else:
            connlist = conndata["network"]["tcp"]

        conns = filter(lambda i: (i["sport"], i["dport"], i["src"], i["dst"]) == (sport, dport, src, dst), connlist)
        stream = conns[0]
        offset = stream["offset"]
    except:
        return render(request, "standalone_error.html", {
            "error": "Could not find the requested stream",
        })

    try:
        fobj = fs.get(conndata["network"]["sorted_pcap_id"])
        setattr(fobj, "fileno", lambda: -1)
    except:
        return render(request, "standalone_error.html", {
            "error": "The required sorted PCAP does not exist",
        })

    packets = list(network.packets_for_stream(fobj, offset))
    # TODO: starting from django 1.7 we should use JsonResponse.
    return HttpResponse(json.dumps(packets), content_type="application/json")


@login_required
def export_analysis(request, task_id):
    if request.method == "POST":
        return export(request, task_id)

    report = results_db.analysis.find_one(
        {"info.id": int(task_id)}, sort=[("_id", pymongo.DESCENDING)]
    )
    if not report:
        return render(request, "error.html", {
            "error": "The specified analysis does not exist",
        })

    if "analysis_path" not in report.get("info", {}):
        return render(request, "error.html", {
            "error": "The analysis was created before the export "
                     "functionality was integrated with Cuckoo and is "
                     "therefore not available for this task (in order to "
                     "export this analysis, please reprocess its report)."
        })

    analysis_path = report["info"]["analysis_path"]

    # Locate all directories/results available for this analysis.
    dirs, files = [], []
    for filename in os.listdir(analysis_path):
        path = os.path.join(analysis_path, filename)
        if os.path.isdir(path):
            dirs.append((filename, len(os.listdir(path))))
        else:
            files.append(filename)

    return render(request, "analysis/export.html", {
        "analysis": report,
        "dirs": dirs,
        "files": files,
    })


def json_default(obj):
    if isinstance(obj, datetime.datetime):
        if obj.utcoffset() is not None:
            obj = obj - obj.utcoffset()
        return calendar.timegm(obj.timetuple()) + obj.microsecond / 1000000.0
    raise TypeError("%r is not JSON serializable" % obj)


@login_required
def export(request, task_id):
    taken_dirs = request.POST.getlist("dirs")
    taken_files = request.POST.getlist("files")
    if not taken_dirs and not taken_files:
        return render(request, "error.html", {
            "error": "Please select at least one directory or file to be exported."
        })

    report = results_db.analysis.find_one(
        {"info.id": int(task_id)}, sort=[("_id", pymongo.DESCENDING)]
    )
    if not report:
        return render(request, "error.html", {
            "error": "The specified analysis does not exist",
        })

    path = report["info"]["analysis_path"]

    # Creating an analysis.json file with basic information about this
    # analysis. This information serves as metadata when importing a task.
    analysis_path = os.path.join(path, "analysis.json")
    with open(analysis_path, "w") as outfile:
        report["target"].pop("file_id", None)
        metadata = {
            "info": report["info"],
            "target": report["target"],
        }
        json.dump(metadata, outfile, indent=4, default=json_default)

    f = StringIO()

    # Creates a zip file with the selected files and directories of the task.
    zf = zipfile.ZipFile(f, "w", zipfile.ZIP_DEFLATED, allowZip64=True)

    for dirname, subdirs, files in os.walk(path):
        if os.path.basename(dirname) == task_id:
            for filename in files:
                if filename in taken_files:
                    zf.write(os.path.join(dirname, filename), filename)
        if os.path.basename(dirname) in taken_dirs:
            for filename in files:
                zf.write(os.path.join(dirname, filename),
                         os.path.join(os.path.basename(dirname), filename))

    zf.close()

    response = HttpResponse(f.getvalue(), content_type="application/zip")
    response["Content-Disposition"] = "attachment; filename=%s.zip" % task_id
    return response


@login_required
def import_analysis(request):
    if request.method == "GET":
        return render(request, "analysis/import.html")

    task_ids = []

    for analysis in request.FILES.getlist("analyses"):
        if not analysis.size:
            return render(request, "error.html", {
                "error": "You uploaded an empty analysis.",
            })

        # if analysis.size > settings.MAX_UPLOAD_SIZE:
        # return render(request, "error.html", {
        #     "error": "You uploaded a file that exceeds that maximum allowed upload size.",
        # })

        if not analysis.name.endswith(".zip"):
            return render(request, "error.html", {
                "error": "You uploaded an analysis that wasn't a .zip.",
            })

        zf = zipfile.ZipFile(analysis)

        # As per Python documentation we have to make sure there are no
        # incorrect filenames.
        for filename in zf.namelist():
            if filename.startswith("/") or ".." in filename or ":" in filename:
                return render(request, "error.html", {
                    "error": "The zip file contains incorrect filenames, "
                             "please provide a legitimate .zip file.",
                })

        if "analysis.json" in zf.namelist():
            analysis_info = json.loads(zf.read("analysis.json"))
        elif "binary" in zf.namelist():
            analysis_info = {
                "target": {
                    "category": "file",
                },
            }
        else:
            analysis_info = {
                "target": {
                    "category": "url",
                    "url": "unknown",
                },
            }

        category = analysis_info["target"]["category"]
        info = analysis_info.get("info", {})

        if category == "file":
            binary = store_temp_file(zf.read("binary"), "binary")

            if os.path.isfile(binary):
                task_id = db.add_path(file_path=binary,
                                      package=info.get("package"),
                                      timeout=0,
                                      options=info.get("options"),
                                      priority=0,
                                      machine="",
                                      custom=info.get("custom"),
                                      memory=False,
                                      enforce_timeout=False,
                                      tags=info.get("tags"),
                                      owner=request.user.username if request.user.is_authenticated else "")
                if task_id:
                    task_ids.append(task_id)

        elif category == "url":
            url = analysis_info["target"]["url"]
            if not url:
                return render(request, "error.html", {
                    "error": "You specified an invalid URL!",
                })

            task_id = db.add_url(url=url,
                                 package=info.get("package"),
                                 timeout=0,
                                 options=info.get("options"),
                                 priority=0,
                                 machine="",
                                 custom=info.get("custom"),
                                 memory=False,
                                 enforce_timeout=False,
                                 tags=info.get("tags"),
                                 owner=request.user.username if request.user.is_authenticated else "")
            if task_id:
                task_ids.append(task_id)

        if not task_id:
            continue

        # Extract all of the files related to this analysis. This probably
        # requires some hacks depending on the user/group the Web
        # Interface is running under.
        analysis_path = os.path.join(
            CUCKOO_ROOT, "storage", "analyses", "%d" % task_id
        )

        if not os.path.exists(analysis_path):
            os.mkdir(analysis_path)

        zf.extractall(analysis_path)

        # We set this analysis as completed so that it will be processed
        # automatically (assuming process.py / process2.py is running).
        db.set_status(task_id, TASK_COMPLETED)

    if task_ids:
        return render(request, "submission/complete.html", {
            "tasks": task_ids,
            "baseurl": request.build_absolute_uri("/")[:-1],
        })


@login_required
def reboot_analysis(request, task_id):
    task_id = db.add_reboot(task_id=task_id)

    return render(request, "submission/reboot.html", {
        "task_id": task_id,
        "baseurl": request.build_absolute_uri("/")[:-1],
    })


def check_misp_errors(response, error_str):
    if "errors" in response:
        raise Exception("{0}: {1}".format(error_str, response["errors"][-1]))
    return response


def convert_to_epoch_time(my_datetime):
    return int((my_datetime - datetime.datetime(1970,1,1)).total_seconds())
