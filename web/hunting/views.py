# Copyright (C) 2010-2013 Claudio Guarnieri.
# Copyright (C) 2014-2016 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.
import mimetypes
import os
import json
import shutil
import random
import sys
import traceback
import uuid
import logging
import cProfile
from datetime import datetime
from time import time
import docker
import pymisp

import re

from pymisp import MISPObjectReference, MISPEvent, MISPObject
from pymisp.tools import FileObject

from lib.cuckoo.core.database import Database
from lib.cuckoo.common.utils import sha1_file
from django import template
from django.conf import settings
from django.core.urlresolvers import reverse
from django.contrib.auth.decorators import login_required
from django.http import HttpResponse, JsonResponse
from django.shortcuts import redirect
from django.shortcuts import render
from django.views.decorators.http import require_safe
from elasticsearch import Elasticsearch
from helpers import convert_hit_to_template
from web.tlp_methods import get_tlp_users, create_tlp_query, get_analyses_numbers_matching_tlp2
from lib.cuckoo.common.config import Config
from lib.phoenix.rule_reader import get_hunting_suri_rules

sys.path.insert(0, settings.CUCKOO_PATH)
# analyses_prefix =
analyses_prefix = settings.ANALYSES_PREFIX
analyses_storage = os.path.abspath(os.path.join(analyses_prefix, os.pardir))
# source_for_suri_yaml =
source_for_suri_yaml = settings.SURICATA_PATH
jobSplitLength = 100
mon = datetime.now().strftime('%Y%m%d')
es = settings.ELASTIC
log = logging.getLogger(__name__)
results_db = settings.MONGO
register = template.Library()


def timing(f):
    def wrap(*args):
        time1 = time()
        ret = f(*args)
        time2 = time()
        print '%s function took %0.3f ms' % (f.func_name, (time2 - time1) * 1000.0)
        return ret

    return wrap

def check_misp_errors(response, error_str):
    if "errors" in response:
        raise Exception("{0}: {1}".format(error_str, response["errors"][-1]))
    if "response" in response:
        return response["response"]

@require_safe
@login_required
def index(request):
    if request.user.is_authenticated():
        # query_template = '{"from": 0, "size": 10, "query":{"bool":{"must":[{"term":{"username.raw":"' + request.user.username + '"}},'
        # yara_query = query_template + '{"term":{"_type":"yara"}}]}}}'
        # suri_query = query_template + '{"term":{"_type":"suricata"}}]}}}'
        # yara_hunts = es.search(index="hunt-*", body=yara_query)
        # suricata_hunts = es.search(index="hunt-*", body=suri_query)
        # analyses_yhunts = [convert_hit_to_template(c) for c in yara_hunts['hits']['hits']]
        # analyses_surihunts = [convert_hit_to_template(c) for c in suricata_hunts['hits']['hits']]
        return render(request, "hunting/index.html"
                      #, {'yara_hunts': analyses_yhunts, 'suricata_hunts': analyses_surihunts})
                      )
    else:
        return redirect("/login?next=/hunting")


@login_required
def report(request, task_id=None):
    if not task_id:
        return render(request, "hunting/index.html")
    #
    # query = create_tlp_query(request.user, {"term": {"uuid.raw": task_id}})
    # record = es.search(index="hunt-*", body=query)
    list_images = os.listdir(os.path.join(os.path.dirname(__file__), "../static/img/loader_gifs"))
    image = random.choice(list_images)
    return render(request, "hunting/report.html", {'loading_image': image})
    # {'results': [convert_hit_to_template(c) for c in record['hits']['hits']]})


def get_hunt_data(request, task_id):
    query = create_tlp_query(request.user, {"term": {"uuid.raw": task_id}})
    record = es.search(index="hunt-*", body=query)
    es_hits = [convert_hit_to_template(c) for c in record['hits']['hits']]
    id_set = set()
    for hit in es_hits:
        id_set.add(hit["analysis_id"])
    mongo_results = {str(x["info"]["id"]): x for x in getMongoObj(list(id_set))}

    for hit in es_hits:
        http_recs = []
        hit["checkbox"] = ""

        analysis_id = hit["analysis_id"]
        if analysis_id not in mongo_results:
            continue
        mongo_object = mongo_results[analysis_id]
        if "network" in mongo_object:
            if "https_ex" in mongo_object["network"]:
                http_recs += mongo_object["network"]["https_ex"]
            if "http_ex" in mongo_object["network"]:
                http_recs += mongo_object["network"]["http_ex"]
        mongo_result = next(
            (result for result in http_recs if straight_match(result, hit) or reverse_match(result, hit)), None)
        if mongo_result:
            hit["uri"] = mongo_result.get("protocol") + "://" + mongo_result.get("host") + mongo_result.get("uri")
            hit["method"] = mongo_result.get("method")
            hit["link_url"] = reverse("moloch",
                                      kwargs={"src_ip": mongo_result.get("src"), "src_port": mongo_result.get("sport"),
                                              "dst_ip": mongo_result.get("dst"),
                                              "dst_port": mongo_result.get("dport"), "date": "4380"})
    return JsonResponse({"results": es_hits})


def reverse_match(mobj, hit):
    return mobj["sport"] == hit["dest_port"] and mobj["dport"] == hit["src_port"] and mobj["src"] == hit["dest_ip"] and \
           mobj["dst"] == hit["src_ip"]


def straight_match(mobj, hit):
    return mobj["sport"] == hit["src_port"] and mobj["dport"] == hit["dest_port"] and mobj["src"] == hit["src_ip"] and \
           mobj["dst"] == hit["dest_ip"]


@login_required
def submit(request):
    print "Submit"
    # pr = cProfile.Profile()
    # pr.enable()
    try:
        suriFiles = request.FILES.getlist("suricataRulesFile")
        yaraFiles = request.FILES.getlist("yaraRulesFile")
        tlp = request.POST.get("tlp")
        if len(suriFiles) == 0 and len(yaraFiles) == 0:
            return render(request, "hunting/index.html")

        strUuid = str(uuid.uuid4())

        client = docker.DockerClient()

        # usersInGroup = get_tlp_users(request.user)
        username = request.user.username
        analyses_numbers = get_analyses_numbers_matching_tlp2(username)

        # analyses = results_db.analysis.find({}, {"info.id": "1"})
        hunting_uuid = os.path.join(analyses_prefix, ".hunting", strUuid)

        os.makedirs(hunting_uuid)

        #       Workaround for TLP
        #        analyses = results_db.getCollection('analysis').find({"info.options":/yellow/},{"info":"1"})
        # analyses_numbers = [f for f in os.listdir(analyses_prefix) if str(f).isdigit()]
        if yaraFiles:
            yaraRuleFile = yaraFiles[0]
            kick_off_yara(analyses_numbers, client, hunting_uuid, strUuid, yaraRuleFile, tlp, username)
        elif suriFiles:
            suriRuleFile = suriFiles[0]
            kick_off_suricata(analyses_numbers, client, hunting_uuid, strUuid, suriRuleFile, tlp, username)
        # pr.disable()
        # pr.dump_stats("huntingprofile.pstat")
        return redirect('hunting.views.status', task_id=strUuid)
    except Exception as e:
        return HttpResponse(str(e.message) + " " + str(traceback.format_exc()))


def chunker(xs, n):
    """Yield successive n-sized chunks from l."""
    L = len(xs)
    if (n > L) or (L < 100):
        return [xs]
    assert 0 < n <= L
    s, r = divmod(L, n)
    t = s + 1
    return ([xs[p:p + t] for p in range(0, r * t, t)] +
            [xs[p:p + s] for p in range(r * t, L, s)])


def kick_off_suricata(analyses_numbers, client, hunting_uuid, strUuid, suriRuleFile, tlp, username):
    slices = chunker(analyses_numbers, settings.MAX_SURICATA_WORKERS)
    for idx, slice in enumerate(slices):
        slice_dir = hunting_uuid + '/' + str(idx)
        os.makedirs(slice_dir)
        with open(os.path.join(slice_dir, "all.rules"), 'wb+') as destination:
            for chunk in suriRuleFile.chunks():
                destination.write(chunk)
        shutil.copy(source_for_suri_yaml, slice_dir)
        with open(os.path.join(slice_dir, "infiles"), 'wb+') as infiles:
            # start_index = idx * jobSplitLength
            # end_index = start_index + jobSplitLength - 1 if len(
            #     analyses_numbers) > start_index + jobSplitLength else len(analyses_numbers) - 1
            for number in slice:
                infiles.write('/input/' + str(number) + '/dump.pcap\n')
        client.containers.run(settings.SURICATA_DOCKER_IMAGE,
                              "{0} {1} {2} {3} {4}".format(strUuid, username, tlp, idx, settings.ELASTIC_HOSTS[0]),
                              detach=True,
                              volumes={analyses_prefix: {'bind': '/input', 'mode': 'rw'}},
                              mem_limit='2g',
                              stderr=True,
                              labels={'uuid': strUuid},
                              network="docker_phoenix",
                              remove=True)


def kick_off_yara(analyses_numbers, client, hunting_uuid, strUuid, yaraRuleFile, tlp, username):
    number_set = set(analyses_numbers)
    db = Database()
    file_tuples = db.get_paths_for_tasks(list(number_set))
    yara_malware_folder, yara_root_folder, yara_rule_file_path, yara_rules_folder, yara_target_files = get_yara_paths(
        hunting_uuid)
    os.makedirs(yara_rules_folder)
    os.makedirs(yara_malware_folder)
    # write yara rule file to new yara hunt dir
    volumes = {yara_root_folder: {'bind': '/yara', 'mode': 'rw'},
               analyses_storage: {'bind': '/analyses', 'mode': 'ro'},
               '/opt/phoenix/storage/binaries' : {'bind': '/opt/phoenix/storage/binaries', 'mode': 'ro'}}

    with open(yara_rule_file_path, 'wb+') as yara_destination:
        for chunk in yaraRuleFile.chunks():
            yara_destination.write(chunk)

    # targets = []

    # create symlinks for all TLP approved files
    slices = chunker(list(file_tuples), settings.MAX_YARA_WORKERS)
    for index,slice in enumerate(slices):
        # os.symlink(analysis_memory_path, os.path.join(yara_malware_instance_folder, "binary"))
        yara_slice_targets_path = os.path.join(yara_root_folder, "targets")+'_'+str(index)
        with open(yara_slice_targets_path, 'w+') as target_file:
            target_file.writelines([str(line.task_id)+","+line.file_path + "\n" for line in slice])

        print volumes
        client.containers.run(settings.YARA_DOCKER_IMAGE,
                                               command="{0} {1} {2} {3} {4} {5} {6} {7}".format(
                                                   "-y {0}".format("/yara/rules/yararules.yar"),
                                                   "-s {0}".format('/yara/targets_'+str(index)),
                                                   "-o {0}".format(username),
                                                   "-t {0}".format(tlp),
                                                   "-u {0}".format(strUuid),
                                                   "-m {0}".format(settings.MONGO_HOST),
                                                   "-e {0}".format(settings.ELASTIC_HOSTS[0]),
                                                   "-i {0}".format(index)),
                                               stderr=True,
                                               labels={'uuid': strUuid},
                                               volumes=volumes,
                                               network="docker_phoenix",
                                               detach=True,
                                               )


def get_yara_paths(hunting_uuid):
    yara_root_folder = os.path.join(hunting_uuid, "yara")
    yara_target_files = os.path.join(analyses_prefix, hunting_uuid, "yara/targets")
    yara_rules_folder = os.path.join(yara_root_folder, "rules")
    yara_malware_folder = os.path.join(yara_root_folder, "malware")
    yara_rule_file_path = os.path.join(yara_rules_folder, "yararules.yar")
    return yara_malware_folder, yara_root_folder, yara_rule_file_path, yara_rules_folder, yara_target_files


@login_required
def yara_file(request, hunt_uuid):
    hunting_uuid = os.path.join(analyses_prefix, ".hunting", hunt_uuid)
    yara_malware_folder, yara_root_folder, yara_rule_file_path, yara_rules_folder, yara_target_files = get_yara_paths(
        hunting_uuid)
    with open(yara_rule_file_path, 'rb') as f:
        response = HttpResponse(f, mimetypes.guess_type(yara_rule_file_path)[0])
        response['Content-Disposition'] = 'attachment; filename="yararules.yar"'
        return response

@login_required
def yara_download(request,hunt_result_id, index):
    result = es.get(index,hunt_result_id)
    if result:
        filepath = result["_source"]["raw_filename"]
        if os.path.exists(filepath):
            with open(filepath, 'rb') as f:
                response = HttpResponse(f, mimetypes.guess_type(filepath)[0])
                response['Content-Disposition'] = 'attachment; filename="{0}"'.format(os.path.basename(filepath))
                return response
        else:
            return HttpResponse("The file was not found at the path in the database.  Please tell the administrator to check ID {0} of index {1}".format(hunt_result_id,index))

@login_required
def suri_file(request, hunt_uuid):
    hunting_prefix = os.path.join(analyses_prefix, ".hunting")
    hunting_uuid = os.path.join(hunting_prefix, hunt_uuid)
    suri_file = os.path.join(hunting_uuid, "0", "all.rules")
    with open(suri_file, 'rb') as f:
        response = HttpResponse(f, mimetypes.guess_type(suri_file)[0])
        response['Content-Disposition'] = 'attachment; filename="all.rules"'
        return response


@login_required
def pcap(request, analysis_id):
    record = results_db.analysis.find_one({"info.id": int(analysis_id)})
    if record is None:
        return None
    else:
        return redirect('analysis.views.file', category='pcap', object_id=record["network"]["pcap_id"])


def getMongoObj(taskid_list):
    # TODO: Make Mongo host config-based
    client = settings.MONGO

    id_list = [int(taskid) for taskid in taskid_list]
    cursor = client.analysis.find({"info.id": {"$in": id_list}},
                                  {"network.http_ex": "1", "network.https_ex": "1", "info.id": "1", "_id": "0"})
    return cursor


@login_required
def status(request, task_id):
    # TODO Create a library for ES stuff to remove duplication
    # record = es.search(index="*", body={"query": {'match_phrase': {'uuid': task_id}}})
    # record = results_db.analysis.find_one({'uuid': task_id})
    # if record['hits']['total'] == 0:
    client = docker.APIClient(version='auto')
    containers = client.containers(filters={'label': 'uuid=' + task_id})
    docker_count = len(containers)

    if docker_count > 0:
        progress_data = []
        if containers[0]["Image"] == settings.YARA_DOCKER_IMAGE:
            hunt_path = os.path.join(analyses_prefix, ".hunting", task_id, "yara")
            progress_files = filter(lambda file: file.startswith("progress_"), os.listdir(hunt_path))
            for index, file in enumerate(progress_files):
                with open(os.path.join(hunt_path, file), 'r') as progress_file:
                    progress_data.append("Docker container {0} - {1}".format(index, progress_file.read()))
            if len(progress_data) < len(containers):
                for i in range(len(progress_data), len(containers)):
                    progress_data.append("Docker container {0} still enumerating files".format(i))
        return render(request, "hunting/status.html", {
            "task_id": task_id,
            "instance_count": docker_count,
            "progress_data":progress_data
        })
    return redirect("hunting.views.report", task_id=task_id)
    # return redirect("analysis.views.report", task_id=task_id)

def publish(request,hunt_uuid):
    body = json.loads(request.body)
    data = body["data"]
    type = body["type"]
    if not data or not type:
        return "Nothing sent to me"
    config = Config("reporting")
    options = config.get("z_misp")
    mymisp = options["url"]
    auth_key = options["apikey"]
    misp = pymisp.PyMISP(mymisp, auth_key, False)
    if type == "suricata":
        ruledict = get_hunting_suri_rules(hunt_uuid)
    for item in data:
        try:
            analysis_id = item["analysis_id"]
            events = check_misp_errors(misp.search_index(eventinfo="Phoenix Sandbox analysis #{0}".format(analysis_id)), "error parsing event object {0}".format(
                analysis_id))
        except Exception as e:
            log.error(e.message)
            continue
        if type == "yara":
            if 'storage/binaries' in item["raw_filename"]:
                filepath = item["raw_filename"]
            else:
                filepath = os.path.join(analyses_prefix, *item["raw_filename"].split("/")[-3:])
            hash = sha1_file("%s" % filepath)

        for event in events:
            event_object = MISPEvent()
            event_object.load(misp.get_event(event["id"]))
            file_objects = filter(lambda obj: obj["name"] == "file", event_object["Object"])
            refs_to_add = []
            if type == "yara":
                yara_objects = filter(lambda obj: obj["name"] == "yara", event_object["Object"])
                refs_to_add = publish_yara(event_object, file_objects, filepath, hash, hunt_uuid, item, yara_objects)
            elif type == "suricata":
                refs_to_add = publish_suricata(event_object, file_objects, item,ruledict)
            if refs_to_add:
                misp.update(event_object)
                for ref in refs_to_add:
                    misp.add_object_reference(ref)
                misp.fast_publish(event_object["id"])

    return JsonResponse({})


def publish_suricata(event_object, file_objects, item, ruledict):
    refs_to_add = []
    original_file = get_original_file(file_objects)
    if original_file:
        objects = filter(lambda obj: obj["name"] == "suricata", event_object["Object"])
        if has_suri_match(objects, item["alert"]["signature_id"], item["alert"]["rev"]):
            return []
        alert = item["alert"]
        suri_obj = MISPObject(name='suricata', standalone=False)
        suri_obj.add_attribute('suricata', type="snort", value=ruledict[(alert["signature_id"], alert["signature"])])
        event_object.add_object(suri_obj)
        suri_ref = MISPObjectReference()
        suri_ref.from_dict(suri_obj.uuid, original_file["uuid"], "mitigates")
        refs_to_add.append(suri_ref)
    return refs_to_add


def has_suri_match(objects, sid, rev):
    for object in objects:
        for att in object["Attribute"]:
            if att["type"] == "snort" and re.search("sid:{0};".format(str(sid)), att["value"]) and re.search("rev:{0};".format(str(rev)), att["value"]):
                return True




def get_original_file(file_objects):
    for file_object in file_objects:
        for att in file_object["Attribute"]:
            if att["category"] == "External analysis" and att["type"] == "malware-sample":
                return file_object


def publish_yara(event_object, file_objects, filepath, hash, hunt_uuid, item, yara_objects):
    refs_to_add = []
    matched_files = []

    yfile = os.path.join(analyses_prefix, ".hunting", hunt_uuid, "yara/rules/yararules.yar")
    with open(yfile, 'r') as myfile:
        yfilestring = myfile.read()
    yrulematch = re.search(r'rule\s+' + str(item["rule"]) + r'.*?\n\}', yfilestring, re.S)
    if not yrulematch:
        log.warn("Yara rule {0} not found in rules file {1}".format(item["rule"],yfile))
        return []
    attribute_lists = map(lambda outer_object: (outer_object["Attribute"], outer_object["ObjectReference"]), yara_objects)

    itemdict = {}
    for tuple in attribute_lists:
        if tuple[0]:
            file_refs = []
            for object_ref in tuple[1]:
                for file in file_objects:
                    if file["uuid"] == object_ref["referenced_uuid"]:
                        for att in file["Attribute"]:
                            if att["type"] == "sha1":
                                file_refs.append(att["value"])
                                break
                        break
            itemdict[tuple[0][0]["value"]] = file_refs
    # yara_rules_in_event  = [yara_object[0][0]["value"] for yara_object in attribute_lists if any(yara_object)]
    if yrulematch.group(0) in itemdict and hash in itemdict[yrulematch.group(0)]:
        log.info("Yara rule is already here and associated to the file")
        return []
    for file_object in file_objects:
        for att in file_object["Attribute"]:
            if att["category"] == "External analysis" and att["type"] == "malware-sample":
                original_file = file_object
            elif att["type"] == "sha1" and att["value"] == hash:
                matched_files.append(file_object)
                break
    if not matched_files and original_file:
        file = FileObject(filename=filepath.split("/")[-1], filepath=filepath)
        event_object.add_object(file)
        if "/memory/" in filepath:
            relationship = "contained-within"
        else:
            relationship = "dropped-by"

        file.add_reference(original_file["uuid"], relationship)
        reference = MISPObjectReference()
        reference.from_dict(file.uuid, original_file["uuid"], relationship)
        refs_to_add.append(reference)
        matched_files.append(file)
    for file in matched_files:
        yara_rule = MISPObject("yara", True, False)
        yara_ref = MISPObjectReference()
        yara_ref.from_dict(yara_rule.uuid, file["uuid"], "mitigates")
        refs_to_add.append(yara_ref)

        yara_rule.add_attribute("yara", value=yrulematch.group(0))

        event_object.add_object(yara_rule)
    return refs_to_add



