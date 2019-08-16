# Copyright (C) 2016 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.
import hashlib
import os, os.path
import shlex
import warnings
import yara
import re
import sys
import json
import time
from pymisp.tools import FileObject
from pymisp import MISPObject, MISPEvent
from pymisp import MISPObjectReference


##TODO Degrease
from lib.cuckoo.core.database import Database

sys.path.insert(0, os.path.join(os.path.abspath(os.path.dirname(__file__)), "..", ".."))
sys.path.insert(0, os.path.join(os.path.abspath(os.path.dirname(__file__)), "..","..", "web"))
sys.path.insert(0, os.path.join(os.path.abspath(os.path.dirname(__file__)), "..","..", "web", "web"))
os.environ.setdefault("DJANGO_SETTINGS_MODULE", "settings")
db = Database()

from django.conf import settings


try:
    with warnings.catch_warnings():
        warnings.simplefilter("ignore")
        import pymisp

    HAVE_MISP = True
except ImportError:
    HAVE_MISP = False
# import django
# from django.contrib.auth.models import User
from lib.cuckoo.common.abstracts import Report
from lib.cuckoo.common.exceptions import CuckooProcessingError
from lib.cuckoo.common.whitelist import is_whitelisted_domain, is_whitelisted_url, is_whitelisted_ip, \
    is_whitelisted_regex_url
from idstools import rule
#from lib.tldr.tldr import run_tldr
#from web.tlp_methods import get_tlp_users,get_analyses_numbers_matching_tlp

ruledict = {}
for filename in os.listdir("/etc/suricata/rules"):
    if filename.endswith('.rules'):
        part_dict =  {(rule_obj.sid, rule_obj.msg):rule_obj.raw for rule_obj in rule.parse_file(os.path.join("/etc/suricata/rules",filename))}
        ruledict.update(part_dict)

def mongoQuery(mdbquery):
    client = settings.MONGO
    #db = client.cuckoo
    cursor = client.analysis.find(mdbquery)
    return cursor

def check_sha1_in_network(sha1,results):
    for protocol in ("http_ex", "https_ex"):
        for entry in results.get("network", {}).get(protocol, []):
            if entry["sha1"] == sha1:
                uri_ = "%s://%s%s" % (entry["protocol"], entry["host"], entry["uri"])
                if (not is_whitelisted_domain(entry["host"])) and (not is_whitelisted_url(uri_)):
                    return uri_
def check_sha1_in_dropped(sha1,results):
    if 'dropped' in results:
        for drop in results["dropped"]:
            if drop["sha1"] == sha1:
                if 'filepath' in drop:
                    fpath = drop["filepath"]
                else:
                    fpath = drop["name"]
                return fpath
        return None
def get_file_from_pid(pid,results):
    for proc in results["behavior"]["processes"]:
        if proc["pid"] == pid:
            return proc["command_line"]
    return

def open_misp_json():
    with open(os.path.join(os.path.abspath(os.path.dirname(__file__)), "..","..","conf","misp.json"), "r") as m:
        mj = json.load(m)
        return mj

def get_objid_from_event(event,value):
    if 'Object' in event:
        for obj in event["Object"]:
            for att in obj["Attribute"]:
               if "value" in att and att["value"] == value:
                   return obj["uuid"]
        return None



class MISP(Report):
    """Enrich MISP with Cuckoo results."""
    """TLDR MISP Reporting"""

    def create_reference(self, obj_uuid, ref_uuid, relationship_type, comment = None):
        ref = MISPObjectReference()
        ref.from_dict(obj_uuid, ref_uuid, relationship_type,comment)
        return ref

    def get_tldr(self, results, event, initial_file_object, sharing_group):
        mongo_obj = mongoQuery({"info.id": self.task['id']})[0]
        yhits = set()
        refs_to_add = []
        ##TODO Tlp needs to be done
        tlp = "amber"
        if "tlp" in mongo_obj["info"]:
            tlp = mongo_obj["info"]["tlp"]

        # TODO: We haven't yet implemented a safe way to handle TLP Red in MISP, so for now TLP Red is verboten
        # if tlp == "red":
        #     return

        event_obj = MISPEvent()
        event_obj.load(event)
        if sharing_group:
            event_obj.sharing_group_id = sharing_group

        event_obj.distribution = 4 if tlp == "amber" and sharing_group else 3
        event_obj.add_tag("tlp:{0}".format(tlp))
        resolved_hosts = set()
        if 'network' in results and 'dns' in results['network']:
            resolved_hosts = set(map(lambda hostreq:hostreq["request"],
                filter(lambda host: not is_whitelisted_domain(host["request"]), results["network"]["dns"])))
        #self.misp.add_organisation(name="phoenix.beastmode.tools",description="Phoenix TLDR to MISP",)
        ## Go through the network traffic, try and correlate stage 1 -> stage 2
        if 'behavior' in results and 'summary' in results["behavior"]:
                # if 'resolves_host' in results["behavior"]["summary"]:
                #     resolved_hosts = set(filter(lambda host: not is_whitelisted_domain(host), results["behavior"]["summary"]["resolves_host"]))

                if 'connects_ip' in results["behavior"]["summary"]:
                    conn_added = []
                    for ncon in results["behavior"]["summary"]["connects_ip"]:
                        ##TODO add whitelisting
                        # if not str(deadcon[0]).startswith('10.200.0.') and not is_whitelisted_ip(deadcon[0]):
                        connects_ip = ncon[0] if isinstance(ncon, list) else ncon
                        if not str(connects_ip).startswith('10.200.0.') and not str(connects_ip) == "127.0.0.1":
                            ## Build the ip-dst object
                            ipdst_obj = MISPObject(name='network-connection', standalone=False, text="Potential C2 traffic")
                            ## Add your attributes
                            ipdst_obj.add_attribute('ip-dst', value=connects_ip)
                            ipdst_obj.add_attribute('text', type="text", value='Potential C2 traffic')
                            ## Add your reference
                            refs_to_add.append(self.create_reference(initial_file_object,ipdst_obj.uuid,  'communicates-with'))
                            ## Add your object
                            event_obj.add_object(ipdst_obj)

        urls_added = {}
        ips_added = {}
        for protocol in ("http_ex", "https_ex"):
            for entry in results.get("network", {}).get(protocol, []):
                if entry["host"] not in resolved_hosts:
                    continue
                uri_ = "%s://%s%s" % (entry["protocol"], entry["host"], entry["uri"])
                if (not is_whitelisted_domain(entry["host"])) and (not is_whitelisted_url(uri_) and (uri_ not in urls_added) and "." in uri_):
                    ## Check to see if the response body hash matches the hash of any of the files dropped on the filesystem
                    fname = check_sha1_in_dropped(entry["sha1"],results)
                    if not fname and "200 OK" in entry["response"]:
                        # If we didn't find it in dropped, but got a 200 OK, then the file was delivered, so make a file
                        # object from the SHA1
                        fname = entry["sha1"]
                    if fname:
                        ## We have a stage 1 -> stage 2 relationship.  Make the file object
                        file_object = self.make_file_object(fname, entry["path"], "Artifacts dropped")
                        #HACK: Bandaid code.  Find out what's happening, likely a bug in MISP
                        for attr in file_object["Attribute"]:
                            if attr["type"] == "malware-sample":
                                file_object["Attribute"].remove(attr)
                                break
                        ## Make the URL object
                        url_obj = MISPObject(name='url', standalone=False, text="File delivered from "+str(uri_)+" - Landed at: "+str(fname))
                        ## Add a URL attribute to the URL object
                        obj_attr = url_obj.add_attribute('url', value=uri_)
                        obj_attr.add_tag("tlp:{0}".format(tlp))
                        ## Relate the stage 1 -> stage 2
                        file_object.add_reference(url_obj.uuid, 'downloaded-from', 'File landed at '+str(fname))
                        refs_to_add.append(self.create_reference(initial_file_object,url_obj.uuid,'downloaded'))
                        refs_to_add.append(self.create_reference(initial_file_object,file_object.uuid, 'drops'))
                        file_object.add_reference(initial_file_object, 'dropped-by')
                        ## Add objects back to the event
                        urls_added[uri_] = url_obj.uuid
                        ips_added[entry["dst"]] = url_obj.uuid
                        event_obj.add_object(url_obj)
                        event_obj.add_object(file_object)
                    else:
                        ## If there are no related URLs, just add the URL object
                        url_obj = MISPObject(name='url', standalone=False)
                        url_obj.add_attribute('url', value=uri_).add_tag("tlp:{0}".format(tlp))
                        refs_to_add.append(self.create_reference(initial_file_object,url_obj.uuid,  'communicates-with'))
                        urls_added[uri_] = url_obj.uuid
                        event_obj.add_object(url_obj)
        if 'network' in results:
            if 'http' in results["network"]:
                for entry in results["network"]["http"]:
                    uri_ = entry["uri"]
                    if (not is_whitelisted_domain(entry["host"])) and (
                            not is_whitelisted_url(uri_) and (uri_ not in urls_added) and "." in uri_):
                        url_obj = MISPObject(name='url', standalone=False)
                        url_obj.add_attribute('url', value=uri_).add_tag("tlp:{0}".format(tlp))
                        refs_to_add.append(self.create_reference(initial_file_object, url_obj.uuid, 'communicates-with'))
                        urls_added[uri_] = url_obj.uuid
                        event_obj.add_object(url_obj)

            if 'domains' in results['network']:
                for entry in results["network"].get('domains',[]):
                    if entry["domain"] in resolved_hosts:
                        domain_obj = MISPObject(name="domain-ip", standalone=False, text="Domain and IP seen resolved")
                        domain_obj.add_attribute('domain', value=entry['domain'])
                        domain_obj.add_attribute('ip', value=entry['ip'])
                        refs_to_add.append(self.create_reference(initial_file_object,domain_obj.uuid,  'communicates-with'))
                        event_obj.add_object(domain_obj)
            if 'tcp' in results["network"]:
                tcp_added = []
                for tcpcon in results.get("tcp", {}).get('tcp', []):
                    if (tcpcon["dport"] > 1023) and (tcpcon["sport"] > 1023):
                        ##TODO grab this from the config instead
                        if str(tcpcon["dst"]).startswith('10.200.0.'):
                            dstip = tcpcon["src"]
                            dstport = tcpcon["sport"]
                            srcport = tcpcon["dport"]
                        else:
                            dstip = tcpcon["dst"]
                            dstport = tcpcon["dport"]
                            srcport = tcpcon["sport"]
                        ## Build the ip-dst object
                        ipdst_obj = MISPObject(name='ip-port', standalone=False, text="Potential TCP C2")
                        ## Add your attributes
                        ipdst_obj.add_attribute('src-port', value=srcport)
                        ipdst_obj.add_attribute('dst-port', value=dstport)
                        ipdst_obj.add_attribute('ip', value=dstip)
                        ## Add your reference
                        refs_to_add.append(self.create_reference(initial_file_object,ipdst_obj.uuid,  'communicates-with'))
                        ## Add your object
                        event_obj.add_object(ipdst_obj)

            if 'dead_hosts' in results["network"]:
                dead_added = []
                for deadcon in results["network"]["dead_hosts"]:
                    ##TODO add whitelisting
                    #if not str(deadcon[0]).startswith('10.200.0.') and not is_whitelisted_ip(deadcon[0]):
                    if not str(deadcon[0]).startswith('10.200.0.'):
                        ## Build the ip-dst object
                        ipdst_obj = MISPObject(name='ip-port', standalone=False, text="Potential Dead TCP C2")
                        ## Add your attributes
                        ipdst_obj.add_attribute('dst-port', value=deadcon[1])
                        ipdst_obj.add_attribute('ip', value=deadcon[0])
                        ipdst_obj.add_attribute('text', type="text", value='Potential Dead TCP C2')
                        ## Add your reference
                        refs_to_add.append(self.create_reference(initial_file_object,ipdst_obj.uuid,  'communicates-with'))
                        ## Add your object
                        event_obj.add_object(ipdst_obj)



        if 'suricata' in mongo_obj and 'alerts' in mongo_obj['suricata']:
            suri_added = []
            for alert in mongo_obj['suricata']['alerts']:
                if ((alert["sid"],alert["signature"]) in ruledict) and (alert["sid"] not in suri_added):
                    suri_added.append(alert["sid"])
                    suri_obj = MISPObject(name='suricata', standalone=False)
                    suri_obj.add_attribute('suricata', type="snort", value=ruledict[(alert["sid"], alert["signature"])])
                    event_obj.add_object(suri_obj)
                    refs_to_add.append(self.create_reference(suri_obj.uuid, initial_file_object, 'mitigates'))
                    if alert["dst_ip"] in ips_added:
                        refs_to_add.append(self.create_reference(suri_obj.uuid, ips_added[alert["dst_ip"]], 'mitigates'))
                    if alert["src_ip"] in ips_added:
                        refs_to_add.append(self.create_reference(suri_obj.uuid, ips_added[alert["src_ip"]], 'mitigates'))

        # Add URLs found in memory
        if 'procmemory' in mongo_obj:
            ## Didn't want to, but had to go back to mongo to get the procmemory stuff
            r = mongo_obj["procmemory"]
            for pmem in r:
                pid = pmem["pid"]
                ##TODO - add MISP Object for Command Line and relate it to the network traffic
                cli = get_file_from_pid(pid,results)
                seen_urls = set()
                for memurl in pmem["urls"]:
                    if memurl in seen_urls:
                        continue
                    seen_urls.add(memurl)
                    domain = memurl.split('://')[1].split('/')[0]
                    if (not is_whitelisted_url(memurl)) and (not is_whitelisted_domain(domain) and (not is_whitelisted_regex_url(memurl)) and "." in memurl):
                        ## Create a URL object and related it if found in memory and not whitelisted
                        if memurl in urls_added and initial_file_object:
                            refs_to_add.append(self.create_reference(urls_added[memurl], initial_file_object, 'contained-within'))
                        else:
                            url_obj = MISPObject(name='url', standalone=False, text="URL Found in memory")
                            url_attr = url_obj.add_attribute('url', value=memurl)
                            url_attr.add_tag("tlp:{0}".format(tlp))
                            event_obj.add_object(url_obj)
                            if initial_file_object:
                                refs_to_add.append(self.create_reference(url_obj.uuid, initial_file_object, 'contained-within'))

        ## Time to scan our files with our sharing ruleset, and create and tag mitigating controls
        if 'info' in results:
            ##TODO Check if rules have changed, and recompile
            ## Sometimes you've just got to debug
            #with open('/tmp/debug', 'w+') as dbgfile:
            #    dbgfile.write(str(results))
            ## Original binary path
            pwd = os.path.dirname(os.path.realpath(__file__))
            apath = os.path.join(pwd , "../../storage/analyses/", str(results["info"]["id"]))
            yrules = os.path.realpath(os.path.join(pwd ,"../../data/misp_yara"))
            if os.path.isdir(yrules):
                ## Yara code
                rules = yara.compile(filepaths={f:os.path.join(yrules,f) for f in os.listdir(yrules)})
                binary = os.path.join(apath, 'binary')
                bmatches = rules.match(binary)
                mcategory="Payload delivery"
                comment = ""
                if 'target' in results and 'file' in results["target"]:
                    ysha1 = results["target"]["file"]["sha1"]
                    ysha256 = results["target"]["file"]["sha256"]
                    ymd5 = results["target"]["file"]["md5"]
                    comment = "md5=" + str(ymd5) + " sha1=" + str(ysha1) + " sha256=" + str(ysha256)
                ## Process the matches
                self.process_yara_matches(bmatches, event_obj, mcategory, results, yrules,comment, ysha1, yhits,tlp)

                files_path = os.path.join(apath, "files")
                if os.path.isdir(files_path):

                    for ffilename in os.listdir(files_path):
                        comment = ""
                        ffile = os.path.join(files_path,ffilename)

                        ##TODO Find a better way than actually hashing the file
                        ysha1 = self.file_hash(ffile)
                        if 'dropped' in results:
                            for dfile in results["dropped"]:
                                if dfile["sha1"] == ysha1:
                                    ymd5=dfile["md5"]
                                    ysha256=dfile["sha256"]
                                    if 'filepath' in dfile:
                                        comment+='file_path='+str(dfile["filepath"])+" md5=" + str(ymd5) + " sha1=" + str(ysha1) + " sha256=" + str(ysha256)
                                    else:
                                        comment+='file_path='+str(dfile["name"])+" md5=" + str(ymd5) + " sha1=" + str(ysha1) + " sha256=" + str(ysha256)
                        fmatches = rules.match(ffile)
                        mcategory= "Artifacts dropped"
                        self.process_yara_matches(fmatches, event_obj, mcategory, results, yrules, comment, ysha1, yhits, tlp)

        ## Time to add the mutexes

        if 'dropped' in results:
            ##TODO Move this to a configuration file.  I do this to keep from flooding stuff in with noise.
            dropped_extensions = ["exe", "bat", "cmd", "url", "rtf","chm","lnk","dll","doc","sct"]
            dfiles = set()
            for drop in results["dropped"]:
                if 'filepath' in drop:
                    fpath = drop["filepath"]
                    ext = drop["filepath"].split(".")[-1]
                else:
                    fpath = drop["name"]
                    ext = drop["name"].split(".")[-1]
                if results["target"]["category"] == "file":
                    stage1sha1 = results["target"]["file"]["sha1"]
                    stage1 = get_objid_from_event(event_obj,stage1sha1)
                    file_object = self.make_file_object(fpath, drop["path"], "Artifacts dropped")
                    if stage1:
                        file_object.add_reference(stage1, 'dropped-by')
                    if 'behavior' in results and 'generic' in results["behavior"]:
                        for lproc in results["behavior"]["generic"]:
                            if 'summary' in lproc and 'mutex' in lproc["summary"]:
                                for mutex in lproc["summary"]["mutex"]:
                                    pproc = lproc["process_name"]
                                    ppath = lproc["process_path"]
                                    # for mdrop in results["dropped"]:
                                    pid = lproc["pid"]
                                    ## If the process name is the same as the filename from dropped split after the beginning guid
                                    if ('name' in drop) and (drop["name"].split("_", 1)[1] == pproc):
                                        mutex_obj = MISPObject(name='mutex', standalone=False)
                                        m_attr = mutex_obj.add_attribute('name', value=mutex)
                                        m_attr.add_tag("tlp:{0}".format(tlp))
                                        event_obj.add_object(mutex_obj)
                                        file_object.add_reference(mutex_obj.uuid,"uses")

                    event_obj.add_object(file_object)
        self.check_misp_errors(self.user_misp.update(event_obj), "Failed to update the event")
        for ref in refs_to_add:
            self.check_misp_errors(self.user_misp.add_object_reference(ref), "Failed to add references to object")

    def check_misp_errors(self,response, error_str):
        if "errors" in response:
            raise Exception("{0}: {1}".format(error_str, response["errors"][-1]))
        if "response" in response:
            return response["response"]

    def file_hash(self, filename):
        h = hashlib.sha1()
        with open(filename, 'rb', buffering=0) as f:
            for b in iter(lambda: f.read(128 * 1024), b''):
                h.update(b)
        return h.hexdigest()

    def process_yara_matches(self, bmatches, event, mcategory, results, yrules, comment, ysha1, yhits,tlp):
        for bmatch in bmatches:
            yrulename = bmatch.rule
            if yrulename in yhits: continue
            yfile = os.path.join(yrules, bmatch.namespace)
            with open(yfile, 'r') as myfile:
                yfilestring = myfile.read()
            yrulematch = re.search(r'rule\s+' + str(yrulename) + r'.*?\n\}', yfilestring,re.S)
            if yrulematch:
                if yrulename not in yhits:
                    yhits.add(yrulename)
                yara_object = MISPObject(name='yara', standalone=False, text=comment)
                y_attr = yara_object.add_attribute('yara', value=yrulematch.group(0))
                y_attr.add_tag("tlp:{0}".format(tlp))

                rel_obj = get_objid_from_event(event, ysha1)
                if rel_obj:
                    yara_object.add_reference(rel_obj, 'mitigates')
                event.add_object(yara_object)
                # self.misp.update(event)

    def sample_hashes(self, results, event):
        """For now only reports hash of the analyzed file, not of the dropped
        files, as we may have hundreds or even thousands of dropped files, and
        the misp.add_hashes() method doesn't accept multiple arguments yet."""
        if results.get("target", {}).get("file", {}):
            f = results["target"]["file"]
            self.user_misp.add_hashes(
                event,
                category="Payload delivery",
                filename=f["name"],
                md5=f["md5"],
                sha1=f["sha1"],
                sha256=f["sha256"],
                comment="File submitted to Cuckoo",
            )

    def maldoc_network(self, results, event):
        """Specific reporting functionality for malicious documents. Most of
        this functionality should be integrated more properly in the Cuckoo
        Core rather than being abused at this point."""
        urls = set()
        for signature in results.get("signatures", []):
            if signature["name"] != "malicious_document_urls":
                continue

            for mark in signature["marks"]:
                if (mark["category"] == "url") and (not is_whitelisted_url(mark["ioc"])):
                    urls.add(mark["ioc"])

        self.user_misp.add_url(event, sorted(list(urls)))

    def all_urls(self, results, event):
        """All of the accessed URLS as per the PCAP. *Might* have duplicates
        when compared to the 'maldoc' mode, but e.g., in offline mode, when no
        outgoing traffic is allowed, 'maldoc' reports URLs that are not present
        in the PCAP (as the PCAP is basically empty)."""
        urls = set()
        for protocol in ("http_ex", "https_ex"):
            for entry in results.get("network", {}).get(protocol, []):
                uri_ = "%s://%s%s" % (entry["protocol"], entry["host"], entry["uri"])
                if (not is_whitelisted_domain(entry["host"])) and (not is_whitelisted_url(uri_)):
                    urls.add(uri_)

        self.user_misp.add_url(event, sorted(list(urls)))

    def domain_ipaddr(self, results, event):

        #whitelist = [
        #    "www.msftncsi.com", "dns.msftncsi.com",
        #    "teredo.ipv6.microsoft.com", "time.windows.com",
        #]

        domains, ips = {}, set()
        for domain in results.get("network", {}).get("domains", []):
            if not is_whitelisted_domain(domain["domain"]):
                domains[domain["domain"]] = domain["ip"]
                ips.add(domain["ip"])

        ipaddrs = set()
        for ipaddr in results.get("network", {}).get("hosts", []):
            if (ipaddr not in ips) and (not is_whitelisted_ip(ipaddr)):
                ipaddrs.add(ipaddr)

        self.user_misp.add_domains_ips(event, domains)
        self.user_misp.add_ipdst(event, sorted(list(ipaddrs)))


    def make_file_object(self, filename, filepath, category):
        fileob = FileObject(filename=filename, filepath=filepath, standalone=False)
        for att in fileob["Attribute"]:
            if att["category"] and att["category"] != "Other":
                att["category"] = category
        return fileob


    def run(self, results):
        """Submits results to MISP.
        @param results: Cuckoo results dict.
        """
        if self.task["category"] != "file":
            return
        url = self.options.get("url")
        apikey = self.options.get("apikey")
        # email_suffix = self.options.get("email_suffix")
        mode = shlex.split(self.options.get("mode") or "")
        # django.setup()
        if not url or not apikey:
            raise CuckooProcessingError(
                "Please configure the URL and API key for your MISP instance."
            )

        self.misp = pymisp.PyMISP(url, apikey, False, "json")
        owner = self.task["owner"]
        # org_obj = self.misp.get_organisations_list()["response"]
        # orgs = map(lambda org: {"name": org["Organisation"]["name"], "id": org["Organisation"]["id"]}, org_obj)
        sharing_groups = self.misp.get_sharing_groups()
        email = db.get_email_for_user(owner)

        # user_object = User.objects.get(username=owner)
        # group_names = set([group.name for group in user_object.groups.all()])
        # common_groups = set(map(lambda org: org["name"], orgs)) & group_names

        # users_map = map(lambda user: {user["User"]["email"]: user["User"]["authkey"]}, self.misp.get_users_list()["response"])
        users_map = {user["User"]["email"]: {"auth_key": user["User"]["authkey"], "org_id": user["Organisation"]["id"]} for user in self.check_misp_errors(self.misp.get_users_list(), "Couldn't get users from MISP")}
        #user_email = user_object.email
        user_email = email
        if user_email in users_map and self.task["tlp"] != "red":
            misp_user = users_map[user_email]
            self.user_misp = pymisp.PyMISP(url, users_map[user_email]["auth_key"], False, "json")
            if self.task["tlp"] == "amber":
                my_groups = filter(lambda group: any(group_org["org_id"] == misp_user["org_id"] for group_org in group["SharingGroupOrg"]),sharing_groups)
                if not my_groups:
                    print "No sharing groups found for {0}".format(user_email)
                for sharing_group in my_groups:
                    self.publish_event(mode, results, sharing_group["SharingGroup"]["id"])
            else:
                self.publish_event(mode, results)
        else:
            if self.task["tlp"] != "red":
                print "Could not find user {0}, submitting event under default account".format(user_email)
            else:
                print "TLP Is red for {0}, exporting to filesystem".format(self.task["id"])
            self.user_misp = self.misp
            self.publish_event(mode, results)

    def publish_event(self, mode, results, sharing_group=None):
        event = self.user_misp.new_event(
            distribution=3,

            threat_level_id=4,
            analysis=2,
            info="Phoenix Sandbox analysis #%d" % self.task["id"],


        )
        initial_file_object = None
        if results.get("target", {}).get("category") == "file":
            # OLd and busted (pymisp==2.4.54)
            # self.org_misp.upload_sample(
            #    filename=os.path.basename(self.task["target"]),
            #    filepath=self.task["target"],
            #    event_id=event["Event"]["id"],
            #    category="External analysis",
            # )
            # New Hotness (pymisp==2.4.92.1)
            # results.get("target", {}).get("file", {})
            # file_object = self.make_file_object(results["target"]["info"]["name"], results["target"]["info"]["path"])
            # initial_file_object = file_object.uuid
            # event_obj.add_object(file_object)
            # self.org_misp.update(event_obj)
            ## they don't make it easy to get the filename and the filepath, so i'll just let the original upload sample handle that, and look for a hash that matches and grab the object ID.
            ## Super Greasy...
            response = self.user_misp.upload_sample(
                os.path.basename(self.task["target"]),
                self.task["target"],
                event["Event"]["id"],
                category="External analysis",
            )
            event = self.user_misp.get_event(event["Event"]["id"])

            isha1 = self.file_hash(os.path.join(settings.CUCKOO_PATH, 'storage/analyses/{0}/binary'.format(str(self.task["id"]) )))
            initial_file_object = get_objid_from_event(event["Event"], isha1)
        if "hashes" in mode:
            self.sample_hashes(results, event)
        if "maldoc" in mode:
            self.maldoc_network(results, event)
        if "url" in mode:
            self.all_urls(results, event)
        if "ipaddr" in mode:
            self.domain_ipaddr(results, event)
        if "tldr" in mode:
            self.get_tldr(results, event, initial_file_object, sharing_group)
        misptag = open_misp_json()
        eid = event["Event"]["id"]
        e_uuid = event["Event"]["uuid"]
        new_event = self.user_misp.get_event(eid)

        alist = []
        attributes = new_event["Event"]["Attribute"]
        objs = new_event["Event"]["Object"]
        for obj in objs:
            if 'Attribute' in obj:
                for attr in obj["Attribute"]:
                    alist.append({"attr": attr, "oid": obj["id"]})
        for att in attributes:
            alist.append(att)
        tags_to_add = set()
        for attribute in alist:
            deleted = False
            aid = attribute["attr"]["id"]
            uuid = attribute["attr"]["uuid"]
            val = attribute["attr"]["value"]
            comment = attribute["attr"]["comment"]
            for pv in misptag["purge"]["values"]:
                rematch = re.search(pv, val)
                if rematch:
                    self.check_misp_errors(self.user_misp.delete_object(attribute["oid"]),"Couldn't delete object")
                    deleted = True
                    break
            if deleted: continue
            for pc in misptag["purge"]["comments"]:
                rematch = re.search(pc, comment)
                if rematch:
                    self.check_misp_errors(self.user_misp.delete_object(attribute["oid"]), "Couldn't delete object")
                    deleted = True
                    break
            if deleted: continue
            for atv in misptag["add_tags"]["values"]:
                regex = atv["regex"]
                rematch = re.search(regex, val)
                if rematch:
                    for tag in atv["tags"]:
                        self.user_misp.tag(uuid, tag)
                        tags_to_add.add(tag)
            for atc in misptag["add_tags"]["comments"]:
                regex = atc["regex"]
                rematch = re.search(regex, comment)
                if rematch:
                    for tag in atc["tags"]:
                        self.user_misp.tag(uuid, tag)
                        tags_to_add.add(tag)
        for tag in tags_to_add:
            self.user_misp.tag(e_uuid, tag)

        if self.task["tlp"] != "red":
            self.user_misp.fast_publish(eid)
        else:
            # dumping the event object or using .get_event returns an object with all the actual malware-samples intact,
            # making the file huge.  This is actually how MISP exports stuff.
            event_json = self.user_misp.search(eventid=eid)
            with open(os.path.join(settings.CUCKOO_PATH, 'storage/analyses/{0}/mispreport.json'.format(str(self.task["id"]))), 'w+') as f:
                json.dump(event_json, f)
            self.check_misp_errors(self.user_misp.delete_event(eid), "Failed deleting the event")

