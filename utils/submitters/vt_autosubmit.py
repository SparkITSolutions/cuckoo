#!/usr/bin/python
## This only works for RL right now, VT polling will be added shortly
import requests, json, os.path, random, logging, hashlib, sys
from datetime import date, timedelta, datetime
from random import randint
import pprint
import plyara
import magic

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)
now = date.today()
rnow = datetime.now()
yesterday = date.today() - timedelta(1)
yest = yesterday.strftime('%Y-%m-%d')
today = now.strftime('%Y-%m-%d')
mytime = rnow.strftime('%Y-%m-%d %H:%M:%s')
storagedir = "/data/malicious_files"
akey = 'YOUR_VT_KEY_HERE'
owner_org = "YOUR_ORG_HERE"
import os, random, requests

def get_ftype(f):
    mtype = magic.from_file(f,mime=True)
    if mtype == "application/msword" or mtype == "application/vnd.openxmlformats-officedocument.wordprocessingml.document" or mtype == "application/rtf":
        return "doc"
    if mtype == "application/vnd.ms-excel" or mtype == "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet":
        return "xls"
    if mtype == "application/vnd.ms-powerpoint" or mtype == "application/vnd.openxmlformats-officedocument.presentationml.presentation":
        return "ppt"
    if mtype == "application/pdf":
        return "pdf"
    if mtype == "text/html":
        return "ie"
    if mtype == "application/java-archive":
        return "jar"
    if mtype == "application/zip":
        return "zip"
    if mtype == "text/javascript":
        return "js"
    if mtype == "application/octet-stream" or mtype == "application/x-dosexec":
        return "exe"
    ## TODO - create deep file checks for .vbs and .ps1, since those don't have mim types

def sha1_checksum(filename, block_size=65536):
    sha1 = hashlib.sha1()
    with open(filename, 'rb') as f:
        for block in iter(lambda: f.read(block_size), b''):
            sha1.update(block)
    return sha1.hexdigest()

def sha256_checksum(filename, block_size=65536):
    sha256 = hashlib.sha256()
    with open(filename, 'rb') as f:
        for block in iter(lambda: f.read(block_size), b''):
            sha256.update(block)
    return sha256.hexdigest()

def get_vt_rules(akey):
    parser = plyara.Plyara()
    resp = requests.get('https://www.virustotal.com/intelligence/hunting/export-ruleset/?ruleset=*&key='+str(akey))
    rules_list = parser.parse_string(resp.content)
    return rules_list
    
def get_vt_file(akey,fhash, yrule):
    if not os.path.exists(storagedir + '/' + yrule["rule_name"]):
        os.makedirs(storagedir + '/' + yrule["rule_name"])
    ofile = os.path.join(storagedir, yrule["rule_name"], fhash)
    resp = requests.get('https://www.virustotal.com/intelligence/download/?hash='+str(fhash)+'&apikey='+str(akey))
    downloaded_file = resp.content
    f = open(ofile, 'w')
    f.write(downloaded_file)
    f.close()
    return ofile

def submit2cuckoo(myfile, vpn, ftype, vrule):
    stime = randint(15,20)
    logger.info(mytime + ' submitting : ' + myfile)
    url = "http://127.0.0.1:8090/tasks/create/file"
    files = dict(
        file=open(myfile, "rb"),
        filename=os.path.basename(myfile)
    )
    vpns = ["Brazil","CAToronto","Netherlands","HongKong","Romania","Spain","USEast"]
    with open(myfile, 'rb') as sample:
        if vpn:
            data = dict(options='route=' + random.choice(vpns) + ',procmemdump=yes',
                        owner=vrule["author"], tlp=vrule["tlp"], timeout=stime, enforce_timeout=True)
        else:
            data = dict(options='procmemdump=yes', owner=vrule["author"], tlp=vrule["tlp"], timeout=stime,
                        enforce_timeout=True)
        if ftype:
            data['package'] = ftype
        return
        r = requests.post(url, files=files, data=data)
        logger.info(mytime + " " + str(r))

def dupeCheck(myhash):
    logger.debug(mytime + " Checking existing store for Sample " + myhash)
    for root, dirs, files in os.walk(storagedir):
        for name in files:
            if myhash in name:
                logger.debug(mytime + ' already have the file ' + myhash)
                return True
            else:
                return False

def getFileList():
    params = {'apikey': akey}
    response = requests.get('https://www.virustotal.com/intelligence/hunting/notifications-feed/?key=' + akey)
    results = ""
    for r in response:
        results = results + r
    hits = json.loads(results)
    return hits

def process_file(fhash, vrule):
    if not dupeCheck(fhash):
        ofile = get_vt_file(akey, fhash, vrule)
        submit2cuckoo(ofile,True,get_ftype(ofile),vrule)

myrules = get_vt_rules(akey)
valid_rules = []
for rule in myrules:
    author = None
    tlp = None
    risk_score = None
    rname = rule["rule_name"]
    if 'Padding' in rname:
        print rname
    if "metadata" not in rule:
        logger.info(mytime+' - Invalid rule - No metadata for rule='+str(rname))
        continue
    else:
        for m in rule["metadata"]:
            if "author" in m:
                author = m["author"]
            if "tlp" in m:
                tlp = m["tlp"]
            if "risk_score" in m:
                risk_score = m["risk_score"]
    if author and tlp and risk_score and author.endswith(owner_org):
        valid_rules.append({"rule_name":rname,"author":author.lower(),"tlp":tlp.lower(),"risk_score":risk_score})
        
myf = getFileList()
for hit in myf["notifications"]:
    rulename = hit["subject"]
    for v in valid_rules:
        if (':' in rulename and rulename.startswith(v["rule_name"])) or (rulename == v["rule_name"]):
            process_file(hit["sha256"],v)
