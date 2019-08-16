# Copyright (C) 2010-2013 Claudio Guarnieri.
# Copyright (C) 2014-2016 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import os.path

import re

from lib.cuckoo.common.constants import CUCKOO_ROOT

domains = set()
urls = set()
ips = set()
url_regexes = []

def is_whitelisted_domain(domain):
    return domain in domains

def is_whitelisted_url(url):
    return url in urls

def is_whitelisted_ip(ip):
    return ip in ips

def is_whitelisted_regex_url(url):
    for regex in url_regexes:
        if re.search(regex, url):
            return True
    return False
# Initialize the domain whitelist.
for domain in open(os.path.join(CUCKOO_ROOT, "data", "whitelist", "domain.txt")):
    domains.add(domain.strip())

# Initialize the URL whitelist.
for url in open(os.path.join(CUCKOO_ROOT, "data", "whitelist", "url.txt")):
    urls.add(url.strip())

# Initialize the URL whitelist.
for ip in open(os.path.join(CUCKOO_ROOT, "data", "whitelist", "ip.txt")):
    ips.add(ip.strip())

with open(os.path.join(CUCKOO_ROOT, "data", "whitelist", "url_regex.txt"), 'rb') as regex_lines:
    for regex in regex_lines:
        url_regexes.append(regex.strip())