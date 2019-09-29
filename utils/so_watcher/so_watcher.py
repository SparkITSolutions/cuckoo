import argparse
import sys
import time
import logging
import random
from random import  randint

from datetime import datetime

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)
import pyinotify

import os
import yara

# Put your stuff here
import requests

owner = "YOUR USERNAME HERE"
url = "YOUR URL HERE"

mytime = datetime.now().strftime('%Y-%m-%d %H:%M:%s')
rules = yara.compile(os.path.join(os.path.dirname(os.path.abspath(__file__)), "rules", "watcher_rules.yar"))
wm = pyinotify.WatchManager()  # Watch Manager
mask = pyinotify.IN_CLOSE_WRITE | pyinotify.IN_MOVED_TO  # watched events

def yara_test(file_path):
    return any(rules.match(filepath=file_path))

def submit_to_phoenix(file_path,vpn = True):
    stime = randint(20,25)

    files = dict(
        file=open(file_path, "rb"),
        filename=os.path.basename(file_path)
    )
    vpns = ["Romania"]
    with open(file_path, 'rb') as sample:
        if vpn:
            data = dict(options='route=' + random.choice(vpns) + ',procmemdump=yes',
                        owner=owner, tlp='red', timeout=stime, enforce_timeout=True, priority=1)
        else:
            data = dict(options='procmemdump=yes', owner=owner, tlp='red', timeout=stime,
                        enforce_timeout=True, priority=1)
        # if ftype:
        #     data['package'] = ftype
        # return
        r = requests.post(url, files=files, data=data, auth=(user,passw))
        logger.info(mytime + " " + str(r))

class EventHandler(pyinotify.ProcessEvent):
    def process_IN_CLOSE_WRITE(self, event):
        logger.info("Creating: {0}".format(event.pathname))
        self.process_internal(event)

    def process_IN_MOVED_TO(self, event):
        logger.info("Moved: {0}".format(event.pathname))
        self.process_internal(event)


    def process_internal(self,event):
        if yara_test(event.pathname):
            logger.info("{0} matched the yara rules, submitting to Phoenix".format(event.pathname))
            submit_to_phoenix(event.pathname)

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description="Submit created/modified and moved files to Phoenix")
    parser.add_argument('path', help='Path to watch for files')
    parser.add_argument('-u', '--user', help='Username for Phoenix frontdoor')
    parser.add_argument('-p', '--password', help='Password for Phoenix frontdoor')
    args = parser.parse_args()
    global user
    global passw
    user = args.user
    passw = args.password
    handler = EventHandler()
    notifier = pyinotify.Notifier(wm, handler)
    wdd = wm.add_watch(sys.argv[1], mask, rec=False)

    notifier.loop()
