import os
from idstools import rule
from django.conf import settings


def get_suricata_rules(path="/etc/suricata/rules"):
    ruledict = {}
    for filename in os.listdir(path):
        if filename.endswith('.rules'):
            part_dict = {(rule_obj.sid, rule_obj.msg): rule_obj.raw for rule_obj in
                         rule.parse_file(os.path.join(path, filename))}
            ruledict.update(part_dict)
    return ruledict


def get_hunting_suri_rules(hunt_id):
    analyses_prefix = settings.ANALYSES_PREFIX
    hunt_path = os.path.join(analyses_prefix, ".hunting", hunt_id,"0")
    return get_suricata_rules(hunt_path)