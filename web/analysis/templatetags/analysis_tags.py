from django.template.defaultfilters import register
from django.templatetags import static

from lib.phoenix.constants import PUBLISHERS_GROUP


@register.filter
def mongo_id(value):
    """Retrieve _id value.
    @todo: it will be removed in future.
    """
    if isinstance(value, dict):
        return value.get("_id", value)

    # Return value
    return unicode(value)

@register.filter
def is_dict(value):
    """Checks if value is an instance of dict"""
    return isinstance(value, dict)

@register.filter
def get_item(dictionary, key):
    return dictionary.get(key, "")

@register.filter
def filter_key_if_has(l, key):
    ret = []
    for x in l:
        if key not in x or x[key]:
            ret.append(x)
    return ret

@register.filter
def custom_length(dictionary, keys):
    if not dictionary:
        return 0

    ret = 0
    for key in keys.split():
        ret += len(dictionary.get(key, []))
    return ret

@register.filter
def volsort(l):
    """Sort baselined Volatility results. Results with `class_` set have a
    higher priority over the regular results."""
    if not l:
        return

    for x in l:
        if x.get("class_"):
            yield x

    for x in l:
        if not x.get("class_"):
            yield x

@register.filter
def isdeadip(ipaddr, analysis):
    # It doesn't make much sense to report a dead IP address when the analysis
    # didn't have internet access in the first place.
    if analysis.get("info", {}).get("route") == "none":
        return

    for ip, port in analysis.get("network", {}).get("dead_hosts", []):
        if ip == ipaddr:
            return True

@register.filter
def sigsort(l):
    """Sort signatures entries. Generic explanations come first, followed by
    IOCs, followed by API calls."""
    if not l:
        return

    for x in l:
        if x.get("type", x.get("_type")) == "generic":
            yield x

    for x in l:
        if x.get("type", x.get("_type")) == "ioc":
            yield x

    first = True
    for x in l:
        if x.get("type", x.get("_type")) == "call":
            if first:
                x["first"] = True
                first = False
            yield x

@register.filter
def ensurelist(o):
    if isinstance(o, (tuple, list)):
        return o
    return o,

@register.filter
def sizeof_fmt(num):
    suffix = "B"
    for unit in ["", "K", "M", "G", "T", "P", "E", "Z"]:
        if abs(num) < 1024.0:
            return "%3.1f%s%s" % (num, unit, suffix)
        num /= 1024.0
    return "%.1f%s%s" % (num, "Yi", suffix)

@register.filter
def process_name(pid, analysis):
    for proc in analysis.get("behavior", {}).get("generic", []):
        if proc["pid"] == pid:
            return proc["process_name"]

@register.simple_tag
def vt_link(url_fragment, value):
    return '<a href="https://www.virustotal.com/#/{0}/{1}" target="_blank"><img class="vtimage" src="{2}" /></a><a href="https://www.virustotal.com/intelligence/search/?query={1}" target="_blank"><img class="vtimage" src="{3}" /></a>'.format(url_fragment, value, static.static("images/virustotal.png"), static.static("images/intelligence-small.png"))

@register.simple_tag
def rl_link(url_fragment, value):
    querystr = "{0}%3A{1}".format(url_fragment,value)
    if url_fragment == "uri":
        querystr="{0}%3A{1}%20OR%20c2%3A{1}".format(url_fragment,value)

    return '<a href="https://a1000.reversinglabs.com/search/?q={0}" target="_blank"><img class="vtimage" src="{1}" /></a>'.format(querystr, static.static("images/reversinglabs.png"))


@register.filter(name='is_publisher')
def has_group(user):
    return user.groups.filter(name=PUBLISHERS_GROUP).exists()
