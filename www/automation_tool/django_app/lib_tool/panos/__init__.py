# PAN-OS API by firewall version.
#
# After the API key, the PAN-OS version of each firewall is read (show system info) and the matching class is
# chosen ONCE per firewall and per job: exact 'major.minor' -> 'major' -> DEFAULT (PanOS11_1). Every request to that
# firewall then goes through its object (same HTTPS session = TLS connection reused).
# A version class holds the API AND the field rules of that version (limits of names, descriptions, allowed values...).
#
# New version:
#   1. lib_tool/panos/v12_1.py:  from .v11_1 import PanOS11_1
#                                class PanOS12_1(PanOS11_1):      # override ONLY what differs from 11.1
#                                    NAME_MAX = 127               #   a field rule (attribute, see PanOS11_1)
#                                    def create_nat_rule(self, object, location_object): ...   #   an API call
#      Same API and rules as 11.1:  class PanOS11_2(PanOS11_1): pass
#   2. here: import it and add it to API_CLASSES, e.g. {'11.1': PanOS11_1, '12.1': PanOS12_1}
# One class per SUPPORTED version of the PAN-OS API portal (docs.paloaltonetworks.com, skill panos-version-diff);
# end-of-life versions have no class: they use DEFAULT (works or not, user decision 2026-11-25).
import re
import threading
from .common import new_session, FirewallError, xml_response, xml_api_msg, API_TIMEOUT
from .v11_1 import PanOS11_1

# standard = PanOS11_1 (API + field rules read on PAN-OS 11.1); a version without its own class uses it
API_CLASSES = {'11.1': PanOS11_1}
DEFAULT = PanOS11_1

APIS = {}            # host -> API object of the current job (one per firewall)
_sessions = {}       # host -> session opened by keygen, handed to the API object by connect()
_lock = threading.Lock()


def select_class(sw_version):
    m = re.match(r'(\d+)\.(\d+)', sw_version or '')
    if not m:
        return DEFAULT
    return API_CLASSES.get(f'{m.group(1)}.{m.group(2)}') or API_CLASSES.get(m.group(1)) or DEFAULT


#API key (version independent: the version is not known yet); the session is kept for this firewall
def keygen(host, user, password):
    session = new_session()
    response = session.post(f'https://{host}/api/', data={'type': 'keygen', 'user': user, 'password': password}, timeout=API_TIMEOUT)
    rs = xml_response(response)
    if response.status_code == 200 and rs.get('@status') == 'success':
        with _lock:
            old = _sessions.pop(host, None)
            _sessions[host] = session
        if old:
            old.close()
        return rs['result']['key']
    session.close()
    raise FirewallError(xml_api_msg(rs) or f'HTTP {response.status_code}')


#read the PAN-OS version (read only) and create the API object of the firewall with the matching class
def connect(host, token):
    with _lock:
        session = _sessions.pop(host, None) or new_session()
    response = session.post(f'https://{host}/api/', data={'type': 'op', 'cmd': '<show><system><info></info></system></show>', 'key': token},
                            timeout=API_TIMEOUT)
    rs = xml_response(response)
    if rs.get('@status') != 'success':
        raise FirewallError(xml_api_msg(rs) or 'show system info refused')
    try:
        sw = str(rs['result']['system']['sw-version'])
    except (KeyError, TypeError):
        raise FirewallError('no sw-version in show system info')
    if not re.match(r'\d+\.\d+', sw):
        raise FirewallError(f'unknown PAN-OS version {sw[:40]!r}')
    api = select_class(sw)(host, token, sw, session)
    with _lock:
        old = APIS.get(host)
        APIS[host] = api
    if old and old.session is not session:
        old.session.close()
    return api


#API object of a firewall; not connected (version not read, e.g. old caller) -> DEFAULT class, no REST URL (no guess)
def api(host, token):
    current = APIS.get(host)
    if current is not None and current.token == token:
        return current
    return DEFAULT(host, token, None, _sessions.get(host) or new_session())


#text for the job page: version, REST path and class used for this firewall
def describe(host):
    current = APIS.get(host)
    if current is None:
        return 'PAN-OS ? (not read)'
    name = type(current).__name__
    m = re.match(r'(\d+)\.(\d+)', current.sw_version)
    default = ' (default, no class for ' + f'{m.group(1)}.{m.group(2)} / {m.group(1)})' if type(current) is DEFAULT and m.group(1) not in API_CLASSES and f'{m.group(1)}.{m.group(2)}' not in API_CLASSES else ''
    return f'PAN-OS {current.sw_version} -> REST API /restapi/{current.rest_base().split("/restapi/")[1]}/, API class {name}{default}'
