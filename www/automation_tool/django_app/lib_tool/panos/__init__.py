# PAN-OS API by firewall version.
#
# class chosen once per firewall and job: major.minor, then major, then DEFAULT
# a version class holds the API and the field rules of its version
#
# New version:
#   1. lib_tool/panos/v12_1.py:  from .v11_1 import PanOS11_1
#                                class PanOS12_1(PanOS11_1):      # only what differs from 11.1
#                                    NAME_MAX = 127               # field rule
#                                    def create_nat_rule(self, object, location_object): ...   # API call
#      Same API and rules as 11.1:  class PanOS11_2(PanOS11_1): pass
#   2. here: import it and add it to API_CLASSES
# one class per supported version of the API portal, EoL versions use DEFAULT
import re
import threading
from .common import new_session, FirewallError, xml_response, xml_api_msg, API_TIMEOUT
from .v11_1 import PanOS11_1
from .v10_1 import PanOS10_1

# default class for versions without their own class
API_CLASSES = {'11.1': PanOS11_1, '10.1': PanOS10_1}
DEFAULT = PanOS11_1

APIS = {}
_sessions = {}
_lock = threading.Lock()


def select_class(sw_version):
    m = re.match(r'(\d+)\.(\d+)', sw_version or '')
    if not m:
        return DEFAULT
    return API_CLASSES.get(f'{m.group(1)}.{m.group(2)}') or API_CLASSES.get(m.group(1)) or DEFAULT


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


#not connected: DEFAULT class, no REST URL
def api(host, token):
    current = APIS.get(host)
    if current is not None and current.token == token:
        return current
    return DEFAULT(host, token, None, _sessions.get(host) or new_session())


def describe(host):
    current = APIS.get(host)
    if current is None:
        return 'PAN-OS ? (not read)'
    name = type(current).__name__
    m = re.match(r'(\d+)\.(\d+)', current.sw_version)
    default = ' (default, no class for ' + f'{m.group(1)}.{m.group(2)} / {m.group(1)})' if type(current) is DEFAULT and m.group(1) not in API_CLASSES and f'{m.group(1)}.{m.group(2)}' not in API_CLASSES else ''
    return f'PAN-OS {current.sw_version} -> REST API /restapi/{current.rest_base().split("/restapi/")[1]}/, API class {name}{default}'
