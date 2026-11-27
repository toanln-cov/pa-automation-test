# Helpers shared by every PAN-OS version class: HTTP session, errors, XML / JSON answers.
# json_or_error / location_params / xml_response / xml_api_msg: the version class calls them through its own methods
# (self.json_or_error...), so a version with another format overrides the method in its class, not here. keygen and
# 'show system info' (panos/__init__.py) use them directly: the version is not known yet at that point.
import requests
import xmltodict
import xml.parsers.expat

# Disable self-signed warning
requests.packages.urllib3.disable_warnings()

# (connect, read) timeout in seconds for every request to firewall, avoid hanging forever
API_TIMEOUT = (10, 120)

# TLS certificate check of the firewalls: False (default, firewalls usually have self-signed certs)
# or path of a CA bundle (APP_PANOS_CA_BUNDLE) -> certificate verified, MITM between tool and firewall detected
try:
    from django.conf import settings
    TLS_VERIFY = settings.PANOS_TLS_VERIFY
except Exception:
    TLS_VERIFY = False


#one HTTPS session per firewall and per job: the TLS connection is reused by every request (keep-alive)
def new_session():
    session = requests.Session()
    session.verify = TLS_VERIFY
    return session


# error reported by the firewall itself (message is safe to show)
class FirewallError(Exception):
    pass



#short message of an exception for the pages: no traceback, no server path, no URL details (full details go to the server log)
def safe_error(e, limit=200):
    if isinstance(e, FirewallError):
        text = str(e)
    elif isinstance(e, requests.exceptions.ConnectTimeout):
        text = 'connection timeout (firewall unreachable?)'
    elif isinstance(e, requests.exceptions.ReadTimeout):
        text = 'no response from the firewall (timeout)'
    elif isinstance(e, requests.exceptions.SSLError):
        text = 'TLS error with the firewall'
    elif isinstance(e, requests.exceptions.ConnectionError):
        text = 'cannot connect to the firewall (refused / no route)'
    elif isinstance(e, (xml.parsers.expat.ExpatError, ValueError, KeyError, TypeError, IndexError)):
        text = 'unexpected response from the firewall'
    else:
        text = 'unexpected error (' + type(e).__name__ + ')'
    return text if len(text) <= limit else text[:limit] + '...'


#json body of a REST response; non-JSON body (proxy / web server error page) -> error dict, no exception
def json_or_error(response):
    try:
        return response.json()
    except ValueError:
        return {'code': response.status_code, 'message': f'HTTP {response.status_code}, response is not JSON'}


#query params of location for GET: {'location': 'vsys', '@vsys': 'vsys1'} -> location=vsys&vsys=vsys1 ; {'location': 'shared'} -> location=shared
def location_params(location_object):
    params = {'location': location_object['location']}
    sub = location_object.get('@' + location_object['location'])
    if sub:
        params[location_object['location']] = sub
    return params


#<response> of an XML API answer; not XML, or XML without <response> (proxy error page, wrong address) -> FirewallError
def xml_response(response):
    try:
        data = xmltodict.parse(response.text)
    except xml.parsers.expat.ExpatError:
        raise FirewallError(f'HTTP {response.status_code}, response is not XML')
    if not isinstance(data, dict) or not isinstance(data.get('response'), dict):
        raise FirewallError(f'HTTP {response.status_code}, response is not a PAN-OS answer (proxy or wrong address?)')
    return data['response']


#readable message of XML API response
def xml_api_msg(rs):
    #known PAN-OS message shapes -> text: <msg>t</msg>, <result><msg>t</msg></result>, <msg><line>t</line>...</msg>,
    #nested <line>; several lines joined with '; ' ('Validation Error: rule1 ...' after a line ending with ':').
    #Any other shape -> the answer as the firewall sent it (XML), never a guess.
    def text(value):
        if isinstance(value, str):
            return value.strip()
        if isinstance(value, list):
            out = ''
            for part in (text(v) for v in value):
                if part:
                    out += (' ' if out.endswith(':') else '; ') + part if out else part
            return out
        if isinstance(value, dict):
            keys = [k for k in value if not k.startswith('@')]
            if 'msg' in keys:                                  # e.g. commit: <result><msg>..</msg><job>12</job></result>
                return text(value['msg'])
            if keys == ['line'] or keys == ['#text']:
                return text(value[keys[0]])
        raise ValueError('unknown message shape')
    if not rs:
        return ''
    try:
        if isinstance(rs, dict):
            msg = text(rs['msg']) if 'msg' in rs else text(rs.get('result') or '')
        else:
            msg = text(rs)
        if msg:
            return msg
    except ValueError:
        pass
    try:
        raw = xmltodict.unparse({'response': rs} if isinstance(rs, dict) else {'msg': rs}, full_document=False)
    except Exception:
        raw = str(rs)
    return raw if len(raw) <= 500 else raw[:500] + '...'
