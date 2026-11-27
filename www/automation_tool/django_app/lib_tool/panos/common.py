# Helpers shared by every PAN-OS version class.
# version classes call these through their own methods, override there
import requests
import xmltodict
import xml.parsers.expat

requests.packages.urllib3.disable_warnings()

# (connect, read) timeout, avoid hanging forever
API_TIMEOUT = (10, 120)

# TLS verify: False by default, or a CA bundle path via APP_PANOS_CA_BUNDLE
try:
    from django.conf import settings
    TLS_VERIFY = settings.PANOS_TLS_VERIFY
except Exception:
    TLS_VERIFY = False


#one session per firewall per job, keep-alive
def new_session():
    session = requests.Session()
    session.verify = TLS_VERIFY
    return session


# firewall error, message safe to show
class FirewallError(Exception):
    pass



#no traceback, paths or URLs on pages, full details in server log
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


#non-JSON body like a proxy error page gives an error dict
def json_or_error(response):
    try:
        return response.json()
    except ValueError:
        return {'code': response.status_code, 'message': f'HTTP {response.status_code}, response is not JSON'}


def location_params(location_object):
    params = {'location': location_object['location']}
    sub = location_object.get('@' + location_object['location'])
    if sub:
        params[location_object['location']] = sub
    return params


#no XML <response> means proxy page or wrong address
def xml_response(response):
    try:
        data = xmltodict.parse(response.text)
    except xml.parsers.expat.ExpatError:
        raise FirewallError(f'HTTP {response.status_code}, response is not XML')
    if not isinstance(data, dict) or not isinstance(data.get('response'), dict):
        raise FirewallError(f'HTTP {response.status_code}, response is not a PAN-OS answer (proxy or wrong address?)')
    return data['response']


def xml_api_msg(rs):
    #unknown message shapes returned as sent, never guessed
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
            if 'msg' in keys:
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
