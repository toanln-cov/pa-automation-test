# PAN-OS 11.1: default class for versions without their own class
# other version: subclass in vX_Y.py, override only what differs, add to API_CLASSES
import copy
import ipaddress
import json
import re
from datetime import datetime
import xml.etree.ElementTree as ET
from xml.sax.saxutils import escape
from . import common
from .common import API_TIMEOUT, FirewallError
from . import fields


class PanOS11_1:
    # --- field rules of PAN-OS 11.1
    NAME_MAX = 63
    NAME_CHARS = re.compile(r'[ 0-9a-zA-Z._-]')
    NAME_CHARS_TEXT = 'letters, digits, space, . _ -'
    DESCRIPTION_MAX_OBJECT = 1023                   # bytes in UTF-8, not characters
    DESCRIPTION_MAX_RULE = 1024
    TAG_MAX = 127
    TAG_CHARS = re.compile(r'[^&<"\'\[\]\x00-\x1f\x7f]')     # REST refuses these in a tag name
    TAGS_MAX = 64
    ZONE_MAX = 31
    PROFILE_GROUP_MAX = 31
    URL_CATEGORY_MAX = 31
    LOG_FORWARDING_MAX = 63
    INTERFACE_MAX = 31
    ADDRESS_TYPES = ('ip-netmask', 'ip-range', 'ip-wildcard', 'fqdn')
    FQDN = re.compile(r'[a-zA-Z0-9_]([a-zA-Z0-9._-])+[a-zA-Z0-9]')
    FQDN_MAX = 255
    PORT_MAX = 65535
    TIMEOUT_MAX = 604800
    TIMEWAIT_MAX = 600
    ACTIONS = ('allow', 'deny', 'drop', 'reset-client', 'reset-server', 'reset-both')
    YES_NO = ('yes', 'no')
    NAT_TYPES = ('ipv4',)                           # nat64 / nptv6 not supported
    NAT_TYPES_REFUSED = ('nat64', 'nptv6')
    HA_BINDINGS = ('primary', 'both', '0', '1')
    DESTINATION_TRANSLATION_TYPES = ('none', 'static', 'dynamic')     # none = no destination NAT
    DNS_REWRITE = ('no', 'reverse', 'forward')                       # no = no dns-rewrite
    DISTRIBUTIONS = ('round-robin', 'source-ip-hash', 'ip-modulo', 'ip-hash', 'least-sessions')
    TRANSLATE_PORT_MAX = 65535
    LIST_COLUMNS = ('Tag', 'Member', 'Source-zone', 'Destination-zone', 'Source-ip', 'Destination-ip', 'Application', 'Service',
                    'Url-category', 'Source-user', 'Profile-group', 'Src-translate-address')     # Service: not for NAT
    ANY = 'any'                                     # only name accepted in any case
    ANY_COLUMNS = ('Source-zone', 'Destination-zone', 'Source-ip', 'Destination-ip', 'Application', 'Service', 'Url-category',
                   'Source-user')
    SERVICE_ALONE = ('any', 'application-default')
    SOURCE_USER_KEYWORDS = ('pre-logon', 'known-user', 'unknown')
    VSYS_NAME = re.compile(r'vsys[1-9][0-9]*')
    CLEAR_WORD = 'none'                             # whole cell 'none' clears the value on edit sheets
    # 0.0.0.0/0 and ::/0 refused, use any
    ALL_ADDRESSES = (ipaddress.ip_network('0.0.0.0/0'), ipaddress.ip_network('::/0'))
    # web UI color name to PAN-OS code, no color18
    TAG_COLORS = {'red': 'color1', 'green': 'color2', 'blue': 'color3', 'yellow': 'color4', 'copper': 'color5',
                  'orange': 'color6', 'purple': 'color7', 'gray': 'color8', 'light green': 'color9', 'cyan': 'color10',
                  'light gray': 'color11', 'blue gray': 'color12', 'lime': 'color13', 'black': 'color14', 'gold': 'color15',
                  'brown': 'color16', 'olive': 'color17', 'maroon': 'color19', 'red-orange': 'color20',
                  'yellow-orange': 'color21', 'forest green': 'color22', 'turquoise blue': 'color23', 'azure blue': 'color24',
                  'cerulean blue': 'color25', 'midnight blue': 'color26', 'medium blue': 'color27', 'cobalt blue': 'color28',
                  'violet blue': 'color29', 'blue violet': 'color30', 'medium violet': 'color31', 'medium rose': 'color32',
                  'lavender': 'color33', 'orchid': 'color34', 'thistle': 'color35', 'peach': 'color36', 'salmon': 'color37',
                  'magenta': 'color38', 'red violet': 'color39', 'mahogany': 'color40', 'burnt sienna': 'color41',
                  'chestnut': 'color42'}
    TAG_COMMENTS_MAX = 1023
    PREDEFINED_TAGS = ('Sanctioned', 'empty')       # predefined tags, not in the REST list
    KIND_TEXT = {'tag': 'tag', 'address': 'address object', 'address_group': 'address group', 'service': 'service object',
                 'service_group': 'service group', 'security_rule': 'security rule', 'nat_rule': 'NAT rule'}
    # NAT columns used by each translation type
    NAT_DST_COLUMNS = {'none': (), 'static': ('Dns-rewrite', 'Dst-translate-address', 'Translate-port'),
                       'dynamic': ('Distribution', 'Dst-translate-address', 'Translate-port')}
    NAT_SRC_COLUMNS = {'none': (), 'dynamic-ip-and-port with Translate address': ('Src-translate-address',),
                       'dynamic-ip-and-port with Interface address IP': ('Src-translate-interface', 'Src-translate-address-ip'),
                       'dynamic-ip-and-port with Interface address Floating IP': ('Src-translate-interface', 'Src-translate-address-ip'),
                       'dynamic-ip': ('Src-translate-address',), 'static-ip': ('Src-translate-address', 'static-bi-directional')}

    # --- PAN-OS values used by the tool
    POSITIONS = ('top', 'bottom', 'before', 'after')                 # before / after need dst
    SOURCE_TRANSLATION_TYPES = ('none', 'dynamic-ip-and-port with Translate address', 'dynamic-ip-and-port with Interface address IP',
                                'dynamic-ip-and-port with Interface address Floating IP', 'dynamic-ip', 'static-ip')
    PREDEFINED_SERVICES = ('any', 'application-default', 'service-http', 'service-https')
    GROUP_PREDEFINED_SERVICES = ('service-http', 'service-https')
    JOB_FINISHED = 'FIN'                            # show jobs: finished and successful
    JOB_OK = 'OK'

    # --- dry-run: name lists read once per firewall and vsys
    REFERENCE_SOURCES = {
        'address': ['get_Objects_Addresses', 'get_Objects_AddressGroups', 'get_Objects_ExternalDynamicLists', 'get_Objects_Regions'],
        'address_member': ['get_Objects_Addresses', 'get_Objects_AddressGroups'],
        'service': ['get_Objects_Services', 'get_Objects_ServiceGroups'],
        'security_rule': ['get_security_rule'],
        'nat_rule': ['get_nat_rule'],
        'zone': ['get_Zones'],
        'tag': ['get_Objects_Tags'],                # predefined tags refused in a rule / object
        'profile_group': ['get_Objects_SecurityProfileGroups'],
        'log_forwarding': ['get_Objects_LogForwardingProfiles'],
        'url_category': ['get_Objects_CustomURLCategories', ('predefined_names', ('pan-url-categories',), 'predefined URL categories')],
        'application': ['get_Objects_Applications', 'get_Objects_ApplicationGroups', 'get_Objects_ApplicationFilters'],
        'vsys': ['get_VirtualSystems'],
        'tag_entry': ['get_Objects_Tags'],
    }
    REFERENCE_SHARED = ('get_Objects_Addresses', 'get_Objects_AddressGroups', 'get_Objects_ExternalDynamicLists',     # shared objects usable by a vsys
                        'get_Objects_Services', 'get_Objects_ServiceGroups', 'get_Objects_Tags',
                        'get_Objects_SecurityProfileGroups', 'get_Objects_LogForwardingProfiles',
                        'get_Objects_CustomURLCategories', 'get_Objects_Applications',
                        'get_Objects_ApplicationGroups', 'get_Objects_ApplicationFilters')
    REFERENCE_NOT_CASE_SENSITIVE = ()               # references are case-sensitive, tags too
    REFERENCE_EXCLUDED = {'address_member': ('ip-wildcard',)}
    MEMBER_REFUSED = {'get_Objects_ExternalDynamicLists': 'an EDL', 'get_Objects_Regions': 'a region',
                      'ip-wildcard': 'an ip-wildcard address'}
    STATIC_MEMBERS = 'address objects (ip-netmask, ip-range, fqdn) or address groups'
    NAME_SPACES = {                                 # same name refused across these kinds: "Name Not Unique"
        'address': ('address_group', 'get_Objects_AddressGroups', 'address group'),
        'address_group': ('address', 'get_Objects_Addresses', 'address object'),
        'service': ('service_group', 'get_Objects_ServiceGroups', 'service group'),
        'service_group': ('service', 'get_Objects_Services', 'service object'),
    }
    LIST_NAMES = {
        'get_Objects_Addresses': 'address objects', 'get_Objects_AddressGroups': 'address groups',
        'get_Objects_Services': 'service objects', 'get_Objects_ServiceGroups': 'service groups',
        'get_security_rule': 'security rules', 'get_nat_rule': 'NAT rules',
        'get_Zones': 'zones', 'get_Objects_Tags': 'tags', 'get_Objects_SecurityProfileGroups': 'security profile groups',
        'get_Objects_LogForwardingProfiles': 'log forwarding profiles', 'get_Objects_CustomURLCategories': 'custom URL categories',
        'get_Objects_ExternalDynamicLists': 'external dynamic lists', 'get_Objects_Regions': 'regions',
        'get_Objects_Applications': 'applications', 'get_Objects_ApplicationGroups': 'application groups',
        'get_Objects_ApplicationFilters': 'application filters', 'get_VirtualSystems': 'virtual systems',
    }

    def __init__(self, host, token, sw_version, session):
        self.host = host
        self.token = token
        self.sw_version = sw_version
        self.session = session                       # one HTTPS session per firewall, TLS reused

    # --- firewall answers: REST
    def is_success(self, rs):
        return isinstance(rs, dict) and (rs.get('@code') == '20' or rs.get('@status') == 'success')

    #text of a success line
    def success_text(self, rs):
        return str(rs.get('msg') or 'command succeeded')

    #readable error text from the PAN-OS error JSON
    #details are for display only, may change between releases
    def error_text(self, rs):
        if isinstance(rs, dict) and ('message' in rs or 'code' in rs):
            message = str(rs.get('message') or rs.get('msg') or 'error')
            causes = []
            for detail in rs.get('details') or []:
                for cause in (detail.get('causes') or []) if isinstance(detail, dict) else []:
                    text = cause.get('description') if isinstance(cause, dict) else None
                    if text and text != message and text not in causes:
                        causes.append(str(text))
            result = 'FAILED: ' + message + (' - ' + '; '.join(causes) if causes else '')
            return result + (f" (code {rs['code']})" if 'code' in rs else '')
        return 'FAILED: ' + str(rs)

    #fake success answer for dry-run writes
    def dry_answer(self, action):
        return {'@code': '20', 'msg': 'CAN ' + action.upper()}

    #error text of a failed answer, never raises
    def answer_text(self, response):
        try:
            rs = response.json()
            if isinstance(rs, dict) and ('message' in rs or 'code' in rs or 'details' in rs):
                text = self.error_text(rs).removeprefix('FAILED: ')
                text = ' '.join(''.join(ch if ch.isprintable() else ' ' for ch in text).split())
                return text if len(text) <= 200 else text[:200] + '...'
        except Exception:
            pass
        return f"HTTP {getattr(response, 'status_code', '?')}, unexpected answer"

    #entries of a list answer
    def entries(self, response):
        try:
            rs = response.json()
        except Exception:
            rs = None
        if isinstance(rs, dict) and rs.get('@status') == 'success':
            result = rs.get('result')
            entry = result.get('entry') if isinstance(result, dict) else None
            entry = [entry] if isinstance(entry, dict) else (entry or [])
            if isinstance(entry, list) and all(isinstance(e, dict) and '@name' in e for e in entry):
                return entry, ''
        return None, self.answer_text(response)

    #bare IP must be an address object name
    def is_literal_address(self, name):
        return name == 'any' or (len(name) == 2 and name.isalpha() and name.isupper())

    #NAT translated address: object name or bare IP both accepted
    def is_ip_literal(self, name):
        try:
            if '-' in name:
                first, last = name.split('-', 1)
                ipaddress.ip_address(first)
                ipaddress.ip_address(last)
            else:
                ipaddress.ip_network(name, strict=False)
            return True
        except ValueError:
            return False

    def job_finished(self, status):
        return status['status'] == self.JOB_FINISHED

    def job_ok(self, status):
        return status['result'] == self.JOB_OK

    # --- Excel row to REST entry
    #Name column: mandatory + naming rule
    def take_name(self, row_dict, object, check_mandatory_value):
        value = row_dict.get('Name')
        reason = '' if fields.empty(value) else self.name_error(value)
        if not fields.empty(value) and not reason:
            object['entry']['@name'] = str(value)
            return
        check_mandatory_value['status'] = False
        check_mandatory_value['msg'] += ' Name Input Error' + (f' ({reason})' if reason else '') + ' +++'

    #field rules of the other columns
    def take_rules(self, kind, row_dict, check_mandatory_value):
        for col, reason in self.check_row(kind, row_dict):
            check_mandatory_value['status'] = False
            check_mandatory_value['msg'] += f' {col} Input Error ({reason}) +++'

    #Excel row to REST tag entry
    def build_tag(self, row_dict, check_mandatory_value):
        object = {'entry': {'@name': ''}}
        value = row_dict.get('Name')
        reason = '' if fields.empty(value) else self.tag_name_error(value)
        if fields.empty(value) or reason:
            check_mandatory_value['status'] = False
            check_mandatory_value['msg'] += ' Name Input Error' + (f' ({reason})' if reason else '') + ' +++'
        else:
            object['entry']['@name'] = str(value)
        self.take_rules('tag', row_dict, check_mandatory_value)
        if not fields.empty(row_dict.get('Color')):
            object['entry']['color'] = self.TAG_COLORS.get(str(row_dict['Color']).strip().lower(), '')
        if not fields.empty(row_dict.get('Comments')):
            object['entry']['comments'] = str(row_dict['Comments'])
        return object

    def tag_name_error(self, value):
        text = str(value)
        if len(text) > self.TAG_MAX:
            return f'max {self.TAG_MAX} characters, has {len(text)}'
        bad = fields.bad_chars(text, self.TAG_CHARS)
        return f'not allowed: {bad}' if bad else ''

    #Excel row to REST address entry
    def build_address(self, row_dict, check_mandatory_value):
        object = {'entry': {}}

        #check mandatory value:
        self.take_name(row_dict, object, check_mandatory_value)
        self.take_rules('address', row_dict, check_mandatory_value)

        try:
            fields.check_nan_value(row_dict['Type'])
            fields.check_nan_value(row_dict['Value'])
            object['entry'][str(row_dict['Type'])] = str(row_dict['Value'])
        except Exception as e:
            if e:
                check_mandatory_value['status'] = False
                check_mandatory_value['msg'] += ' Type Input or Value Input Error +++' 


        #check optional value:
        try:
            if not fields.empty(row_dict.get('Tag')):
                object['entry']['tag'] = {'member': []}
                object['entry']['tag']['member'] = [m.strip() for m in str(row_dict['Tag']).split(',')]
        except Exception as e:
            if e:
                check_mandatory_value['status'] = False
                check_mandatory_value['msg'] += ' Tag Input Error +++'

        try:
            if not fields.empty(row_dict.get('Description')):
                object['entry']['description'] = str(row_dict['Description'])
        except Exception as e:
            if e:
                check_mandatory_value['status'] = False
                check_mandatory_value['msg'] += ' Description Input Error +++'

        return object

    #Excel row to REST address group entry
    def build_address_group(self, row_dict, check_mandatory_value):
        object = {
            'entry': {
                '@name': '',
                'static': {
                    'member': []
                    }
                }
            }

        #check mandatory value:
        self.take_name(row_dict, object, check_mandatory_value)
        self.take_rules('address_group', row_dict, check_mandatory_value)

        try:
            fields.check_nan_value(row_dict['Member'])
            object['entry']['static']['member'] = [m.strip() for m in str(row_dict['Member']).split(',')]
        except Exception as e:
            if e:
                check_mandatory_value['status'] = False
                check_mandatory_value['msg'] += ' Member Input Error (required) +++' 

        #check optional value:
        try:
            if not fields.empty(row_dict.get('Tag')):
                object['entry']['tag'] = {'member': []}
                object['entry']['tag']['member'] = [m.strip() for m in str(row_dict['Tag']).split(',')]
        except Exception as e:
            if e:
                check_mandatory_value['status'] = False
                check_mandatory_value['msg'] += ' Tag Input Error +++'

        try:
            if not fields.empty(row_dict.get('Description')):
                object['entry']['description'] = str(row_dict['Description'])
        except Exception as e:
            if e:
                check_mandatory_value['status'] = False
                check_mandatory_value['msg'] += ' Description Input Error +++'

        return object

    #Excel row to REST service entry
    #second value: entry without timeouts, for the duplicate check
    def build_service(self, row_dict, check_mandatory_value):
        object = {
            'entry': {
                '@name': '',
                'protocol': {}
                }
            }


        #check mandatory value:
        self.take_name(row_dict, object, check_mandatory_value)
        self.take_rules('service', row_dict, check_mandatory_value)

        protocol = None                      # None if Protocol invalid: skip dependent columns
        try:
            fields.check_nan_value(row_dict['Protocol'])
            if str(row_dict['Protocol']).lower() == 'tcp' or str(row_dict['Protocol']).lower() == 'udp':
                protocol = str(row_dict['Protocol']).lower()
                object['entry']['protocol'][protocol] = {'port':''}
            else:
                raise ValueError("Invalid protocol")
        except Exception as e:
            if e:
                check_mandatory_value['status'] = False
                check_mandatory_value['msg'] += ' Protocol Input Error +++' 
        try:
            fields.check_nan_value(row_dict['Destination-port'])
            port = str(row_dict['Destination-port']).lower()
            if protocol:
                object['entry']['protocol'][protocol]['port'] = port
        except Exception as e:  
            if e:
                check_mandatory_value['status'] = False     
                check_mandatory_value['msg'] += ' Destination-port Input Error +++'

        #check optional value:
        try:
            if protocol and not fields.empty(row_dict.get('Source-port')):
                object['entry']['protocol'][protocol]['source-port'] = str(row_dict['Source-port'])
        except Exception as e:
            if e:
                check_mandatory_value['status'] = False
                check_mandatory_value['msg'] += ' Source-port Input Error +++'

        object2 = copy.deepcopy(object)

        try:
            if protocol and not fields.empty(row_dict.get('Override')) and (str(row_dict['Override']).lower() == 'yes'):
                override = str(row_dict['Override']).lower()
                object['entry']['protocol'][protocol]['override'] = {}
                object['entry']['protocol'][protocol]['override'][override] = {}
                object2['entry']['protocol'][protocol]['override'] = {override: {}}
                if not fields.empty(row_dict.get('Timeout')):
                    object['entry']['protocol'][protocol]['override'][override]['timeout'] = int(row_dict['Timeout'])
                    object2['entry']['protocol'][protocol]['override'][override]['timeout'] = str(row_dict['Timeout'])
                if protocol == 'tcp':
                    if not fields.empty(row_dict.get('Halfclose-timeout')):
                        object['entry']['protocol'][protocol]['override'][override]['halfclose-timeout'] = int(row_dict['Halfclose-timeout'])
                        object2['entry']['protocol'][protocol]['override'][override]['halfclose-timeout'] = str(row_dict['Halfclose-timeout'])
                    if not fields.empty(row_dict.get('Timewait-timeout')):
                        object['entry']['protocol'][protocol]['override'][override]['timewait-timeout'] = int(row_dict['Timewait-timeout'])
                        object2['entry']['protocol'][protocol]['override'][override]['timewait-timeout'] = str(row_dict['Timewait-timeout'])

        except Exception as e:
            if e:
                check_mandatory_value['status'] = False
                check_mandatory_value['msg'] += ' Override Input Error +++'

        try:
            if not fields.empty(row_dict.get('Tag')):
                object['entry']['tag'] = {'member': []}
                object['entry']['tag']['member'] = [m.strip() for m in str(row_dict['Tag']).split(',')]
        except Exception as e:
            if e:
                check_mandatory_value['status'] = False
                check_mandatory_value['msg'] += ' Tag Input Error +++'

        try:
            if not fields.empty(row_dict.get('Description')):
                object['entry']['description'] = str(row_dict['Description'])
        except Exception as e:
            if e:
                check_mandatory_value['status'] = False
                check_mandatory_value['msg'] += ' Description Input Error +++'

        return object, object2

    #Excel row to REST service group entry
    def build_service_group(self, row_dict, check_mandatory_value):
        object = {
            'entry': {
                '@name': '',
                'members': {
                    'member': []
                    }
                }
            }

        #check mandatory value:
        self.take_name(row_dict, object, check_mandatory_value)
        self.take_rules('service_group', row_dict, check_mandatory_value)

        try:
            fields.check_nan_value(row_dict['Member'])
            object['entry']['members']['member'] = [m.strip() for m in str(row_dict['Member']).split(',')]
        except Exception as e:
            if e:
                check_mandatory_value['status'] = False
                check_mandatory_value['msg'] += ' Member Input Error (required) +++' 

        #check optional value:
        try:
            if not fields.empty(row_dict.get('Tag')):
                object['entry']['tag'] = {'member': []}
                object['entry']['tag']['member'] = [m.strip() for m in str(row_dict['Tag']).split(',')]
        except Exception as e:
            if e:
                check_mandatory_value['status'] = False
                check_mandatory_value['msg'] += ' Tag Input Error +++'

        #service groups have no description, firewall refuses it

        return object

    #Excel row to REST security rule entry
    def build_security_rule(self, row_dict, check_mandatory_value):
        object = {
            'entry': {
                '@name': '', 
                'to': {'member': []}, 
                'from': {'member': []}, 
                'source': {'member': []}, 
                'destination': {'member': []}, 
                'application': {'member': []}, 
                'service': {'member': []},  
                'action': '', 
                'disabled': 'no',
                }
            }

        #check mandatory value:
        self.take_name(row_dict, object, check_mandatory_value)
        self.take_rules('security_rule', row_dict, check_mandatory_value)

        try:
            fields.check_nan_value(row_dict['Source-zone'])
            object['entry']['from']['member'] = [m.strip() for m in str(row_dict['Source-zone']).split(',')]
        except Exception as e:  
            if e:
                check_mandatory_value['status'] = False
                check_mandatory_value['msg'] += ' Source-zone Input Error +++'    

        try:
            fields.check_nan_value(row_dict['Destination-zone'])
            object['entry']['to']['member'] = [m.strip() for m in str(row_dict['Destination-zone']).split(',')]
        except Exception as e:  
            if e:
                check_mandatory_value['status'] = False
                check_mandatory_value['msg'] += ' Destination-zone Input Error +++'  

        try:
            fields.check_nan_value(row_dict['Source-ip'])
            object['entry']['source']['member'] = [m.strip() for m in str(row_dict['Source-ip']).split(',')]
        except Exception as e:  
            if e:
                check_mandatory_value['status'] = False
                check_mandatory_value['msg'] += ' Source-ip Input Error +++'  

        try:
            fields.check_nan_value(row_dict['Destination-ip'])
            object['entry']['destination']['member'] = [m.strip() for m in str(row_dict['Destination-ip']).split(',')]
        except Exception as e:  
            if e:
                check_mandatory_value['status'] = False
                check_mandatory_value['msg'] += ' Destination-ip Input Error +++'  

        try:
            fields.check_nan_value(row_dict['Application'])
            object['entry']['application']['member'] = [m.strip() for m in str(row_dict['Application']).split(',')]
        except Exception as e:  
            if e:
                check_mandatory_value['status'] = False
                check_mandatory_value['msg'] += ' Application Input Error +++' 

        try:
            fields.check_nan_value(row_dict['Service'])
            object['entry']['service']['member'] = [m.strip() for m in str(row_dict['Service']).split(',')]
        except Exception as e:  
            if e:
                check_mandatory_value['status'] = False
                check_mandatory_value['msg'] += ' Service Input Error +++' 

        try:
            fields.check_nan_value(row_dict['Action'])
            object['entry']['action'] = str(row_dict['Action'])
        except Exception as e:
            if e:
                check_mandatory_value['status'] = False
                check_mandatory_value['msg'] += ' Action Input Error +++' 


        #check optional value:
        try:
            if not fields.empty(row_dict.get('Disable')):
                object['entry']['disabled'] = str(row_dict['Disable'])
        except Exception as e:
            if e:
                check_mandatory_value['status'] = False
                check_mandatory_value['msg'] += ' Disable Input Error +++' 

        try:
            if not fields.empty(row_dict.get('Tag')):
                object['entry']['tag'] = {'member': []}
                object['entry']['tag']['member'] = [m.strip() for m in str(row_dict['Tag']).split(',')]
        except Exception as e:
            if e:
                check_mandatory_value['status'] = False
                check_mandatory_value['msg'] += ' Tag Input Error +++' 

        try:
            if not fields.empty(row_dict.get('Description')):
                object['entry']['description'] = str(row_dict['Description'])
        except Exception as e:
            if e:
                check_mandatory_value['status'] = False
                check_mandatory_value['msg'] += ' Description Input Error +++' 

        try:
            if not fields.empty(row_dict.get('Log-forwarding')):
                object['entry']['log-setting'] = str(row_dict['Log-forwarding'])
        except Exception as e:
            if e:
                check_mandatory_value['status'] = False
                check_mandatory_value['msg'] += ' Log-forwarding Input Error +++' 

        try:
            if not fields.empty(row_dict.get('Log-start')):
                object['entry']['log-start'] = str(row_dict['Log-start'])
        except Exception as e:
            if e:
                check_mandatory_value['status'] = False
                check_mandatory_value['msg'] += ' Log-start Input Error +++' 

        try:
            if not fields.empty(row_dict.get('Log-end')):
                object['entry']['log-end'] = str(row_dict['Log-end'])
        except Exception as e:
            if e:
                check_mandatory_value['status'] = False
                check_mandatory_value['msg'] += ' Log-end Input Error +++' 

        try:
            if not fields.empty(row_dict.get('Profile-group')):
                object['entry']['profile-setting'] = {'group': {}}
                object['entry']['profile-setting']['group'] = {'member': []}
                object['entry']['profile-setting']['group']['member'] = [m.strip() for m in str(row_dict['Profile-group']).split(',')]
        except Exception as e:
            if e:
                check_mandatory_value['status'] = False
                check_mandatory_value['msg'] += ' Profile-group Input Error +++' 


        try:
            if not fields.empty(row_dict.get('Url-category')):
                object['entry']['category'] = {'member': []}
                object['entry']['category']['member'] = [m.strip() for m in str(row_dict['Url-category']).split(',')]
        except Exception as e:
            if e:
                check_mandatory_value['status'] = False
                check_mandatory_value['msg'] += ' Url-category Input Error +++' 

        try:
            if not fields.empty(row_dict.get('Source-user')):
                object['entry']['source-user'] = {'member': []}
                object['entry']['source-user']['member'] = [m.strip() for m in str(row_dict['Source-user']).split(',')]
        except Exception as e:
            if e:
                check_mandatory_value['status'] = False
                check_mandatory_value['msg'] += ' Source-user Input Error +++'

        return object

    #Excel row to REST NAT rule entry
    def build_nat_rule(self, row_dict, check_mandatory_value):
        object = {
            'entry': {
                '@name': '', 
                'to': {'member': []}, 
                'from': {'member': []}, 
                'source': {'member': []}, 
                'destination': {'member': []}, 
                'service': {'member': []},  
                'to-interface': '', 
                'disabled': 'no',
                'nat-type': '',
                'active-active-device-binding': 'primary',          # empty = primary, PAN-OS default
                }
            }

        #check mandatory value:
        self.take_name(row_dict, object, check_mandatory_value)
        self.take_rules('nat_rule', row_dict, check_mandatory_value)

        try:
            fields.check_nan_value(row_dict['Source-zone'])
            object['entry']['from']['member'] = [m.strip() for m in str(row_dict['Source-zone']).split(',')]
        except Exception as e:  
            if e:
                check_mandatory_value['status'] = False
                check_mandatory_value['msg'] += ' Source-zone Input Error +++'    

        try:
            fields.check_nan_value(row_dict['Destination-zone'])
            object['entry']['to']['member'] = [m.strip() for m in str(row_dict['Destination-zone']).split(',')]
        except Exception as e:  
            if e:
                check_mandatory_value['status'] = False
                check_mandatory_value['msg'] += ' Destination-zone Input Error +++'  

        try:
            fields.check_nan_value(row_dict['Source-ip'])
            object['entry']['source']['member'] = [m.strip() for m in str(row_dict['Source-ip']).split(',')]
        except Exception as e:  
            if e:
                check_mandatory_value['status'] = False
                check_mandatory_value['msg'] += ' Source-ip Input Error +++'  

        try:
            fields.check_nan_value(row_dict['Destination-ip'])
            object['entry']['destination']['member'] = [m.strip() for m in str(row_dict['Destination-ip']).split(',')]
        except Exception as e:  
            if e:
                check_mandatory_value['status'] = False
                check_mandatory_value['msg'] += ' Destination-ip Input Error +++'  

        try:
            fields.check_nan_value(row_dict['Service'])
            object['entry']['service'] = str(row_dict['Service'])
        except Exception as e:  
            if e:
                check_mandatory_value['status'] = False
                check_mandatory_value['msg'] += ' Service Input Error +++' 

        try:
            fields.check_nan_value(row_dict['Destination-interface'])
            object['entry']['to-interface'] = str(row_dict['Destination-interface'])
        except Exception as e:  
            if e:
                check_mandatory_value['status'] = False
                check_mandatory_value['msg'] += ' Destination-interface Input Error +++' 


        object['entry'].update(self.nat_translation(row_dict, check_mandatory_value))

        try:
            fields.check_nan_value(row_dict['Nat-type'])
            object['entry']['nat-type'] = str(row_dict['Nat-type'])
        except Exception as e:
            if e:
                check_mandatory_value['status'] = False
                check_mandatory_value['msg'] += ' Nat-type Input Error +++' 

        try:
            fields.check_nan_value(row_dict['Disable'])
            object['entry']['disabled'] = str(row_dict['Disable'])
        except Exception as e:
            if e:
                check_mandatory_value['status'] = False
                check_mandatory_value['msg'] += 'Disable Input Error +++' 

        #--- Active-active-device-binding: HA active-active only
        if not fields.empty(row_dict.get('Active-active-device-binding')):
            object['entry']['active-active-device-binding'] = str(row_dict['Active-active-device-binding'])


        #check optional value:
        try:
            if not fields.empty(row_dict.get('Group-tag')):
                object['entry']['group-tag'] = str(row_dict['Group-tag'])
        except Exception as e:
            if e:
                check_mandatory_value['status'] = False
                check_mandatory_value['msg'] += ' Group-tag Input Error +++' 

        try:
            if not fields.empty(row_dict.get('Tag')):
                object['entry']['tag'] = {'member': []}
                object['entry']['tag']['member'] = [m.strip() for m in str(row_dict['Tag']).split(',')]
        except Exception as e:
            if e:
                check_mandatory_value['status'] = False
                check_mandatory_value['msg'] += ' Tag Input Error +++' 

        try:
            if not fields.empty(row_dict.get('Description')):
                object['entry']['description'] = str(row_dict['Description'])
        except Exception as e:
            if e:
                check_mandatory_value['status'] = False
                check_mandatory_value['msg'] += ' Description Input Error +++'

        return object

    #NAT translation keys of a row
    def nat_translation(self, row_dict, check_mandatory_value):
        return dict(self.nat_dst_translation(row_dict, check_mandatory_value), **self.nat_src_translation(row_dict, check_mandatory_value))

    #destination part
    def nat_dst_translation(self, row_dict, check_mandatory_value):
        object = {'entry': {}}
        try:
            fields.check_nan_value(row_dict['Destination-translation-type'])
            if str(row_dict['Destination-translation-type']) == 'static':
                object['entry']['destination-translation'] = {'translated-address':''}
                try:
                    fields.check_nan_value(row_dict['Dns-rewrite'])
                    if str(row_dict['Dns-rewrite']) == 'no':
                        pass
                    elif str(row_dict['Dns-rewrite']) == 'reverse':
                        object['entry']['destination-translation']['dns-rewrite'] = {'direction': 'reverse'}
                    elif str(row_dict['Dns-rewrite']) == 'forward':
                        object['entry']['destination-translation']['dns-rewrite'] = {'direction': 'forward'}
                    else:
                        raise ValueError('invalid Dns-rewrite')
                except Exception as e:
                    if e:
                        check_mandatory_value['status'] = False
                        check_mandatory_value['msg'] += ' Dns-rewrite Input Error' + (' (required for static)' if fields.empty(row_dict.get('Dns-rewrite')) else '') + ' +++'

                try:
                    fields.check_nan_value(row_dict['Dst-translate-address'])
                    object['entry']['destination-translation']['translated-address'] = str(row_dict['Dst-translate-address'])
                except Exception as e:  
                    if e:
                        check_mandatory_value['status'] = False
                        check_mandatory_value['msg'] += ' Dst-translate-address Input Error' + (' (required for static)' if fields.empty(row_dict.get('Dst-translate-address')) else '') + ' +++'

                try:
                    fields.check_nan_value(row_dict['Translate-port'])
                    if str((row_dict['Translate-port'])) == 'all':
                        pass
                    else:
                        object['entry']['destination-translation']['translated-port'] = int(row_dict['Translate-port'])     # REST: integer 1-65535
                except Exception as e:  
                    if e:
                        check_mandatory_value['status'] = False
                        check_mandatory_value['msg'] += ' Translate-port Input Error' + (' (required for static)' if fields.empty(row_dict.get('Translate-port')) else '') + ' +++'

            elif str(row_dict['Destination-translation-type']) == 'dynamic':
                object['entry']['dynamic-destination-translation'] = {'translated-address':''}

                try:
                    fields.check_nan_value(row_dict['Dst-translate-address'])
                    object['entry']['dynamic-destination-translation']['translated-address'] = str(row_dict['Dst-translate-address'])
                except Exception as e:  
                    if e:
                        check_mandatory_value['status'] = False
                        check_mandatory_value['msg'] += ' Dst-translate-address Input Error' + (' (required for dynamic)' if fields.empty(row_dict.get('Dst-translate-address')) else '') + ' +++'

                try:
                    fields.check_nan_value(row_dict['Translate-port'])
                    if str((row_dict['Translate-port'])) == 'all':
                        pass
                    else:
                        object['entry']['dynamic-destination-translation']['translated-port'] = int(row_dict['Translate-port'])     # REST: integer 1-65535
                except Exception as e:  
                    if e:
                        check_mandatory_value['status'] = False
                        check_mandatory_value['msg'] += ' Translate-port Input Error' + (' (required for dynamic)' if fields.empty(row_dict.get('Translate-port')) else '') + ' +++'

                try:
                    fields.check_nan_value(row_dict['Distribution'])
                    object['entry']['dynamic-destination-translation']['distribution'] = str(row_dict['Distribution'])
                except Exception as e:
                    if e:
                        check_mandatory_value['status'] = False
                        check_mandatory_value['msg'] += ' Distribution Input Error' + (' (required for dynamic)' if fields.empty(row_dict.get('Distribution')) else '') + ' +++'

            elif str(row_dict['Destination-translation-type']) == 'none':
                pass
            else:
                raise ValueError('invalid Destination-translation-type')

        except Exception as e:
            if e:
                check_mandatory_value['status'] = False
                check_mandatory_value['msg'] += 'Destination-translation-type Input Error +++' 

        return object['entry']

    #source part
    def nat_src_translation(self, row_dict, check_mandatory_value):
        object = {'entry': {}}
        #--- Source-translation: none = no source NAT
        src_type = row_dict.get('Source-translation-type')
        if fields.empty(src_type) or str(src_type) not in self.SOURCE_TRANSLATION_TYPES:     # any case: normalized by check_row
            check_mandatory_value['status'] = False
            check_mandatory_value['msg'] += 'Source-translation-type Input Error +++'
            src_type = None
        else:
            src_type = str(src_type)

        #column required by the source translation type
        def src_required(col):
            value = row_dict.get(col)
            if fields.empty(value) or str(value).strip() == '':
                check_mandatory_value['status'] = False
                check_mandatory_value['msg'] += f' {col} Input Error (required for {src_type}) +++'
                return None
            return str(value).strip()

        if src_type in ('dynamic-ip-and-port with Translate address', 'dynamic-ip'):
            address = src_required('Src-translate-address')
            if address:
                kind = 'dynamic-ip-and-port' if src_type.startswith('dynamic-ip-and-port') else 'dynamic-ip'
                object['entry']['source-translation'] = {kind: {'translated-address': {'member': [m.strip() for m in address.split(',')]}}}

        elif src_type in ('dynamic-ip-and-port with Interface address IP', 'dynamic-ip-and-port with Interface address Floating IP'):
            interface = src_required('Src-translate-interface')
            ip = src_required('Src-translate-address-ip')          # 'no' = interface address without ip
            if interface and ip:
                interface_address = {'interface': interface}
                if ip != 'no':
                    interface_address['floating-ip' if src_type.endswith('Floating IP') else 'ip'] = ip
                object['entry']['source-translation'] = {'dynamic-ip-and-port': {'interface-address': interface_address}}

        elif src_type == 'static-ip':
            address = src_required('Src-translate-address')
            bi_directional = src_required('static-bi-directional')
            if address and bi_directional:
                object['entry']['source-translation'] = {'static-ip': {'translated-address': address, 'bi-directional': bi_directional}}

        return object['entry']

    ENTRY_READ_ONLY = ('@location', '@vsys', '@uuid', '@loc', '@device-group')    # read-only attributes of a GET answer, not sent back

    # --- edit sheets: column to path in the REST entry, lists end with 'member'
    #whole entry is sent back with PUT, attributes without a column are kept
    EDIT_FIELDS = {
        'tag': {'Color': ('color',), 'Comments': ('comments',)},
        'address': {'Description': ('description',), 'Tag': ('tag', 'member')},          # Type / Value: see edit_sheet
        'address_group': {'Member': ('static', 'member'), 'Description': ('description',), 'Tag': ('tag', 'member')},
        'service': {'Description': ('description',), 'Tag': ('tag', 'member')},          # protocol: see edit_sheet
        'service_group': {'Member': ('members', 'member'), 'Tag': ('tag', 'member')},
        'security_rule': {'Source-zone': ('from', 'member'), 'Destination-zone': ('to', 'member'),
                          'Source-ip': ('source', 'member'), 'Destination-ip': ('destination', 'member'),
                          'Application': ('application', 'member'), 'Service': ('service', 'member'),
                          'Url-category': ('category', 'member'), 'Source-user': ('source-user', 'member'),
                          'Tag': ('tag', 'member'), 'Action': ('action',), 'Disable': ('disabled',),
                          'Description': ('description',), 'Profile-group': ('profile-setting', 'group', 'member'),
                          'Log-forwarding': ('log-setting',), 'Log-start': ('log-start',), 'Log-end': ('log-end',)},
        'nat_rule': {'Source-zone': ('from', 'member'), 'Destination-zone': ('to', 'member'),
                     'Source-ip': ('source', 'member'), 'Destination-ip': ('destination', 'member'), 'Service': ('service',),
                     'Destination-interface': ('to-interface',), 'Nat-type': ('nat-type',), 'Disable': ('disabled',),
                     'Active-active-device-binding': ('active-active-device-binding',), 'Description': ('description',),
                     'Tag': ('tag', 'member'), 'Group-tag': ('group-tag',)},
    }
    # empty on the firewall = any
    ANY_LISTS = ('Source-zone', 'Destination-zone', 'Source-ip', 'Destination-ip', 'Application', 'Service', 'Url-category', 'Source-user')
    CLEARABLE = ('Description', 'Comments', 'Color', 'Tag', 'Profile-group', 'Log-forwarding', 'Group-tag', 'Source-port',
                 'Timeout', 'Halfclose-timeout', 'Timewait-timeout')
    CREATE_KINDS = {
        'tag': ('build_tag', 'get_Objects_Tags', 'create_Objects_Tag', 'duplicate_tag', 'Tag Name', 'tag', None),
        'address': ('build_address', 'get_Objects_Addresses', 'create_Objects_Addresses', 'duplicate_address', 'Address Object Name', 'address', None),
        'address_group': ('build_address_group', 'get_Objects_AddressGroups', 'create_Objects_AddressGroups_static', 'duplicate_address_group',
                          'Address Group Name', 'address_group', None),
        'service': ('build_service', 'get_Objects_Services', 'create_Objects_Services', 'duplicate_service', 'Service Object Name', 'service', None),
        'service_group': ('build_service_group', 'get_Objects_ServiceGroups', 'create_Objects_ServiceGroups', 'duplicate_service_group',
                          'Service Group Name', 'service_group', None),
        'security_rule': ('build_security_rule', 'get_security_rule', 'create_security_rule', 'duplicate_security_rule',
                          'Security Rule Name', 'create_policy', 'move_security_rule'),
        'nat_rule': ('build_nat_rule', 'get_nat_rule', 'create_nat_rule', 'duplicate_nat_rule', 'Nat Rule Name', 'create_nat', 'move_nat_rule'),
    }
    EDIT_KINDS = {
        'tag': ('get_Objects_Tags', 'edit_Objects_Tag', 'Tag Name', 'tag'),
        'address': ('get_Objects_Addresses', 'edit_Objects_Addresses', 'Address Object Name', 'address'),
        'address_group': ('get_Objects_AddressGroups', 'edit_Objects_AddressGroups', 'Address Group Name', 'address_group'),
        'service': ('get_Objects_Services', 'edit_Objects_Services', 'Service Object Name', 'service'),
        'service_group': ('get_Objects_ServiceGroups', 'edit_Objects_ServiceGroups', 'Service Group Name', 'service_group'),
        'security_rule': ('get_security_rule', 'edit_security_rule', 'Security Rule Name', 'edit_policy'),
        'nat_rule': ('get_nat_rule', 'edit_nat_rule', 'Nat Rule Name', 'edit_nat'),
    }

    #tag: same name, vsys or shared
    def duplicate_tag(self, list_tags, object):
        name = object['entry'].get('@name')
        return next(('Duplicate Name with ' + t['@name'] for t in list_tags if name and t['@name'] == name), 'No Duplicate')

    # --- duplicate checks against entries read on the firewall
    #security rule: same name, or every list included in an existing rule
    def duplicate_security_rule(self, list_rules, object):
        e = object['entry']
        for rule in list_rules:
            if e['@name'] == rule['@name']:
                return 'Duplicate Name with ' + rule['@name']
            if all(fields.is_subset(e[key]['member'], rule[key]['member']) for key in ('from', 'to', 'source', 'destination', 'application', 'service')) \
                    and e['action'] == rule['action']:
                return 'Duplicate Value with ' + rule['@name']
        return 'No Duplicate'

    #NAT rule: same name, or zones and addresses included, same service
    def duplicate_nat_rule(self, list_rules, object):
        e = object['entry']
        for rule in list_rules:
            if e['@name'] == rule['@name']:
                return 'Duplicate Name with ' + rule['@name']
            if all(fields.is_subset(e[key]['member'], rule[key]['member']) for key in ('from', 'to', 'source', 'destination')) \
                    and e['service'] == rule['service']:
                return 'Duplicate Value with ' + rule['@name']
        return 'No Duplicate'

    #fqdn compared case-insensitive, final dot ignored
    def address_compare_value(self, kind, value):
        value = str(value).strip()
        return value.lower().rstrip('.') if kind == 'fqdn' else value

    #address object: same name or same type + value
    def duplicate_address(self, list_addresses, object):
        name = object['entry'].get('@name')
        for address in list_addresses:
            if name and address['@name'] == name:
                return 'Duplicate Name with ' + address['@name']
        kind = next((t for t in self.ADDRESS_TYPES if t in object['entry']), None)
        if kind:
            value = self.address_compare_value(kind, object['entry'][kind])
            for address in list_addresses:
                if kind in address and self.address_compare_value(kind, address[kind]) == value:
                    return 'Duplicate Value with ' + address['@name']
        return 'No Duplicate'

    #firewall refuses an existing name: no CAN CREATE in dry-run
    def duplicate_name_refused(self, dup_rs):
        return str(dup_rs).lower().startswith('duplicate name') or str(dup_rs).startswith('Same Name as ')

    #name already used text
    def name_exists_text(self, kind, dup_rs, name):
        text = str(dup_rs)
        for other, (_, _, what) in self.NAME_SPACES.items():
            if text.endswith(f'({what})'):
                return f"{what} '{name}' already exists (an {self.KIND_TEXT[kind]} cannot have the same name)".replace('an service', 'a service')
        if text.endswith('(predefined)'):
            return f"{self.KIND_TEXT[kind]} '{name}' already exists (predefined tag of the firewall)"
        if text.startswith('Same Name as '):
            return f"{self.KIND_TEXT[kind]} '{name}' already exists in shared (a vsys object with the name of a shared object is refused by the tool)"
        return f"{self.KIND_TEXT[kind]} '{name}' already exists" + (' (shared)' if text.endswith('(shared)') else '')

    #group members as a set
    def member_set(self, container):
        members = (container or {}).get('member', [])
        return set([members] if isinstance(members, str) else members)

    #address group: same name or same members
    def duplicate_address_group(self, list_group, object):
        name = object['entry']['@name']
        for group in list_group:
            if group['@name'] == name:
                return 'Duplicate Name with ' + group['@name']
        if 'static' in object['entry']:
            members = self.member_set(object['entry']['static'])
            for group in list_group:
                if 'static' in group and self.member_set(group['static']) == members:
                    return 'Duplicate Value with ' + group['@name']
        return 'No Duplicate'

    #service object: same name or same protocol part
    def duplicate_service(self, list_services, object):
        def value(protocol):                         # port lists compared as sets
            out = {}
            for proto, sub in (protocol or {}).items():
                sub = sub or {}
                out[proto] = {k: (frozenset(p.strip() for p in str(v).split(',')) if k in ('port', 'source-port') else str(v))
                              for k, v in sub.items()}
            return out
        new = value(object['entry'].get('protocol'))
        for service in list_services:
            if object['entry']['@name'] == service['@name']:
                return 'Duplicate Name with ' + service['@name']
            if new == value(service.get('protocol')):
                return 'Duplicate Value with ' + service['@name']
        return 'No Duplicate'

    #service group: same name or same members
    def duplicate_service_group(self, list_group, object):
        name = object['entry']['@name']
        for group in list_group:
            if group['@name'] == name:
                return 'Duplicate Name with ' + group['@name']
        members = self.member_set(object['entry'].get('members'))
        for group in list_group:
            if self.member_set(group.get('members')) == members:
                return 'Duplicate Value with ' + group['@name']
        return 'No Duplicate'

    # --- field checks built from the rule attributes above
    #name of an object / rule, '' = valid
    def name_error(self, value):
        text = str(value)
        if len(text) > self.NAME_MAX:
            return f'max {self.NAME_MAX} characters, has {len(text)}'
        #firewall refuses names starting with . - _ and the name any
        if text.lower() == self.ANY:
            return "'any' is reserved by the firewall (any case)"
        if text[:1] in ('.', '-', '_'):
            return 'must begin with a letter or a digit'
        bad = fields.bad_chars(text, self.NAME_CHARS)
        return f'only {self.NAME_CHARS_TEXT} ; not allowed: {bad}' if bad else ''

    #columns of a sheet kind
    def field_columns(self, kind):
        yes_no = fields.one_of(*self.YES_NO)
        tags = (fields.list_of(self.TAG_MAX, self.TAGS_MAX, 'tag'), False, True)
        objects = {'Description': (fields.bytes_max(self.DESCRIPTION_MAX_OBJECT), False, True), 'Tag': tags}
        rules = {'Description': (fields.bytes_max(self.DESCRIPTION_MAX_RULE), False, True), 'Tag': tags,
                 'Source-zone': (fields.list_of(self.ZONE_MAX, what='zone'), False, False),
                 'Destination-zone': (fields.list_of(self.ZONE_MAX, what='zone'), False, False)}
        member = (fields.list_of(self.NAME_MAX), False, False)
        def protocol(value):
            if value == 'icmp':
                return 'tcp / udp: for ICMP use Application icmp / ping in the rule'
            if value == 'sctp':
                return 'SCTP is not supported by the tool'
            return '' if value in ('tcp', 'udp') else 'tcp / udp'
        def nat_type(value):
            if value in self.NAT_TYPES_REFUSED:
                return f'{value} is not supported by the tool (ipv4 only)'
            return '' if value in self.NAT_TYPES else 'ipv4'
        def color(value):
            return '' if value.strip().lower() in self.TAG_COLORS else 'color name of the web UI, e.g. Red, Green, Light Green'
        return {
            'tag': {'Color': (color, False, False), 'Comments': (fields.bytes_max(self.TAG_COMMENTS_MAX), False, False)},
            'address': dict(objects, **{'Type': (fields.one_of(*self.ADDRESS_TYPES), True, False)}),
            'address_group': dict(objects, **{'Member': member}),
            'service': dict(objects, **{'Protocol': (protocol, True, False), 'Destination-port': (fields.ports(self.PORT_MAX), False, False),
                                        'Source-port': (fields.ports(self.PORT_MAX), False, True), 'Override': (yes_no, True, True)}),
            'service_group': {'Tag': tags, 'Member': member},
            'security_rule': dict(rules, **{
                'Action': (fields.one_of(*self.ACTIONS), True, False),
                'Disable': (yes_no, True, True), 'Log-start': (yes_no, True, True), 'Log-end': (yes_no, True, True),
                'Log-forwarding': (fields.text_max(self.LOG_FORWARDING_MAX), False, True),
                'Profile-group': (fields.list_of(self.PROFILE_GROUP_MAX, what='profile group'), False, True),
                'Url-category': (fields.list_of(self.URL_CATEGORY_MAX, what='URL category'), False, True)}),
            'nat_rule': dict(rules, **{
                'Service': (fields.single, False, False), 'Group-tag': (fields.text_max(self.TAG_MAX), False, True),
                'Nat-type': (nat_type, True, False), 'Disable': (yes_no, True, False),
                'Active-active-device-binding': (fields.one_of(*self.HA_BINDINGS), True, True),
                'Destination-translation-type': (fields.one_of(*self.DESTINATION_TRANSLATION_TYPES), True, False),
                'Src-translate-interface': (fields.text_max(self.INTERFACE_MAX), False, False)}),
        }.get(kind, {})

    #columns that depend on another column
    def field_conditional(self, kind, row, edit=False):
        found = {}
        if kind == 'address' and row.get('Type') in self.ADDRESS_TYPES and not fields.empty(row.get('Value')):
            found['Value'] = (fields.address_value(row['Type'], self.FQDN, self.FQDN_MAX), False, False)
        if kind == 'service' and (row.get('Override') == 'yes' or edit):     # edit: Override may be the current value
            found['Timeout'] = (fields.integer(1, self.TIMEOUT_MAX), False, True)
            if str(row.get('Protocol', '')).lower() == 'tcp' or edit:
                found['Halfclose-timeout'] = (fields.integer(1, self.TIMEOUT_MAX), False, True)
                found['Timewait-timeout'] = (fields.integer(1, self.TIMEWAIT_MAX), False, True)
        if kind == 'nat_rule':
            dst = row.get('Destination-translation-type')
            if dst in ('static', 'dynamic'):
                found['Translate-port'] = (fields.integer_or('all', 1, self.TRANSLATE_PORT_MAX), True, False)
            if dst == 'static':
                found['Dns-rewrite'] = (fields.one_of(*self.DNS_REWRITE), True, False)
            if dst == 'dynamic':
                found['Distribution'] = (fields.one_of(*self.DISTRIBUTIONS), True, False)
            if row.get('Source-translation-type') == 'static-ip':
                found['static-bi-directional'] = (fields.one_of(*self.YES_NO), True, False)
            if str(row.get('Source-translation-type', '')).startswith('dynamic-ip-and-port with Interface address'):
                found['Src-translate-address-ip'] = (fields.interface_ip, False, False)
        return found

    #Vsys column: vsysN or shared, any case
    def vsys_value(self, value):
        if fields.empty(value) or str(value).strip() == '':
            return None, 'required: vsys1, vsys2, ... or shared'
        text = str(value).strip().lower()
        if text == self.SHARED_NAME or self.VSYS_NAME.fullmatch(text):
            return text, ''
        return None, 'must be vsysN (vsys1, vsys2, ...) or shared'

    #clean the row in place, return broken rules
    def check_row(self, kind, row, edit=False):
        lists = set(self.LIST_COLUMNS) - ({'Service'} if kind == 'nat_rule' else set())
        if kind == 'service':
            lists |= {'Destination-port', 'Source-port'}
        if not fields.empty(row.get('Source-translation-type')):          # normalize choice case
            typed = str(row['Source-translation-type']).strip().lower()
            row['Source-translation-type'] = next((t for t in self.SOURCE_TRANSLATION_TYPES if t.lower() == typed), row['Source-translation-type'])
        any_words = {c: (self.ANY,) for c in self.ANY_COLUMNS}
        errors = fields.check_columns(row, self.field_columns(kind), lists, any_words, lambda r: self.field_conditional(kind, r, edit))
        if 'Vsys' in row:
            scope, reason = self.vsys_value(row['Vsys'])
            if reason:
                errors.append(('Vsys', reason))
            else:
                row['Vsys'] = scope
        return errors + [e for e in self.row_rules(kind, row, edit) if e[0] not in {c for c, _ in errors}]

    #rules between values of a row
    def row_rules(self, kind, row, edit=False):
        errors = []
        def parts(col):
            return [] if fields.empty(row.get(col)) else str(row[col]).split(',')
        if kind in ('security_rule', 'nat_rule'):
            for col in self.ANY_COLUMNS:
                if col == 'Service' and kind == 'security_rule':
                    values = parts(col)
                    alone = [v for v in values if v in self.SERVICE_ALONE]
                    if alone and len(values) > 1:
                        errors.append((col, "'any' / 'application-default' must be alone"))
                    continue
                values = parts(col)
                if self.ANY in values and len(values) > 1:
                    errors.append((col, "'any' must be alone"))
            users = parts('Source-user')
            keyword = next((u for u in users if u in self.SOURCE_USER_KEYWORDS), None)
            if keyword and len(users) > 1:
                errors.append(('Source-user', f"'{keyword}' must be alone"))
            if len(parts('Profile-group')) > 1:
                errors.append(('Profile-group', 'one value only'))
        if kind == 'nat_rule':
            if len(parts('Destination-zone')) > 1:
                errors.append(('Destination-zone', 'one value only'))
            elif parts('Destination-zone') == [self.ANY]:       # firewall refuses zone any in NAT
                errors.append(('Destination-zone', 'any is not valid in a NAT rule: ONE zone'))
            if row.get('Service') == 'application-default':
                errors.append(('Service', 'application-default is not valid in a NAT rule: any or ONE service'))
            for type_col, used in (('Destination-translation-type', self.NAT_DST_COLUMNS), ('Source-translation-type', self.NAT_SRC_COLUMNS)):
                chosen = row.get(type_col)
                if fields.empty(chosen) or chosen not in used:
                    continue
                others = {c for cols in used.values() for c in cols} - set(used[chosen])
                for c in sorted(others):
                    if not fields.empty(row.get(c)):
                        errors.append((c, f'not used with {chosen}'))
        if kind in ('address_group', 'service_group') and not fields.empty(row.get('Name')) and str(row['Name']) in parts('Member'):
            errors.append(('Member', 'the group itself: a group cannot contain itself'))     # firewall refuses it
        if kind == 'service' and not edit:      # edit: checked in edit_sheet with current values
            override = str(row.get('Override', '')).lower() == 'yes'
            for c in ('Timeout', 'Halfclose-timeout', 'Timewait-timeout'):     # udp first: one fix for the admin
                if c != 'Timeout' and not fields.empty(row.get(c)) and str(row.get('Protocol', '')).lower() == 'udp':
                    errors.append((c, 'only for tcp'))
                elif not fields.empty(row.get(c)) and not override:
                    errors.append((c, 'only with Override yes'))
        if kind == 'address' and row.get('Type') in ('ip-netmask', 'ip-range') and not fields.empty(row.get('Value')):
            if self.covers_all(row['Type'], str(row['Value'])):
                errors.append(('Value', "covers all addresses: use 'any'"))
        return errors

    #address value covering every IPv4 / IPv6 address
    def covers_all(self, kind, value):
        try:
            if kind == 'ip-netmask':
                return ipaddress.ip_network(value, strict=False) in self.ALL_ADDRESSES
            first, last = [ipaddress.ip_address(p.strip()) for p in value.split('-')]
            net = next(n for n in self.ALL_ADDRESSES if n.version == first.version)
            return first == net[0] and last == net[-1]
        except (ValueError, StopIteration):
            return False

    # --- location of REST calls, sent as query parameters
    DEFAULT_VSYS = 'vsys1'

    def default_location(self):
        return {'location': 'vsys', '@vsys': self.DEFAULT_VSYS}

    def vsys_location(self, vsys):
        return {'location': 'vsys', '@vsys': vsys}

    #shared scope, object sheets only: firewall refuses location=shared for rules
    SHARED_NAME = 'shared'

    def shared_location(self):
        return {'location': 'shared', '@vsys': self.SHARED_NAME}

    def location_params(self, location_object):
        return common.location_params(location_object)

    # --- answers: REST JSON, XML API, commit / validate
    def json_or_error(self, response):
        return common.json_or_error(response)

    def xml_response(self, response):
        return common.xml_response(response)

    def xml_api_msg(self, rs):
        return common.xml_api_msg(rs)

    #commit / validate answer: job id and message
    #no job: firewall message shown as SKIPPED
    def job_or_message(self, rs, what):
        if rs.get('@status') != 'success':
            raise FirewallError(self.xml_api_msg(rs))
        result = rs.get('result') or {}
        job = result.get('job') if isinstance(result, dict) else None
        if job:
            return job, self.xml_api_msg(result)
        if not (rs.get('msg') or (isinstance(result, dict) and result.get('msg'))):
            raise FirewallError(f'no {what} job returned by the firewall: {self.xml_api_msg(rs)}')
        return None, self.xml_api_msg(result if isinstance(result, dict) and result else rs)

    # --- URLs / transport

    #REST version is always the PAN-OS version, never guessed
    def rest_base(self):
        parts = (self.sw_version or '').split('.')
        if len(parts) < 2 or not parts[0].isdigit() or not parts[1].split('-')[0].isdigit():
            raise FirewallError(f'PAN-OS version of {self.host} unknown (not read after keygen)')
        return f'https://{self.host}/restapi/v{parts[0]}.{parts[1].split("-")[0]}'

    def rest_get(self, path, location_object):
        return self.session.get(self.rest_base() + path, params=self.location_params(location_object),
                                headers={'X-PAN-KEY': self.token}, timeout=API_TIMEOUT)

    #POST / PUT / DELETE of one named entry
    def rest_write(self, method, path, object, location_object):
        params = dict(self.location_params(location_object), name=object['entry']['@name'])
        body = json.dumps(object) if method != 'DELETE' else None
        response = self.session.request(method, self.rest_base() + path, params=params, headers={'X-PAN-KEY': self.token},
                                        data=body, timeout=API_TIMEOUT)
        return self.json_or_error(response)

    def rest_move(self, path, location_object):
        params = dict(self.location_params(location_object), **{k: v for k, v in location_object.items() if k in ('name', 'where', 'dst')})
        response = self.session.post(self.rest_base() + path, params=params, headers={'X-PAN-KEY': self.token}, timeout=API_TIMEOUT)
        return self.json_or_error(response)

    # XML API op command, key in the POST body not the URL
    def xml_api_op(self, cmd, type='op', vsys=None):
        data = {'type': type, 'cmd': cmd, 'key': self.token}
        if vsys:
            data['vsys'] = vsys
        response = self.session.post(f'https://{self.host}/api/', data=data, timeout=API_TIMEOUT)
        return self.xml_response(response)

    # --- security rules
    def get_security_rule(self, location_object):
        return self.rest_get('/Policies/SecurityRules', location_object)

    def check_security_rule_exist(self, object, location_object):
        try:
            names = [i['@name'] for i in self.get_security_rule(location_object).json()['result']['entry']]
        except Exception:
            names = []
        return object in names

    def create_security_rule(self, object, location_object):
        return self.rest_write('POST', '/Policies/SecurityRules', object, location_object)

    def edit_security_rule(self, object, location_object):
        return self.rest_write('PUT', '/Policies/SecurityRules', object, location_object)

    def move_security_rule(self, location_object):
        return self.rest_move('/Policies/SecurityRules:move', location_object)

    # --- objects
    def get_Objects_Addresses(self, location_object):
        return self.rest_get('/Objects/Addresses', location_object)

    def check_Objects_Addresses_exist(self, object, location_object):
        return object in [i['@name'] for i in self.get_Objects_Addresses(location_object).json()['result']['entry']]

    def create_Objects_Addresses(self, object, location_object):
        return self.rest_write('POST', '/Objects/Addresses', object, location_object)

    def get_Objects_AddressGroups(self, location_object):
        return self.rest_get('/Objects/AddressGroups', location_object)

    def check_Objects_AddressGroups_exist(self, object, location_object):
        return object in [i['@name'] for i in self.get_Objects_AddressGroups(location_object).json()['result']['entry']]

    def create_Objects_AddressGroups_static(self, object, location_object):
        return self.rest_write('POST', '/Objects/AddressGroups', object, location_object)

    def get_Objects_Services(self, location_object):
        return self.rest_get('/Objects/Services', location_object)

    def check_Objects_Services_exist(self, object, location_object):
        return object in [i['@name'] for i in self.get_Objects_Services(location_object).json()['result']['entry']]

    def create_Objects_Services(self, object, location_object):
        return self.rest_write('POST', '/Objects/Services', object, location_object)

    def get_Objects_ServiceGroups(self, location_object):
        return self.rest_get('/Objects/ServiceGroups', location_object)

    def check_Objects_ServiceGroups_exist(self, object, location_object):
        return object in [i['@name'] for i in self.get_Objects_ServiceGroups(location_object).json()['result']['entry']]

    def create_Objects_ServiceGroups(self, object, location_object):
        return self.rest_write('POST', '/Objects/ServiceGroups', object, location_object)

    def create_Objects_Tag(self, object, location_object):
        return self.rest_write('POST', '/Objects/Tags', object, location_object)

    # --- edit of objects / groups / tags: PUT of the whole entry
    def edit_Objects_Tag(self, object, location_object):
        return self.rest_write('PUT', '/Objects/Tags', object, location_object)

    def edit_Objects_Addresses(self, object, location_object):
        return self.rest_write('PUT', '/Objects/Addresses', object, location_object)

    def edit_Objects_AddressGroups(self, object, location_object):
        return self.rest_write('PUT', '/Objects/AddressGroups', object, location_object)

    def edit_Objects_Services(self, object, location_object):
        return self.rest_write('PUT', '/Objects/Services', object, location_object)

    def edit_Objects_ServiceGroups(self, object, location_object):
        return self.rest_write('PUT', '/Objects/ServiceGroups', object, location_object)

    # --- objects referenced by rules, read only
    def get_Zones(self, location_object):
        return self.rest_get('/Network/Zones', location_object)

    def get_Objects_Tags(self, location_object):
        return self.rest_get('/Objects/Tags', location_object)

    def get_Objects_SecurityProfileGroups(self, location_object):
        return self.rest_get('/Objects/SecurityProfileGroups', location_object)

    def get_Objects_LogForwardingProfiles(self, location_object):
        return self.rest_get('/Objects/LogForwardingProfiles', location_object)

    def get_Objects_CustomURLCategories(self, location_object):
        return self.rest_get('/Objects/CustomURLCategories', location_object)

    def get_Objects_ExternalDynamicLists(self, location_object):
        return self.rest_get('/Objects/ExternalDynamicLists', location_object)

    def get_Objects_Regions(self, location_object):
        return self.rest_get('/Objects/Regions', location_object)

    def get_Objects_Applications(self, location_object):
        return self.rest_get('/Objects/Applications', location_object)

    def get_Objects_ApplicationGroups(self, location_object):
        return self.rest_get('/Objects/ApplicationGroups', location_object)

    def get_Objects_ApplicationFilters(self, location_object):
        return self.rest_get('/Objects/ApplicationFilters', location_object)

    #vsys of the firewall, no location parameter at firewall level
    def get_VirtualSystems(self, location_object=None):
        return self.session.get(self.rest_base() + '/Device/VirtualSystems', headers={'X-PAN-KEY': self.token}, timeout=API_TIMEOUT)

    #names of a predefined list
    def predefined_names(self, kind):
        rs = self.xml_api_op(f'<show><predefined><xpath>/predefined/{kind}</xpath></predefined></show>')
        if rs.get('@status') != 'success':
            raise FirewallError(self.xml_api_msg(rs))
        entries = ((rs.get('result') or {}).get(kind) or {}).get('entry') or []
        return [e['@name'] for e in (entries if isinstance(entries, list) else [entries]) if isinstance(e, dict) and '@name' in e]

    #predefined application of this name, asked one at a time: 11 000+ apps
    PREDEFINED_APPLICATION_KINDS = ('application', 'application-container')

    def predefined_application_exists(self, name):
        if "'" in name:
            return False
        for kind in self.PREDEFINED_APPLICATION_KINDS:
            rs = self.xml_api_op(f"<show><predefined><xpath>/predefined/{kind}/entry[@name='{escape(name)}']</xpath></predefined></show>")
            if rs.get('@status') == 'success':
                return True
            if 'No data found' not in self.xml_api_msg(rs):
                raise FirewallError(self.xml_api_msg(rs))
        return False

    # --- NAT rules
    def get_nat_rule(self, location_object):
        return self.rest_get('/Policies/NatRules', location_object)

    def check_nat_rule_exist(self, object, location_object):
        try:
            names = [i['@name'] for i in self.get_nat_rule(location_object).json()['result']['entry']]
        except Exception:
            names = []
        return object in names

    def create_nat_rule(self, object, location_object):
        return self.rest_write('POST', '/Policies/NatRules', object, location_object)

    def edit_nat_rule(self, object, location_object):
        return self.rest_write('PUT', '/Policies/NatRules', object, location_object)

    def move_nat_rule(self, location_object):
        return self.rest_move('/Policies/NatRules:move', location_object)

    # --- XML API: backup, config lock, commit

    # save candidate config to a named snapshot
    def backup_config(self):
        snap_shot_name = f'Auto-{datetime.now().strftime("%Y-%m-%d-%H%M%S")}.xml'
        try:
            rs = self.xml_api_op('<save><config><to>' + snap_shot_name + '</to></config></save>')
        except FirewallError as e:
            return False, str(e)
        if rs.get('@status') == 'success':
            return True, f'{snap_shot_name}: {self.xml_api_msg(rs)}'
        return False, self.xml_api_msg(rs) or str(rs)

    # config lock of 1 vsys
    #shared lock does not see vsys locks of other admins
    #one admin cannot hold shared + vsys locks at once
    def add_config_lock(self, comment, vsys=None):
        rs = self.xml_api_op('<request><config-lock><add><comment>' + escape(comment) + '</comment></add></config-lock></request>', vsys=vsys)
        return rs.get('@status') == 'success', self.xml_api_msg(rs)

    def remove_config_lock(self, vsys=None):
        rs = self.xml_api_op('<request><config-lock><remove></remove></config-lock></request>', vsys=vsys)
        return rs.get('@status') == 'success', self.xml_api_msg(rs)

    # pending changes in candidate config: yes / no
    def check_pending_changes(self):
        rs = self.xml_api_op('<check><pending-changes></pending-changes></check>')
        if rs.get('@status') != 'success':
            raise FirewallError(self.xml_api_msg(rs))
        return str(rs.get('result', '')).strip()

    # start commit, admin = partial commit, None = full
    def start_commit(self, description, admin=None):
        cmd = '<commit>'
        if admin:
            cmd += '<partial><admin><member>' + escape(admin) + '</member></admin></partial>'
        if description:
            cmd += '<description>' + escape(description) + '</description>'
        cmd += '</commit>'
        return self.job_or_message(self.xml_api_op(cmd, type='commit'), 'commit')

    # status of a firewall job
    #show jobs sends the job description unescaped, answer may not be XML
    #not used by the tool, cut before parsing
    JOB_DESCRIPTION = re.compile(r'<description>.*</description>', re.S)

    #job status, warnings kept as the firewall sends them
    def get_job_status(self, job_id):
        cmd = '<show><jobs><id>' + escape(str(job_id)) + '</id></jobs></show>'
        response = self.session.post(f'https://{self.host}/api/', data={'type': 'op', 'cmd': cmd, 'key': self.token}, timeout=API_TIMEOUT)
        text = response.text
        try:
            rs = self.xml_response(response)
        except FirewallError:
            text = self.JOB_DESCRIPTION.sub('<description></description>', response.text)
            rs = self.xml_response(type('Answer', (), {'text': text, 'status_code': response.status_code}))
        if rs.get('@status') != 'success':
            raise FirewallError(self.xml_api_msg(rs))
        job = rs['result']['job']
        def lines(key):
            value = job.get(key) or {}
            value = value.get('line', '') if isinstance(value, dict) else value
            return ' | '.join(str(l) for l in value) if isinstance(value, list) else str(value or '')
        #xmltodict strips the indent, read <warnings> from the raw answer
        warnings = ET.fromstring(text).findall('.//job/warnings/line')
        return {'status': job.get('status'), 'result': job.get('result'), 'progress': job.get('progress'),
                'details': lines('details'), 'warnings': '\n'.join((w.text or '').rstrip() for w in warnings)}

    # start commit check, validate only
    def start_validate(self, admin=None):
        if admin:
            cmd = '<validate><partial><admin><member>' + escape(admin) + '</member></admin></partial></validate>'
        else:
            cmd = '<validate><full></full></validate>'
        return self.job_or_message(self.xml_api_op(cmd), 'validate')
