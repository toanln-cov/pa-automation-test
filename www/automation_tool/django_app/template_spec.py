# Import template columns, single source for make_template.py and file_check.py
# edit rule / group sheets: every editable column X has an 'Edit-X-mode' column
REQ, COND, OPT = 'required', 'conditional', 'optional'     # header colour: red / yellow / green
LIST, SINGLE = 'list', 'single'                             # edit kind, None = not editable

MODES = {LIST: ('add', 'remove', 'replace', 'remain'), SINGLE: ('replace', 'remain')}
COLORS = {REQ: 'F8CBAD', COND: 'FFE699', OPT: 'C6E0B4'}

YES_NO = 'yes,no'
VSYS_HINT = 'vsys1, vsys2, ... or shared (any case)'
VSYS_RULE_HINT = 'vsys1, vsys2, ... (any case; a rule is never in shared)'
EDIT_KEEP = 'Empty = current value kept.'


def mode_name(column):
    return f'Edit-{column}-mode'


def col(name, level, hint, choices=None, edit=None, width=24):
    return {'name': name, 'level': level, 'hint': hint, 'choices': choices, 'edit': edit, 'width': width}


DEVICE = col('Device-ip', REQ, 'EXAMPLE ROW - replace or delete before upload. Firewall IPv4, e.g. 10.0.0.1')
POSITION = col('Position', OPT, 'top, bottom, before, after. Empty = bottom', 'top,bottom,before,after')
POSITION_EDIT = col('Position', OPT, 'top, bottom, before, after. Empty = not moved', 'top,bottom,before,after')
REFERENCE = col('Reference-rule', OPT, 'EXISTING rule on the firewall, with before / after, e.g. Allow-DNS')


def vsys(rule=False):
    return col('Vsys', REQ, VSYS_RULE_HINT if rule else VSYS_HINT)


TAG_COLOR_HINT = 'Color name as in the firewall web UI, e.g. Red, Green, Light Green (empty = no color)'

ADD_SHEETS = [
    ('add_tag', [
        DEVICE,
        col('Name', REQ, 'New tag name, max 127 characters. A predefined tag of the firewall (Sanctioned) cannot be created'),
        col('Color', OPT, TAG_COLOR_HINT),
        col('Comments', OPT, 'Free text, max 1023 bytes (a letter with accents counts 2-3)'),
        vsys()]),
    ('add_address_object', [
        DEVICE,
        col('Name', REQ, 'Address name, max 63 chars (letters, digits, space, . _ -; begins with a letter or a digit; not any), e.g. WEB_SRV_01'),
        col('Type', REQ, 'ip-netmask | ip-range | ip-wildcard | fqdn', 'ip-netmask,ip-range,ip-wildcard,fqdn'),
        col('Value', REQ, "e.g. 192.0.2.1 or 192.0.2.0/24 (ip-netmask), 192.0.2.1-192.0.2.9 (ip-range), www.example.com (fqdn). "
                          "Not every address (0.0.0.0/0, ::/0): use the firewall's any"),
        col('Description', OPT, 'Free text, max 1023 bytes (a letter with accents counts 2-3)'),
        col('Tag', OPT, 'Existing tag(s), e.g. tag1,tag2'),
        vsys()]),
    ('add_address_group', [
        DEVICE,
        col('Name', REQ, 'Static address group name, max 63 chars (letters, digits, space, . _ -; begins with a letter or a digit; not any)'),
        col('Member', REQ, 'Address objects (ip-netmask / ip-range / fqdn) or address groups, e.g. WEB_SRV_01,WEB_SRV_02. '
                           'Not: EDL, region, ip-wildcard address, any, bare IP', width=38),
        col('Description', OPT, 'Free text, max 1023 bytes (a letter with accents counts 2-3)'),
        col('Tag', OPT, 'Existing tag(s), e.g. tag1,tag2'),
        vsys()]),
    ('add_service_object', [
        DEVICE,
        col('Name', REQ, 'Service name, max 63 chars (letters, digits, space, . _ -; begins with a letter or a digit; not any), e.g. TCP_8443'),
        col('Protocol', REQ, 'tcp | udp. ICMP: use the application icmp / ping in the rule. SCTP not supported', 'tcp,udp'),
        col('Source-port', OPT, 'e.g. 1024-65535 (empty = any)'),
        col('Destination-port', REQ, 'e.g. 443 or 80,443 or 1000-2000'),
        col('Override', OPT, 'yes = use the timeout columns, empty / no = default timeouts', YES_NO),
        col('Timeout', COND, 'Only with Override = yes: seconds 1-604800, e.g. 3600'),
        col('Halfclose-timeout', COND, 'Only with Override = yes and tcp: seconds 1-604800'),
        col('Timewait-timeout', COND, 'Only with Override = yes and tcp: seconds 1-600'),
        col('Description', OPT, 'Free text, max 1023 bytes (a letter with accents counts 2-3)'),
        col('Tag', OPT, 'Existing tag(s), e.g. tag1,tag2'),
        vsys()]),
    ('add_service_group', [
        DEVICE,
        col('Name', REQ, 'Service group name, max 63 chars (letters, digits, space, . _ -; begins with a letter or a digit; not any)'),
        col('Member', REQ, 'Services, service groups, service-http, service-https, e.g. TCP_8443,service-https. Not: any, application-default', width=44),
        col('Tag', OPT, 'Existing tag(s), e.g. tag1,tag2'),
        vsys()]),
    ('add_security_rule', [
        DEVICE, POSITION, REFERENCE,
        col('Name', REQ, 'New rule name, max 63 chars (letters, digits, space, . _ -; begins with a letter or a digit; not any)'),
        col('Source-zone', REQ, 'Zone(s) or any, e.g. trust'),
        col('Destination-zone', REQ, 'Zone(s) or any, e.g. untrust'),
        col('Source-ip', REQ, 'Address / group names, region code (e.g. VN), any alone, or a bare IP / CIDR / range (warning: not an object)'),
        col('Destination-ip', REQ, 'Address / group names, region code (e.g. VN), any alone, or a bare IP / CIDR / range (warning: not an object)'),
        col('Application', REQ, 'Application(s) or any alone, e.g. ssl,web-browsing'),
        col('Service', REQ, 'Service / group names, or application-default, or any (alone)'),
        col('Action', REQ, 'allow | deny | drop | reset-client | reset-server | reset-both', 'allow,deny,drop,reset-client,reset-server,reset-both'),
        col('Disable', OPT, 'yes | no (empty = no)', YES_NO),
        col('Description', OPT, 'Free text, max 1024 bytes (a letter with accents counts 2-3)'),
        col('Tag', OPT, 'Existing tag(s), e.g. tag1,tag2'),
        col('Profile-group', OPT, 'ONE security profile group name'),
        col('Log-forwarding', OPT, 'Log forwarding profile name'),
        col('Log-start', OPT, 'yes | no (empty = no)', YES_NO),
        col('Log-end', OPT, 'yes | no (empty = yes)', YES_NO),
        col('Url-category', OPT, 'URL category(ies), e.g. abused-drugs,gambling'),
        col('Source-user', OPT, 'User(s) / group(s), e.g. domain\\user1, or pre-logon / known-user / unknown / any (alone). Names not checked by the Dry-run'),
        vsys(rule=True)]),
    ('add_nat_rule', [
        DEVICE, POSITION, REFERENCE,
        col('Name', REQ, 'New NAT rule name, max 63 chars (letters, digits, space, . _ -; begins with a letter or a digit; not any)'),
        col('Source-zone', REQ, 'Zone(s) or any, e.g. trust'),
        col('Destination-zone', REQ, 'ONE zone, e.g. untrust (any is not valid in a NAT rule)'),
        col('Source-ip', REQ, 'Address / group names, region code (e.g. VN) or any. Not: ip-wildcard address'),
        col('Destination-ip', REQ, 'Address / group names, region code (e.g. VN) or any'),
        col('Service', REQ, 'ONE service / group name or any (not a list)'),
        col('Destination-interface', REQ, 'ONE interface or any, e.g. ethernet1/1. Not checked by the Dry-run'),
        col('Destination-translation-type', REQ, 'static | dynamic | none', 'static,dynamic,none'),
        col('Dns-rewrite', COND, 'Required with destination static: no | forward | reverse', 'no,forward,reverse'),
        col('Distribution', COND, 'Required with destination dynamic: round-robin | source-ip-hash | ip-modulo | ip-hash | least-sessions',
            'round-robin,source-ip-hash,ip-modulo,ip-hash,least-sessions'),
        col('Dst-translate-address', COND, 'Required with destination static / dynamic: ONE address name or IP'),
        col('Translate-port', COND, 'Required with destination static / dynamic: port 1-65535, or all (port unchanged)'),
        col('Source-translation-type', REQ, 'none | dynamic-ip-and-port with ... | dynamic-ip | static-ip',
            'none,dynamic-ip-and-port with Translate address,dynamic-ip-and-port with Interface address IP,'
            'dynamic-ip-and-port with Interface address Floating IP,dynamic-ip,static-ip'),
        col('static-bi-directional', COND, 'Required with source static-ip: yes | no', YES_NO),
        col('Src-translate-address', COND, 'Required with source Translate address / dynamic-ip (names or IPs, comma separated) or static-ip (ONE)'),
        col('Src-translate-interface', COND, 'Required with source Interface address IP / Floating IP: ONE interface, e.g. ethernet1/1'),
        col('Src-translate-address-ip', COND, 'Required with source Interface address IP / Floating IP: IP of the interface, or no'),
        col('Nat-type', REQ, 'ipv4 (nat64 / nptv6 not supported by the tool)', 'ipv4'),
        col('Disable', REQ, 'yes | no', YES_NO),
        col('Active-active-device-binding', OPT, 'primary | both | 0 | 1. Only used with HA active-active. Empty = primary', 'primary,both,0,1'),
        col('Description', OPT, 'Free text, max 1024 bytes (a letter with accents counts 2-3)'),
        col('Tag', OPT, 'Existing tag(s), e.g. tag1,tag2'),
        col('Group-tag', OPT, 'ONE existing tag'),
        vsys(rule=True)]),
]

KEY_NAME = 'Name of the EXISTING {what} to edit (no rename)'
CLEAR = 'none = clear.'

EDIT_SHEETS = [
    ('edit_tag', [
        DEVICE,
        col('Name', REQ, KEY_NAME.format(what='tag') + '. Predefined tags (Sanctioned) cannot be edited'),
        col('Color', OPT, f'{EDIT_KEEP} {TAG_COLOR_HINT}. {CLEAR}', edit=SINGLE),
        col('Comments', OPT, f'{EDIT_KEEP} Free text, max 1023 bytes. {CLEAR}', edit=SINGLE),
        vsys()]),
    ('edit_address_object', [
        DEVICE,
        col('Name', REQ, KEY_NAME.format(what='address object')),
        col('Type', OPT, f'{EDIT_KEEP} Type and Value always together: ip-netmask | ip-range | ip-wildcard | fqdn. '
                         'ip-wildcard refused while the address is in a static group',
            'ip-netmask,ip-range,ip-wildcard,fqdn', edit=SINGLE),
        col('Value', OPT, f'{EDIT_KEEP} Type and Value always together', edit=SINGLE),
        col('Description', OPT, f'{EDIT_KEEP} Free text, max 1023 bytes. {CLEAR}', edit=SINGLE),
        col('Tag', OPT, f'{EDIT_KEEP} Full new list of existing tags (replaces the current list). {CLEAR}', edit=SINGLE),
        vsys()]),
    ('edit_address_group', [
        DEVICE,
        col('Name', REQ, KEY_NAME.format(what='static address group') + '. Dynamic groups not supported'),
        col('Member', OPT, f'{EDIT_KEEP} Address objects / groups (see Edit-Member-mode). The group cannot become empty', edit=LIST, width=38),
        col('Description', OPT, f'{EDIT_KEEP} Free text, max 1023 bytes. {CLEAR}', edit=SINGLE),
        col('Tag', OPT, f'{EDIT_KEEP} Existing tag(s). replace + {CLEAR}', edit=LIST),
        vsys()]),
    ('edit_service_object', [
        DEVICE,
        col('Name', REQ, KEY_NAME.format(what='service object')),
        col('Protocol', OPT, f'{EDIT_KEEP} Protocol and Destination-port always together: tcp | udp', 'tcp,udp', edit=SINGLE),
        col('Source-port', OPT, f'{EDIT_KEEP} e.g. 1024-65535. {CLEAR}', edit=SINGLE),
        col('Destination-port', OPT, f'{EDIT_KEEP} Protocol and Destination-port always together, full new list', edit=SINGLE),
        col('Override', OPT, f'{EDIT_KEEP} yes | no', YES_NO, edit=SINGLE),
        col('Timeout', COND, f'{EDIT_KEEP} Only with Override yes (empty Override = current value): seconds 1-604800. {CLEAR}', edit=SINGLE),
        col('Halfclose-timeout', COND, f'{EDIT_KEEP} Only with Override yes and tcp: seconds 1-604800. {CLEAR}', edit=SINGLE),
        col('Timewait-timeout', COND, f'{EDIT_KEEP} Only with Override yes and tcp: seconds 1-600. {CLEAR}', edit=SINGLE),
        col('Description', OPT, f'{EDIT_KEEP} Free text, max 1023 bytes. {CLEAR}', edit=SINGLE),
        col('Tag', OPT, f'{EDIT_KEEP} Full new list of existing tags (replaces the current list). {CLEAR}', edit=SINGLE),
        vsys()]),
    ('edit_service_group', [
        DEVICE,
        col('Name', REQ, KEY_NAME.format(what='service group')),
        col('Member', OPT, f'{EDIT_KEEP} Services / groups (see Edit-Member-mode). The group cannot become empty', edit=LIST, width=44),
        col('Tag', OPT, f'{EDIT_KEEP} Existing tag(s). replace + {CLEAR}', edit=LIST),
        vsys()]),
    ('edit_security_rule', [
        DEVICE, POSITION_EDIT, REFERENCE,
        col('Name', REQ, KEY_NAME.format(what='rule')),
        col('Source-zone', OPT, f'{EDIT_KEEP} Zone(s) or any', edit=LIST),
        col('Destination-zone', OPT, f'{EDIT_KEEP} Zone(s) or any', edit=LIST),
        col('Source-ip', OPT, f'{EDIT_KEEP} Address / group names, region code or any', edit=LIST),
        col('Destination-ip', OPT, f'{EDIT_KEEP} Address / group names, region code or any', edit=LIST),
        col('Application', OPT, f'{EDIT_KEEP} Application(s) or any', edit=LIST),
        col('Service', OPT, f'{EDIT_KEEP} Service / group names, application-default or any. application-default and any must be alone: change them with replace', edit=LIST),
        col('Action', OPT, f'{EDIT_KEEP} allow | deny | drop | reset-client | reset-server | reset-both',
            'allow,deny,drop,reset-client,reset-server,reset-both', edit=SINGLE),
        col('Disable', OPT, f'{EDIT_KEEP} yes = disable, no = enable (Install: tick "Allow disabling / enabling rules")', YES_NO, edit=SINGLE),
        col('Description', OPT, f'{EDIT_KEEP} Free text, max 1024 bytes. {CLEAR}', edit=SINGLE),
        col('Tag', OPT, f'{EDIT_KEEP} Existing tag(s). replace + {CLEAR}', edit=LIST),
        col('Profile-group', OPT, f'{EDIT_KEEP} ONE security profile group. {CLEAR}', edit=SINGLE),
        col('Log-forwarding', OPT, f'{EDIT_KEEP} Log forwarding profile. {CLEAR}', edit=SINGLE),
        col('Log-start', OPT, f'{EDIT_KEEP} yes | no', YES_NO, edit=SINGLE),
        col('Log-end', OPT, f'{EDIT_KEEP} yes | no', YES_NO, edit=SINGLE),
        col('Url-category', OPT, f'{EDIT_KEEP} URL category(ies) or any', edit=LIST),
        col('Source-user', OPT, f'{EDIT_KEEP} User(s) / group(s), pre-logon / known-user / unknown or any', edit=LIST),
        vsys(rule=True)]),
    ('edit_nat_rule', [
        DEVICE, POSITION_EDIT, REFERENCE,
        col('Name', REQ, KEY_NAME.format(what='NAT rule')),
        col('Source-zone', OPT, f'{EDIT_KEEP} Zone(s) or any', edit=LIST),
        col('Destination-zone', OPT, f'{EDIT_KEEP} ONE zone (any is not valid in a NAT rule)', edit=SINGLE),
        col('Source-ip', OPT, f'{EDIT_KEEP} Address / group names, region code or any. Not: ip-wildcard address', edit=LIST),
        col('Destination-ip', OPT, f'{EDIT_KEEP} Address / group names, region code or any', edit=LIST),
        col('Service', OPT, f'{EDIT_KEEP} ONE service / group name or any', edit=SINGLE),
        col('Destination-interface', OPT, f'{EDIT_KEEP} ONE interface or any', edit=SINGLE),
        col('Destination-translation-type', OPT, f'{EDIT_KEEP} static | dynamic | none, with every column of the new type',
            'static,dynamic,none', edit=SINGLE),
        col('Dns-rewrite', COND, 'Only with Destination-translation-type replace = static: no | forward | reverse', 'no,forward,reverse'),
        col('Distribution', COND, 'Only with Destination-translation-type replace = dynamic',
            'round-robin,source-ip-hash,ip-modulo,ip-hash,least-sessions'),
        col('Dst-translate-address', COND, 'Only with Destination-translation-type replace = static / dynamic: ONE address name or IP'),
        col('Translate-port', COND, 'Only with Destination-translation-type replace = static / dynamic: port, or all'),
        col('Source-translation-type', OPT, f'{EDIT_KEEP} none | dynamic-ip-and-port with ... | dynamic-ip | static-ip, with every column of the new type',
            'none,dynamic-ip-and-port with Translate address,dynamic-ip-and-port with Interface address IP,'
            'dynamic-ip-and-port with Interface address Floating IP,dynamic-ip,static-ip', edit=SINGLE),
        col('static-bi-directional', COND, 'Only with Source-translation-type replace = static-ip: yes | no', YES_NO),
        col('Src-translate-address', COND, 'Only with Source-translation-type replace = Translate address / dynamic-ip / static-ip'),
        col('Src-translate-interface', COND, 'Only with Source-translation-type replace = Interface address IP / Floating IP'),
        col('Src-translate-address-ip', COND, 'Only with Source-translation-type replace = Interface address IP / Floating IP: IP or no'),
        col('Nat-type', OPT, f'{EDIT_KEEP} ipv4', 'ipv4', edit=SINGLE),
        col('Disable', OPT, f'{EDIT_KEEP} yes = disable, no = enable (Install: tick "Allow disabling / enabling rules")', YES_NO, edit=SINGLE),
        col('Active-active-device-binding', OPT, f'{EDIT_KEEP} primary | both | 0 | 1 (HA active-active only)', 'primary,both,0,1', edit=SINGLE),
        col('Description', OPT, f'{EDIT_KEEP} Free text, max 1024 bytes. {CLEAR}', edit=SINGLE),
        col('Tag', OPT, f'{EDIT_KEEP} Existing tag(s). replace + {CLEAR}', edit=LIST),
        col('Group-tag', OPT, f'{EDIT_KEEP} ONE existing tag. {CLEAR}', edit=SINGLE),
        vsys(rule=True)]),
]

# sheets with a mode column per editable column; object sheets: filled = replace, empty = keep
MODE_SHEETS = ('edit_address_group', 'edit_service_group', 'edit_security_rule', 'edit_nat_rule')
SHARED_SHEETS = ('add_tag', 'add_address_object', 'add_address_group', 'add_service_object', 'add_service_group',
                 'edit_tag', 'edit_address_object', 'edit_address_group', 'edit_service_object', 'edit_service_group')
SHEET_ORDER = [name for name, _ in ADD_SHEETS + EDIT_SHEETS]


#mode sheets: 'Edit-X-mode' right after each editable column X
def sheet_columns(sheet):
    spec = dict(ADD_SHEETS + EDIT_SHEETS)[sheet]
    out = []
    for c in spec:
        out.append(c)
        if sheet in MODE_SHEETS and c['edit']:
            out.append(col(mode_name(c['name']), OPT, f"Mode of {c['name']}: " + ' | '.join(MODES[c['edit']]) +
                           '. Empty / remain = kept', ','.join(MODES[c['edit']]), width=14))
    return out


#edit cells where 'none' clears the value
def clearable(sheet):
    return [c['name'] for c in dict(ADD_SHEETS + EDIT_SHEETS)[sheet] if sheet.startswith('edit_') and CLEAR in c['hint']]


def editable(sheet):
    return {c['name']: c['edit'] for c in dict(ADD_SHEETS + EDIT_SHEETS)[sheet] if c['edit']}


#required columns, red in the template
def mandatory(sheet):
    return [c['name'] for c in dict(ADD_SHEETS + EDIT_SHEETS)[sheet] if c['level'] == REQ]
