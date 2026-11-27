import pandas as pd
from . import palo_alto_api_lib as palib
import logging
import math

logger = logging.getLogger(__name__)


#math tool
#read a sheet: all cells as text, leading/trailing spaces removed, fully empty rows ignored
#cells as typed: no pandas guessing (text "NA", "null", "None" stays text), empty cell = ''
def read_sheet_raw(file, sheet):
    return pd.read_excel(file, sheet_name=sheet, dtype=str, keep_default_na=False)

def clean_sheet(df):
    df = df.map(lambda v: v.strip() if isinstance(v, str) else v)
    df = df.map(lambda v: float('nan') if v == '' else v)          # cell with only spaces = empty
    return df.dropna(how='all')

def read_sheet(file, sheet):
    return clean_sheet(read_sheet_raw(file, sheet))

#rows of a sheet as dicts + '_row' = Excel row number (header = row 1; empty rows dropped, numbers kept)
def sheet_rows(df):
    rows = df.to_dict(orient='records')
    for index, row in zip(df.index, rows):
        row['_row'] = index + 2
    return rows

#start of a result line: Excel row number, so the user finds the row in the file
def row_label(row_dict):
    return f"Row {row_dict['_row']} | " if '_row' in row_dict else ''

#value shown in a result line: empty cell -> '(empty)' instead of 'nan'
def shown(value):
    return '(empty)' if check_nan_value_no_except(value) else str(value)

#row not sent: ' Name Input Error +++  Tag Input Error +++' -> 'Name Input Error · Tag Input Error'
#skipped = duplicate found with Stop duplicated: 'SKIPPED: <duplicate>' only when it is the only reason,
#otherwise the row is an error and shows its errors only (BUG-58, P20)
def row_errors(msg, skipped=''):
    parts = [part.strip() for part in str(msg).split('+++') if part.strip()]
    parts = [p for p in parts if not any(q.startswith(p + ' (') for q in parts)]     # bare '<Column> Input Error' + same with a reason
    if skipped:
        parts = [part for part in parts if part != skipped]
        if not parts:
            return 'SKIPPED: ' + skipped        # an error row shows its errors only, as in the Dry-run (P20)
    return ' · '.join(parts)

#check value is NaN or not, return Raise error
def check_nan_value(value):
    if isinstance(value, float) and math.isnan(value):
        raise ValueError("Empty Value")

#check value is NaN/None or not, without return Raise error (None = optional column not in sheet)
def check_nan_value_no_except(value):
    if value is None or (isinstance(value, float) and math.isnan(value)):
        return True
    else:
        return False


#list of entries on the firewall (duplicate / Reference-rule checks), BUG-54:
#success without 'entry' (no object yet) -> []; any other answer or exception -> None + reason, the row goes on with a warning
def read_entry_list(get_func,host,token,location_object):
    fw = palib.api(host, token)
    what = fw.LIST_NAMES.get(getattr(get_func, '__name__', ''), 'the list')
    where = location_object.get('@' + location_object.get('location', ''), location_object.get('location', ''))
    try:
        entries, reason = fw.entries(get_func(host,token,location_object))
        if entries is not None:
            return entries, ''
    except Exception as e:                       # no answer (timeout, refused, TLS...) or anything unexpected: generic text, details in server log
        logger.warning('cannot read %s from %s: %r', what, host, e)
        reason = 'no valid answer from the firewall'
    return None, f'cannot read {what} ({where}): {reason}'

#list of a sheet cache: read once per (device, vsys) while it works; not cached when unreadable -> next row reads again
#rows done while unreadable go to a pending list, added when the list is read (dry-run creates nothing on the firewall)
#return (list, '') or (pending list, 'cannot read <list> (<vsys>): <reason>')
def cached_list(cache, ckey, get_func, host, token, loc):
    if ckey in cache:
        return cache[ckey], ''
    pending = cache.setdefault(('pending', ckey), [])
    entries, reason = read_entry_list(get_func, host, token, loc)
    if entries is None:
        return pending, reason
    names = {e['@name'] for e in entries}
    cache[ckey] = entries + [e for e in pending if e['@name'] not in names]
    return cache[ckey], ''

#Stop duplicated + list unreadable: not created (duplicate not checked), shown as an error, not SKIPPED
def stop_duplicate_check(check_mandatory_value, dup_rs, not_read):
    if dup_rs == 'No Duplicate':
        return
    if not_read:
        check_mandatory_value['msg'] += f' NOT CREATED (Stop duplicated): {dup_rs} +++'
    else:
        check_mandatory_value['msg'] += f' {dup_rs} +++'
        check_mandatory_value['skipped'] = dup_rs       # SKIPPED only if no other error at the end (row_errors)
    check_mandatory_value['status'] = False

#name already used by the other kind of the same name space (address <-> address group, service <-> service group: version
#class NAME_SPACES): the firewall refuses the create "Name Not Unique" (BUG-75). On the firewall, or (dry-run) created by a
#row of an earlier sheet of the file. List unreadable -> not checked
def other_kind_duplicate(fw, kind, cache, ckey, host, token, loc, object, dup_rs, dry_ctx=None):
    name = object['entry'].get('@name')
    if not name or fw.duplicate_name_refused(dup_rs):
        return dup_rs
    other_kind, getter, what = fw.NAME_SPACES[kind]
    other, not_read = cached_list(cache, ('other', ckey), getattr(palib, getter), host, token, loc)
    created = dry_ctx.created.get((host, loc['@vsys'], 'name:' + other_kind), set()) if dry_ctx else set()
    return f'Duplicate Name with {name} ({what})' if name in created or any(e.get('@name') == name for e in other) else dup_rs

#vsys row: same name / value as an object in shared (P-02 shared). Allowed by the firewall (FW01 11.1: the vsys object hides the
#shared one in that vsys) -> warning, SKIPPED with Stop duplicated. Shared list read once per sheet / firewall, unreadable -> not checked
def shared_duplicate(fw, dup_func, getter, cache, host, token, loc, object, dup_rs):
    if is_shared(loc) or dup_rs != 'No Duplicate':
        return dup_rs
    shared = fw.shared_location()
    known, not_read = cached_list(cache, (host, shared['@vsys']), getter, host, token, shared)
    found = 'No Duplicate' if not_read else dup_func(known, object)
    if found.lower().startswith('duplicate name'):
        return f"Same Name as {found.split(' with ', 1)[1]} (shared): the vsys object hides it in this vsys"
    return dup_rs if found == 'No Duplicate' else f'{found} (shared)'

#Position + Reference-rule columns: where the new rule goes, same as the PAN-OS move (top / bottom / before <rule> / after <rule>).
#Rows run in file order: several rows 'before X' end up together above X, in file order.
#Reference-rule = rule already on the firewall (same vsys); a rule created by the file is refused (FEAT-23).
#input check of Position / Reference-rule; return (where, reference), where '' = bottom (nothing to move)
#rule list unreadable (not_read = reason): before / after cannot be checked -> not created (a rule created at a wrong place is worse), BUG-54
def check_position(fw, row_dict, list_rules, name, check_mandatory_value, not_read='', dry_run=False, created=()):
    def cell(col):
        value = row_dict.get(col)
        return '' if check_nan_value_no_except(value) else str(value).strip()
    where, ref = cell('Position').lower(), cell('Reference-rule')
    error = ''
    if where and where not in fw.POSITIONS:
        error = f" Position Input Error ({', '.join(fw.POSITIONS[:-1])} or {fw.POSITIONS[-1]}) +++"
    elif where in ('before', 'after') and not ref:
        error = ' Reference-rule Input Error (rule name needed with before / after) +++'
    elif where not in ('before', 'after') and ref:
        error = ' Reference-rule Input Error (only with Position before / after) +++'
    elif ref and ref == name:
        error = ' Reference-rule Input Error (the rule itself) +++'
    elif ref and not_read:                              # every row checks on the firewall, even a rule created by a row above
        label = 'CANNOT CREATE' if dry_run else 'NOT CREATED'
        stop = f' NOT CREATED (Stop duplicated): duplicate could not be checked ({not_read}) +++'
        if stop in check_mandatory_value['msg']:            # same reason once: Stop duplicated + Reference-rule
            check_mandatory_value['msg'] = check_mandatory_value['msg'].replace(stop, '')
            error = f' {label}: duplicate / Reference-rule could not be checked ({not_read}) +++'
        else:
            error = f' {label}: Reference-rule could not be checked ({not_read}) +++'
    elif ref and ref in created:
        error = f" Reference-rule Input Error ('{ref}' is created by this file: Reference-rule must be a rule already on the firewall) +++"
    elif ref and ref not in [r['@name'] for r in list_rules]:
        error = f" Reference Error: Reference-rule '{ref}' not found on the firewall +++"
    if error:
        check_mandatory_value['status'] = False
        check_mandatory_value['msg'] += error
    return ('' if where == 'bottom' else where), ref

#move the new rule (last of list_rules) to its Position, update cache only if move success; None = bottom, nothing to send
def move_rule_to_position(fw,move_func,host,token,location_object,list_rules,name,where,ref):
    if not where:
        return None
    params = dict(location_object, name=name, where=where)
    if ref:
        params['dst'] = ref
    rs = move_func(host=host,token=token,location_object=params)
    if fw.is_success(rs) and list_rules is not None and name in [r['@name'] for r in list_rules]:
        rule = list_rules.pop([r['@name'] for r in list_rules].index(name))
        names = [r['@name'] for r in list_rules]
        list_rules.insert({'top': 0, 'bottom': len(names)}.get(where, names.index(ref) + (where == 'after') if ref in names else len(names)), rule)
    return rs

#log text of the move: dry-run 'CAN MOVE before 'X'', install 'moved before 'X''
def move_text(fw, where, ref, rs, dry_run):
    target = {'top': 'to top', 'bottom': 'to bottom'}.get(where, f"{where} '{ref}'")
    if not fw.is_success(rs):
        return f' | Move {target}: ' + fw.error_text(rs)
    return f" | {'CAN MOVE' if dry_run else 'moved'} {target}"

#location of a row: column Vsys (FEAT-23: required, vsysN or shared, any case). Empty / invalid -> the row is an error
#(check_row), its location here is the job default so the row is only reported
def row_location(fw, row_dict, location_object):
    scope, reason = fw.vsys_value(row_dict.get('Vsys'))
    if reason:
        return dict(location_object) if location_object else fw.default_location()
    if scope == fw.SHARED_NAME:
        return fw.shared_location()                 # visible to every vsys (object sheets; rule sheets refused by file_check)
    return fw.vsys_location(scope)

#vsys shown in a result line: the location of the row, or what was typed when the Vsys is empty / wrong (the row is an
#error, it never ran in the default vsys - P7)
def vsys_label(fw, row_dict, loc):
    typed = row_dict.get('Vsys')
    if not fw.vsys_value(typed)[1]:
        return loc['@vsys']
    return 'Vsys empty' if check_nan_value_no_except(typed) or str(typed).strip() == '' else f"Vsys '{str(typed).strip()}'"

def is_shared(loc):
    return loc.get('location') == 'shared'

#names known on firewall (vsys) + names created by earlier rows of the job, per (device, vsys, kind)
class DryRunContext:
    #what is read (REST / XML API lists) and how names compare: attributes of the version class of each firewall
    #(REFERENCE_SOURCES, REFERENCE_NOT_CASE_SENSITIVE, PREDEFINED_SERVICES...), see panos/v11_1.py

    def __init__(self):
        self.firewall = {}
        self.created = {}
        self.warnings = []
        self.predefined_apps = {}               # (firewall, application) -> True / False, asked once per name
        self.apis = {}                          # firewall -> API object of the last check() (register() has no token)
        self.refused = {}                       # (firewall, vsys, name) -> 'an EDL'..., refused as static group member (UI-16)
        self.entries = {}                       # (firewall, vsys, create kind) -> entries created by the add sheets (edit of them)

    #names of an XML API list, or (None, reason)
    @staticmethod
    def read_names(func, args, what, host, token):
        try:
            return set(getattr(palib, func)(host, token, *args)), ''
        except palib.FirewallError as e:
            return None, f'cannot read {what}: {palib.safe_error(e)}'
        except Exception as e:
            logger.warning('cannot read %s from %s: %r', what, host, e)
            return None, f'cannot read {what}: no valid answer from the firewall'

    #None = list unreadable (reason added to the warnings of the row, read again for the next row)
    def names(self, kind, host, token, loc):
        key = (host, loc['@vsys'], kind)
        fw = palib.api(host, token)
        if key not in self.firewall:
            found = set()                       # vsys + shared of the firewall (not Panorama, FEAT-02)
            for source in fw.REFERENCE_SOURCES[kind]:
                if isinstance(source, tuple):
                    names, reason = self.read_names(*source, host, token)
                else:
                    names, reason = set(), ''
                    excluded = fw.REFERENCE_EXCLUDED.get(kind, ())
                    if is_shared(loc) and source not in fw.REFERENCE_SHARED:
                        continue                # no such list in shared (zones, regions): a shared object cannot use them
                    for where in [loc] + ([fw.shared_location()] if source in fw.REFERENCE_SHARED and not is_shared(loc) else []):   # P-02
                        entries, reason = read_entry_list(getattr(palib, source), host, token, where)
                        if entries is None:
                            names = None
                            break
                        names |= {e['@name'] for e in entries if not any(k in e for k in excluded)}
                        for en in entries:
                            what = fw.MEMBER_REFUSED.get(source) or next((t for k, t in fw.MEMBER_REFUSED.items() if k in en), None)
                            if what:
                                self.refused[(host, loc['@vsys'], en['@name'])] = what
                if names is None:
                    if reason not in self.warnings:
                        self.warnings.append(reason)
                    return None
                found |= names
            self.firewall[key] = found
        scopes = [loc['@vsys']] + ([] if is_shared(loc) else [fw.shared_location()['@vsys']])      # a vsys sees what earlier rows created in shared
        created = set()
        for scope in scopes:
            created |= self.created.get((host, scope, kind), set()) | (self.created.get((host, scope, 'address'), set()) - self.created.get((host, scope, 'refused'), set()) if kind == 'address_member' else set())
        return self.firewall[key] | created

    #application: custom / group / filter of the vsys, else a predefined application (asked to the firewall once per name)
    def application_known(self, host, token, loc, name):
        known = self.names('application', host, token, loc)
        if known is None or name in known:
            return known is not None
        if (host, name) not in self.predefined_apps:
            try:
                self.predefined_apps[(host, name)] = palib.predefined_application_exists(host, token, name)
            except Exception as e:
                reason = f'cannot read predefined applications: {palib.safe_error(e)}'
                if not isinstance(e, palib.FirewallError):
                    logger.warning('cannot read predefined application %s from %s: %r', name, host, e)
                    reason = 'cannot read predefined applications: no valid answer from the firewall'
                if reason not in self.warnings:
                    self.warnings.append(reason)
                return True                     # not checked: warning, not an error
        return self.predefined_apps[(host, name)]

    def add(self, kind, host, loc, name):
        self.created.setdefault((host, loc['@vsys'], kind), set()).add(name)

    #return error message ('' if ok); references that cannot be checked -> warning shown by register()
    def check(self, func_kind, host, token, loc, object):
        e = object['entry']
        errors = []
        self.warnings = []
        fw = self.apis[host] = palib.api(host, token)
        #the vsys of the row must exist on the firewall (a missing vsys answers an empty list, then the install fails)
        vsys_list = None if is_shared(loc) else self.names('vsys', host, token, {'location': 'vsys', '@vsys': 'firewall'})   # one list per firewall
        if vsys_list is not None and loc['@vsys'] not in (vsys_list or {fw.DEFAULT_VSYS}):
            return f"Reference Error: vsys '{loc['@vsys']}' not found (firewall vsys: {', '.join(sorted(vsys_list)) or fw.DEFAULT_VSYS})"
        #group members are names only: an IP is the name of an address object, any / application-default are not members
        def need(kind, field, members, group=False, ip_ok=False):
            if not members:
                return
            known = None
            for m in members:
                if not group and ((kind == 'address' and fw.is_literal_address(m)) or (kind == 'service' and m in fw.PREDEFINED_SERVICES)):
                    continue
                if ip_ok and fw.is_ip_literal(m):          # NAT translated address: bare IP accepted (FEAT-23)
                    continue
                if group and kind == 'service' and m in fw.GROUP_PREDEFINED_SERVICES:
                    continue
                known = known if known is not None else self.names(kind, host, token, loc)
                if known is None:
                    return
                if kind in fw.REFERENCE_NOT_CASE_SENSITIVE:
                    found = m.lower() in {k.lower() for k in known}
                else:
                    found = m in known
                if not found and kind == 'address_member' and m in (self.names('address', host, token, loc) or ()):
                    what = next((self.refused[(host, v, m)] for v in (loc['@vsys'], fw.shared_location()['@vsys']) if (host, v, m) in self.refused), 'not an address')
                    errors.append(f"{field} '{m}' is {what}: a static address group only accepts {fw.STATIC_MEMBERS}")
                elif not found and group and m == e.get('@name'):
                    self.warnings.append(f"group '{m}' contains itself")     # the firewall decides at Install (FEAT-23)
                elif not found:
                    same = [k for k in known if k.lower() == m.lower()]      # the firewall compares names exactly (BUG-71)
                    errors.append(f"{field} '{m}' not found" + (' in shared' if is_shared(loc) else '') + (f" (did you mean '{same[0]}'?)" if same else ''))
        def members(container):
            value = (container or {}).get('member') if isinstance(container, dict) else container
            return [] if not value else ([value] if isinstance(value, str) else list(value))
        def any_free(values):
            return [v for v in values if v != 'any']
        def missing(kind, name):
            known = self.names(kind, host, token, loc)
            return known is not None and name not in known
        if func_kind in ('edit_policy', 'delete_policy') and missing('security_rule', e['@name']):
            errors.append(f"rule '{e['@name']}' not found")
        if func_kind in ('edit_nat', 'delete_nat') and missing('nat_rule', e['@name']):
            errors.append(f"nat rule '{e['@name']}' not found")
        if func_kind in ('create_policy', 'edit_policy', 'create_nat', 'edit_nat'):
            need('address', 'source', e['source']['member'], ip_ok=True)          # bare IP: warning (P18), not an error
            need('address', 'destination', e['destination']['member'], ip_ok=True)
            service = e['service']['member'] if isinstance(e['service'], dict) else [e['service']]
            need('service', 'service', service)
        if func_kind in ('create_nat', 'edit_nat'):
            for t in ('destination-translation', 'dynamic-destination-translation'):
                if t in e and e[t].get('translated-address'):
                    need('address', 'translated-address', [e[t]['translated-address']], ip_ok=True)
        if func_kind == 'address_group':
            need('address_member', 'member', e['static']['member'], group=True)
        if func_kind == 'service_group':
            need('service', 'member', e['members']['member'], group=True)
        #zones, tags, profiles, log forwarding, URL categories, applications of rules / NAT; tags of objects. Interfaces are not
        #checked (user 2026-11-25, BUG-72): the firewall refuses a wrong one at Install
        if func_kind in ('create_policy', 'edit_policy', 'create_nat', 'edit_nat'):
            need('zone', 'source zone', any_free(members(e.get('from'))))
            need('zone', 'destination zone', any_free(members(e.get('to'))))
        if func_kind in ('create_policy', 'edit_policy'):
            for app in any_free(members(e.get('application'))):
                if not self.application_known(host, token, loc, app):
                    errors.append(f"application '{app}' not found")
            need('profile_group', 'profile group', members((e.get('profile-setting') or {}).get('group')))
            need('log_forwarding', 'log forwarding', members(e.get('log-setting')))
            need('url_category', 'URL category', any_free(members(e.get('category'))))
        if func_kind in ('create_nat', 'edit_nat'):
            for kind in (e.get('source-translation') or {}).values():
                need('address', 'source translated-address', members((kind or {}).get('translated-address')), ip_ok=True)
            need('tag', 'group tag', members(e.get('group-tag')))
        if func_kind in ('create_policy', 'edit_policy', 'create_nat', 'edit_nat', 'address', 'address_group', 'service', 'service_group'):
            need('tag', 'tag', members(e.get('tag')))
        return ('Reference Error: ' + '; '.join(errors)) if errors else ''

    #after a row would succeed: its object becomes known for next rows/sheets
    #row can be done: remember what it creates; return the warning text of references not checked ('' if none)
    def register(self, func_kind, host, loc, object):
        kind = {'address': 'address', 'address_group': 'address', 'service': 'service', 'service_group': 'service',
                'create_policy': 'security_rule', 'create_nat': 'nat_rule', 'tag': 'tag'}.get(func_kind)
        if kind:
            self.entries.setdefault((host, loc['@vsys'], func_kind), []).append(object['entry'])     # edit sheets of the same file
            self.add(kind, host, loc, object['entry']['@name'])
            self.add('name:' + func_kind, host, loc, object['entry']['@name'])     # its own kind: name space check (BUG-75)
            what = next((t for k, t in getattr(self.apis.get(host), 'MEMBER_REFUSED', {}).items() if func_kind == 'address' and k in object['entry']), None)
            if what:                            # ip-wildcard created by an earlier row: not a static group member (UI-16)
                self.add('refused', host, loc, object['entry']['@name'])
                self.refused[(host, loc['@vsys'], object['entry']['@name'])] = what
        text = ''.join(f' | Warning: {w}' if w.startswith(('group ', 'circular ')) else f' | Warning: references could not be checked ({w})'
                       for w in self.warnings)
        self.warnings = []
        return text

# Main function
# Get unique device and token
def get_unique_device_and_token(username,password,file_content,sheetname):
    df = read_sheet(file_content, sheetname)
    list_of_dicts = df.to_dict(orient='records')

    list_device_ip = dict.fromkeys(row_dict['Device-ip'] for row_dict in list_of_dicts)    # unique, in file order

    # get all device token:
    dict_device_token = {}
    for host in list_device_ip:
        try:
            check_nan_value(host)
            token = ''
            token = palib.get_token(host,username,password)
            dict_device_token[host] = token
        except Exception as e:
            error = f'Get API Token from {host} failed: {palib.safe_error(e)}'
            dict_device_token[host] = error

            return f'Get API Token from {host} failed: {palib.safe_error(e)}'
        try:
            palib.detect_rest_version(host, token)       # REST URLs of this firewall use its own PAN-OS version
        except Exception as e:
            return f'Cannot read the PAN-OS version of {host} (show system info): {palib.safe_error(e)}'
    return dict_device_token

#API key + PAN-OS version of every firewall of the job, in file order (BUG-69): a firewall that fails (unreachable,
#wrong password, version not readable) does not stop the others -> (tokens {host: key}, failures {host: reason})
def get_device_tokens(username,password,rows):
    hosts = dict.fromkeys(row_dict['Device-ip'] for row_dict in rows)          # unique, in file order (job sections follow it)
    tokens, failures = {}, {}
    for host in hosts:
        try:
            check_nan_value(host)
            token = palib.get_token(host,username,password)
        except Exception as e:
            failures[host] = f'Get API Token from {host} failed: {palib.safe_error(e)}'
            continue
        try:
            palib.detect_rest_version(host, token)       # REST URLs of this firewall use its own PAN-OS version
        except Exception as e:
            failures[host] = f'Cannot read the PAN-OS version of {host} (show system info): {palib.safe_error(e)}'
            continue
        tokens[host] = token
    return tokens, failures



#rule that allows everything (allow + source / destination / application / service any): created, with a warning (FEAT-23)
def allows_all(entry):
    def members(key):
        value = (entry.get(key) or {}).get('member') if isinstance(entry.get(key), dict) else entry.get(key)
        return [value] if isinstance(value, str) else list(value or [])
    return entry.get('action') == 'allow' and all(members(k) == ['any'] for k in ('source', 'destination', 'application', 'service'))

ALLOWS_ALL = 'rule allows all traffic (source, destination, application, service = any)'


#group nesting that comes back to the group itself (G1 -> G2 -> G1) -> 'circular nesting: G1 -> G2 -> G1' or '' (FEAT-23:
#warning only, the firewall decides at Install); groups = entries of the same location (firewall + rows of the file)
GROUP_MEMBERS = {'address_group': 'static', 'service_group': 'members'}

def group_cycle(kind, groups, entry):
    key = GROUP_MEMBERS[kind]
    def members(e):
        value = (e.get(key) or {}).get('member') or []
        return [value] if isinstance(value, str) else list(value)
    graph = {g['@name']: members(g) for g in groups}
    graph[entry['@name']] = members(entry)
    start = entry['@name']
    if start in graph[start]:
        return f"group '{start}' contains itself"
    stack = [(m, [start, m]) for m in graph[start]]
    seen = set()
    while stack:
        node, path = stack.pop()
        if node == start:
            return 'circular nesting: ' + ' -> '.join(path)
        if node in seen or node not in graph:
            continue
        seen.add(node)
        stack += [(m, path + [m]) for m in graph[node]]
    return ''


#type of the addresses a NAT row may use (ip-netmask / ip-range / ip-wildcard / fqdn): vsys + shared lists (read once per
#sheet), then the addresses created / changed by earlier rows of the job
def address_types(fw, cache, host, token, loc, job):
    types = {}
    for where in (fw.shared_location(), loc):           # a vsys address hides the shared one of the same name
        entries, not_read = cached_list(cache, ('addresses', host, where['@vsys']), palib.get_Objects_Addresses, host, token, where)
        types.update({e['@name']: next((t for t in fw.ADDRESS_TYPES if t in e), '') for e in entries})
    for (h, v, n), t in job.get('addr_types', {}).items():
        if h == host and v in (fw.SHARED_NAME, loc['@vsys']):
            types[n] = t
    return types


#ip-wildcard addresses used as NAT Source-ip: refused by FW01 11.1 (AO-617) -> refused by the tool at Dry-run and Install (P8)
def nat_wildcard_sources(fw, cache, host, token, loc, sources, job):
    types = address_types(fw, cache, host, token, loc, job)
    return [s for s in sources if types.get(s) == 'ip-wildcard']


#bare IP / CIDR / range / IPv6 of a rule Source-ip / Destination-ip that is not the name of an address object: FW01 11.1
#accepts it as typed -> warning at Dry-run and Install (P18, user 2026-11-27)
def bare_ip_warnings(fw, cache, host, token, loc, entry, job, cols=('source', 'destination')):
    types = None
    out = []
    for key in cols:
        for m in (entry.get(key) or {}).get('member') or []:
            if fw.is_ip_literal(m):
                types = types if types is not None else address_types(fw, cache, host, token, loc, job)
                if m not in types:
                    out.append(f"{key} '{m}' is not an address object: the firewall uses it as a bare IP")
    return out


#fqdn address as translated address of a static destination NAT: refused by FW01 11.1 ("is an invalid ipv4/v6 address",
#AO-617) -> refused by the tool at Dry-run and Install (P19); dynamic destination NAT accepts fqdn
def nat_static_fqdn(fw, cache, host, token, loc, entry, job):
    target = (entry.get('destination-translation') or {}).get('translated-address')
    return target if target and address_types(fw, cache, host, token, loc, job).get(target) == 'fqdn' else ''


#remember the type of an address created / edited by the job, for the NAT checks of later sheets
def note_wildcard(job, host, loc, entry):
    job.setdefault('addr_types', {})[(host, loc['@vsys'], entry['@name'])] = next((t for t in ('ip-netmask', 'ip-range', 'ip-wildcard', 'fqdn') if t in entry), '')


#names of a kind created by the add sheets of the job (Reference-rule must be a rule already on the firewall, FEAT-23)
def job_created(job, host, loc, kind):
    return {name for h, v, k, name in job.get('created', ()) if (h, v, k) == (host, loc['@vsys'], kind)}


#one add sheet (FEAT-23: same code for every kind, rules of the version class CREATE_KINDS):
#  name already used (same kind, other kind of the name space, shared) -> dry-run CANNOT CREATE '<kind> 'X' already exists';
#  install: sent, the firewall refuses with its message (a vsys object named like a shared object: refused by the tool);
#  same value as an existing entry -> warning, SKIPPED with Stop duplicated (install)
def automatic_create(kind,username,password,input_excel_file_path,sheet,location_object=None,stop_duplicate=False,dict_device_token=None,log=None,dry_run=False,dry_ctx=None,device=None,job=None):
    job = {} if job is None else job          # shared by the sheets of the job: names created by the file ('created')
    location_object = dict(location_object) if location_object else None      # None: default location of the firewall version (vsys1)
    if dry_run and dry_ctx is None:
        dry_ctx = DryRunContext()
    if dict_device_token is None:
        dict_device_token = get_unique_device_and_token(username=username,password=password,file_content=input_excel_file_path,sheetname=sheet)

    list_of_dicts = sheet_rows(read_sheet(input_excel_file_path, sheet))     # file order
    if device is not None:                                     # job per firewall: only the rows of this Device-ip
        list_of_dicts = [r for r in list_of_dicts if str(r.get('Device-ip')) == device]

    final_result = ''
    cache = {}                  #(device, vsys) -> entries read on the firewall, GET once per sheet
    for row_dict in list_of_dicts:
        host = row_dict['Device-ip']
        token = dict_device_token[host]
        fw = palib.api(host, token)          # version class of this firewall (PAN-OS values, answers, field rules)
        builder, getter, create_call, dup_func, text, ctx_kind, move_call = fw.CREATE_KINDS[kind]
        loc = row_location(fw, row_dict, location_object)
        ckey = (host, loc['@vsys'])
        check_mandatory_value = {'status': True, 'msg': ''}
        built = getattr(fw, builder)(row_dict, check_mandatory_value)
        object, compared = built if isinstance(built, tuple) else (built, built)      # service: entry without timeouts compared
        name = object['entry'].get('@name') or shown(row_dict.get('Name'))

        #duplicates: same name / same value on the firewall (vsys, other kind of the same name space, shared)
        known, not_read = cached_list(cache, ckey, getattr(palib, getter), host, token, loc)
        made = cache.setdefault(('made', ckey), [])          # entries created by earlier rows of this sheet
        dup_rs = f'duplicate could not be checked ({not_read})' if not_read else getattr(fw, dup_func)(known, compared)
        if not fw.duplicate_name_refused(dup_rs) and any(e.get('@name') == compared['entry'].get('@name') for e in made):
            dup_rs = 'Duplicate Name with ' + compared['entry']['@name']
        if kind == 'tag' and not fw.duplicate_name_refused(dup_rs) and name in fw.PREDEFINED_TAGS:
            dup_rs = f'Duplicate Name with {name} (predefined)'      # Sanctioned...: not in the REST list (FEAT-23)
        if kind in fw.NAME_SPACES:
            dup_rs = other_kind_duplicate(fw, kind, cache, ckey, host, token, loc, object, dup_rs, dry_ctx)     # BUG-75
        if kind not in ('security_rule', 'nat_rule'):
            dup_rs = shared_duplicate(fw, getattr(fw, dup_func), getattr(palib, getter), cache, host, token, loc, compared, dup_rs)
        name_used = fw.duplicate_name_refused(dup_rs)
        if name_used:
            exists = fw.name_exists_text(kind, dup_rs, name)
            if is_shared(loc) and not exists.endswith('(shared)'):
                exists += ' (shared)'
            if dry_run:
                check_mandatory_value['status'] = False
                check_mandatory_value['msg'] += f' CANNOT CREATE: {exists} +++'
            elif dup_rs.startswith('Same Name as ') or dup_rs.endswith('(predefined)'):
                # F-28: vsys object named like a shared object; P5: predefined tag name (FW01 11.1.10 creates a second
                #'Sanctioned' in the vsys) -> refused by the tool at Install too, like the Dry-run
                check_mandatory_value['status'] = False
                check_mandatory_value['msg'] += f' NOT CREATED: {exists} +++'
        elif stop_duplicate and not dry_run:      # Install only: dry-run never skips, duplicate = warning
            stop_duplicate_check(check_mandatory_value, dup_rs, not_read)

        where, ref = '', ''
        if move_call:                           #--- Position / Reference-rule: the reference must be on the firewall already
            where, ref = check_position(fw, row_dict, known + made, object['entry'].get('@name'), check_mandatory_value, not_read, dry_run,
                                        created=job_created(job, host, loc, kind))

        if kind == 'nat_rule' and check_mandatory_value['status'] == True:
            wild = nat_wildcard_sources(fw, cache, host, token, loc, object['entry']['source']['member'], job)
            if wild:
                check_mandatory_value['status'] = False
                check_mandatory_value['msg'] += ' Source-ip: ' + ', '.join(f"'{w}'" for w in wild) + ' is an ip-wildcard address: not valid in a NAT rule +++'
            fqdn = nat_static_fqdn(fw, cache, host, token, loc, object['entry'], job)
            if fqdn:
                check_mandatory_value['status'] = False
                check_mandatory_value['msg'] += f" Dst-translate-address: '{fqdn}' is an fqdn address: not valid with destination static (use an IP address) +++"

        #dry-run: referenced objects must exist (on firewall or created by earlier rows)
        if dry_run and check_mandatory_value['status'] == True:
            ref_rs = dry_ctx.check(ctx_kind, host, token, loc, object)
            if ref_rs:
                check_mandatory_value['status'] = False
                check_mandatory_value['msg'] += ref_rs

        result = row_label(row_dict) + 'Device-IP: ' + str(row_dict['Device-ip']) + ' (' + vsys_label(fw, row_dict, loc) + f') | {text}: ' + shown(row_dict.get('Name')) + ' => '
        if check_mandatory_value['status'] == True:
            rs = fw.dry_answer('create') if dry_run else getattr(palib, create_call)(host=host, token=token, object=object, location_object=loc)
            move_rs = None
            if fw.is_success(rs):
                made.append(compared['entry'])          #names of next rows; values of new rows are not compared (FEAT-23)
                order = cache.setdefault(('order', ckey), known)        # rule order on the firewall, for the moves
                job.setdefault('created', set()).add((host, loc['@vsys'], kind, object['entry']['@name']))
                if kind == 'address':
                    note_wildcard(job, host, loc, object['entry'])
                if move_call:
                    move = (lambda **k: fw.dry_answer('move')) if dry_run else getattr(palib, move_call)
                    if order is known:
                        order = cache[('order', ckey)] = list(known)
                    order.append(compared['entry'])
                    move_rs = move_rule_to_position(fw, move, host, token, loc, None if not_read else order, object['entry']['@name'], where, ref)
                    if not not_read:            # rulebase after this row, for the moves of the edit sheets at Dry-run (BUG-86)
                        job.setdefault('order', {})[(host, loc['@vsys'], kind)] = list(order)
                result += fw.success_text(rs)
                if dry_run:
                    result += dry_ctx.register(ctx_kind, host, loc, object)
                if dup_rs != 'No Duplicate' and not name_used:
                    result += ' | Warning: ' + dup_rs
                if kind == 'security_rule' and allows_all(object['entry']):
                    result += ' | Warning: ' + ALLOWS_ALL
                if kind in ('security_rule', 'nat_rule'):
                    result += ''.join(' | Warning: ' + w for w in bare_ip_warnings(fw, cache, host, token, loc, object['entry'], job))
                cycle = group_cycle(kind, known + made, object['entry']) if kind in GROUP_MEMBERS else ''
                if cycle and cycle not in result:
                    result += ' | Warning: ' + cycle
                if move_rs is not None:
                    result += move_text(fw, where, ref, move_rs, dry_run)
            else:
                result += fw.error_text(rs)
                if dup_rs != 'No Duplicate' and not name_used:     # firewall refused the row: keep the duplicate found by the tool
                    result += ' | Warning: ' + dup_rs
        else:
            result += row_errors(check_mandatory_value['msg'], check_mandatory_value.get('skipped', ''))
        final_result += result + '\n'
        if log:
            log(result)
    return final_result
