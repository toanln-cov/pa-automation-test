# Edit sheets: entry read, edited and sent back whole with PUT under the config lock
import copy
from . import palo_alto_api_lib as palib
from .PA_tool import (read_sheet, sheet_rows, row_label, shown, row_errors, cached_list, row_location, check_position,
                      move_rule_to_position, move_text, DryRunContext, get_unique_device_and_token, allows_all, ALLOWS_ALL,
                      is_shared, rules_before, group_cycle, GROUP_MEMBERS, vsys_label, nat_wildcard_sources, note_wildcard, nat_static_fqdn, bare_ip_warnings)
from .panos import fields

MODE_KINDS = ('address_group', 'service_group', 'security_rule', 'nat_rule')
MODES = ('add', 'remove', 'replace', 'remain')
CREATE_KIND = {'security_rule': 'create_policy', 'nat_rule': 'create_nat'}
NAT_TYPE_COLUMNS = {'Destination-translation-type': 'nat_dst_translation', 'Source-translation-type': 'nat_src_translation'}


def mode_name(column):
    return f'Edit-{column}-mode'


def is_clear(fw, value):
    return not fields.empty(value) and str(value).strip().lower() == fw.CLEAR_WORD


def get_path(entry, path):
    node = entry
    for key in path:
        node = node.get(key) if isinstance(node, dict) else None
        if node is None:
            break
    if path[-1] == 'member':
        return [] if node is None else ([node] if isinstance(node, str) else list(node))
    return node


def set_path(entry, path, value):
    if value is None or value == []:
        parents = [entry]
        for key in path[:-1]:
            parents.append(parents[-1].get(key) if isinstance(parents[-1], dict) else None)
            if parents[-1] is None:
                return
        parents[-1].pop(path[-1], None)
        for depth in range(len(path) - 1, 0, -1):      # empty containers are not valid
            if parents[depth] == {}:
                parents[depth - 1].pop(path[depth - 1], None)
        return
    node = entry
    for key in path[:-1]:
        node = node.setdefault(key, {})
    node[path[-1]] = value


def row_modes(fw, kind, row, editable, check):
    modes = {}
    for col, is_list in editable.items():
        filled = not fields.empty(row.get(col))
        if kind not in MODE_KINDS:
            if filled:
                modes[col] = 'replace'
            continue
        raw = row.get(mode_name(col))
        mode = '' if fields.empty(raw) else str(raw).strip().lower()
        allowed = MODES if is_list else ('replace', 'remain')
        error = ''
        if mode and mode not in MODES:
            error = f"{mode_name(col)}: {' / '.join(allowed)}"
        elif mode in ('add', 'remove') and not is_list:
            error = f"{mode_name(col)}: {col} is a single value, replace only"
        elif mode == 'remain' and filled:
            error = f'{col}: must be empty with remain'
        elif mode in ('add', 'remove', 'replace') and not filled:
            error = f'{col}: empty (fill a value; to clear use none)' if col in fw.CLEARABLE else f'{col}: empty'
        elif filled and not mode:
            error = f'{mode_name(col)}: required when {col} is filled'
        elif filled:
            modes[col] = mode
        if error:
            check['status'] = False
            check['msg'] += f' {error} +++'
    return modes


#service: application-default behaves like any
def list_change(col, mode, current, values, any_list, service, thing):
    anys = ('any', 'application-default') if service else ('any',)
    cur_any = any_list and (not current or (len(current) == 1 and current[0] in anys))
    word = (current[0] if current else 'any') if cur_any else None
    names = lambda items: ', '.join(f"'{v}'" for v in items)
    if mode == 'add':
        if service and 'application-default' in values:
            return None, f'{col}: application-default cannot be added, use replace', ''
        if any_list and values == ['any']:
            if cur_any and word == 'any':
                return None, f'{col}: is already any', ''
            return ['any'], '', f'{col} widened to any'
        if cur_any:
            return None, f'{col}: is {word}, cannot add (use replace)', ''
        already = [v for v in values if v in current]
        if already:
            return None, f'{col}: {names(already)} already in the {thing}', ''
        return current + values, '', ''
    if mode == 'remove':
        if any_list and 'any' in values:
            return None, (f'{col}: removing any keeps any, use replace' if cur_any else f'{col}: has no any'), ''
        if cur_any:
            return None, f'{col}: is {word}, nothing to remove', ''
        missing = [v for v in values if v not in current]
        if missing:
            return None, f'{col}: {names(missing)} not in the {thing}', ''
        result = [v for v in current if v not in values]
        if not result and any_list:
            return None, f'{col}: would be empty (= any), use replace any', ''
        if not result and col == 'Member':
            return None, 'Member: group would be empty', ''
        return result, '', ''
    old = ['any'] if cur_any and not current else current
    if set(values) == set(old):
        return current, '', ''
    warning = ''
    if any_list and values == ['any'] and not cur_any:
        warning = f'{col} widened to any'
    elif any_list and cur_any and word == 'any' and values != ['any']:
        warning = f'{col} narrowed from any'
    return values, '', warning


def nat_translation_change(fw, row, col, entry, check):
    keys = ('destination-translation', 'dynamic-destination-translation') if col.startswith('Destination') else ('source-translation',)
    built = getattr(fw, NAT_TYPE_COLUMNS[col])(row, check)
    old = {k: entry.get(k) for k in keys if k in entry}
    for k in keys:
        entry.pop(k, None)
    entry.update(built)
    return old != built, built


def reference_entry(fw, kind, name, refs):
    if kind in ('security_rule', 'nat_rule'):
        entry = {'@name': name, 'from': {'member': []}, 'to': {'member': []}, 'source': {'member': []},
                 'destination': {'member': []}, 'application': {'member': []}, 'service': {'member': []}}
    elif kind == 'address_group':
        entry = {'@name': name, 'static': {'member': []}}
    elif kind == 'service_group':
        entry = {'@name': name, 'members': {'member': []}}
    else:
        entry = {'@name': name}
    for col, values in refs.items():
        path = fw.EDIT_FIELDS[kind].get(col)
        if path:
            set_path(entry, path, list(values) if path[-1] == 'member' else values[0])
        elif col in NAT_TYPE_COLUMNS:
            entry.update(values)
    return entry


#Dry-run: rules from add sheets are not on the firewall yet
def rule_order(cache, ckey, job, host, loc, kind, dry_run):
    planned = job.get('order', {}).get((host, loc['@vsys'], kind))
    if not dry_run or planned is None:
        return cache.get(ckey, [])
    if ('dry_order', ckey) not in cache:
        cache[('dry_order', ckey)] = list(planned)
    return cache[('dry_order', ckey)]


def already_at(rules, name, where, ref):
    names = [r['@name'] for r in rules]
    if name not in names:
        return False
    i = names.index(name)
    if where == 'top':
        return i == 0
    if where == 'bottom':
        return i == len(names) - 1
    if ref not in names:
        return False
    return i == names.index(ref) + (1 if where == 'after' else -1)


#one edit sheet of the job
def automatic_edit(kind,username,password,input_excel_file_path,sheet,location_object=None,dict_device_token=None,log=None,dry_run=False,dry_ctx=None,device=None,job=None,**_):
    job = {} if job is None else job
    if dry_run and dry_ctx is None:
        dry_ctx = DryRunContext()
    if dict_device_token is None:
        dict_device_token = get_unique_device_and_token(username=username,password=password,file_content=input_excel_file_path,sheetname=sheet)
    rows = sheet_rows(read_sheet(input_excel_file_path, sheet))
    if device is not None:
        rows = [r for r in rows if str(r.get('Device-ip')) == device]

    final_result = ''
    cache = {}
    for row in rows:
        host = row['Device-ip']
        token = dict_device_token[host]
        fw = palib.api(host, token)
        getter, put_call, text, ctx_kind = fw.EDIT_KINDS[kind]
        loc = row_location(fw, row, location_object)
        ckey = (host, loc['@vsys'])
        check = {'status': True, 'msg': ''}
        warnings = []
        result = row_label(row) + 'Device-IP: ' + str(row['Device-ip']) + ' (' + vsys_label(fw, row, loc) + f') | {text}: ' + shown(row.get('Name')) + ' => '

        holder = {'entry': {}}
        if kind == 'tag':
            reason = '' if fields.empty(row.get('Name')) else fw.tag_name_error(row['Name'])
            if fields.empty(row.get('Name')) or reason:
                check['status'] = False
                check['msg'] += ' Name Input Error' + (f' ({reason})' if reason else '') + ' +++'
            else:
                holder['entry']['@name'] = str(row['Name'])
        else:
            fw.take_name(row, holder, check)
        name = holder['entry'].get('@name', '')

        editable = edit_columns(fw, kind)
        modes = row_modes(fw, kind, row, editable, check)
        clears = {c for c, m in modes.items() if m == 'replace' and c in fw.CLEARABLE and is_clear(fw, row.get(c))}
        checked = {k: v for k, v in row.items() if k not in clears}
        for col, reason in fw.check_row(kind, checked, edit=True):
            check['status'] = False
            check['msg'] += f' {col} Input Error ({reason}) +++'
        for col in clears:
            checked[col] = row[col]
        row = checked
        together = {'address': ('Type', 'Value'), 'service': ('Protocol', 'Destination-port')}.get(kind)
        if together and (together[0] in modes) != (together[1] in modes):
            check['status'] = False
            check['msg'] += f' {together[0]} and {together[1]} must be filled together +++'
        if kind == 'nat_rule':
            for type_col, used in (('Destination-translation-type', fw.NAT_DST_COLUMNS), ('Source-translation-type', fw.NAT_SRC_COLUMNS)):
                for c in sorted({c for cols in used.values() for c in cols}):
                    if not fields.empty(row.get(c)) and type_col not in modes:
                        check['status'] = False
                        check['msg'] += f' {c}: only with {type_col} replace +++'

        current, not_read = None, ''
        if check['status']:
            known, not_read = cached_list(cache, ckey, getattr(palib, getter), host, token, loc)
            pool = known + (dry_ctx.entries.get((host, loc['@vsys'], CREATE_KIND.get(kind, kind)), []) if dry_run else [])
            current = next((e for e in pool if e.get('@name') == name), None)
            if not_read:
                check['status'] = False
                check['msg'] += f' NOT EDITED: current {fw.KIND_TEXT[kind]} could not be read ({not_read}) +++'
            elif current is None and kind == 'tag' and name in fw.PREDEFINED_TAGS:
                check['status'] = False
                check['msg'] += f" tag '{name}' is a predefined tag of the firewall: cannot be edited +++"
            elif current is None:
                check['status'] = False
                check['msg'] += f" Reference Error: {fw.KIND_TEXT[kind]} '{name}' not found" + (' in shared' if is_shared(loc) else '') + ' +++'
            elif kind == 'address_group' and 'dynamic' in current:
                check['status'] = False
                check['msg'] += f" address group '{name}' is dynamic: not supported +++"

        new, changed, refs = None, False, {}
        if check['status']:
            new = copy.deepcopy(current)
            for key in fw.ENTRY_READ_ONLY:
                new.pop(key, None)
            made = {k: dry_ctx.entries.get((host, loc['@vsys'], k), []) if dry_run else [] for k in ('address_group', 'create_nat')}
            changed, refs = apply_row(fw, kind, row, modes, clears, new, check, warnings, host, token, loc, cache, made)

        where, ref, move_wanted = '', '', False
        if check['status'] and kind in ('security_rule', 'nat_rule') and not fields.empty(row.get('Position')):
            rules = rule_order(cache, ckey, job, host, loc, kind, dry_run)
            existing = set() if not_read else rules_before(job, host, loc, kind, known)
            where, ref = check_position(fw, row, existing, name, check, not_read, dry_run)
            where = where or 'bottom'
            if check['status']:
                if already_at(rules, name, where, ref):
                    warnings.append('already at that position, not moved')
                else:
                    move_wanted = True

        #firewall refuses ip-wildcard as NAT Source-ip / Destination-ip
        for key, col in (('source', 'Source-ip'), ('destination', 'Destination-ip')):
            if check['status'] and kind == 'nat_rule' and col in modes:
                wild = nat_wildcard_sources(fw, cache, host, token, loc, get_path(new, (key, 'member')), job)
                if wild:
                    check['status'] = False
                    check['msg'] += f' {col}: ' + ', '.join(f"'{w}'" for w in wild) + ' is an ip-wildcard address: not valid in a NAT rule +++'
        if check['status'] and kind == 'nat_rule' and 'Destination-translation-type' in modes:
            fqdn = nat_static_fqdn(fw, cache, host, token, loc, new, job)
            if fqdn:
                check['status'] = False
                check['msg'] += f" Dst-translate-address: '{fqdn}' is an fqdn address: not valid with destination static (use an IP address) +++"

        if dry_run and check['status'] and refs:
            ref_rs = dry_ctx.check(ctx_kind, host, token, loc, {'entry': reference_entry(fw, kind, name, refs)})
            if ref_rs:
                check['status'] = False
                check['msg'] += ref_rs

        if not check['status']:
            result += row_errors(check['msg'])
        elif not changed and not move_wanted:
            result += 'NOT EDITED: nothing to change (same values as on the firewall)' + ''.join(f' | Warning: {w}' for w in warnings)
        else:
            rs = None
            if changed:
                rs = fw.dry_answer('edit') if dry_run else getattr(palib, put_call)(host=host, token=token, object={'entry': new}, location_object=loc)
                if fw.is_success(rs):
                    if kind == 'address':
                        note_wildcard(job, host, loc, new)
                    if not dry_run:
                        known[:] = [new if e.get('@name') == name else e for e in known]
                    else:
                        remember_dry_edit(fw, dry_ctx, kind, host, loc, current, new, known)
                    result += fw.success_text(rs)
                else:
                    result += fw.error_text(rs)
            if move_wanted and (rs is None or fw.is_success(rs)):
                move = (lambda **k: fw.dry_answer('move')) if dry_run else getattr(palib, 'move_security_rule' if kind == 'security_rule' else 'move_nat_rule')
                rules = rule_order(cache, ckey, job, host, loc, kind, dry_run)
                move_rs = move_rule_to_position(fw, move, host, token, loc, rules, name, where, ref)
                result += (move_text(fw, where, ref, move_rs, dry_run) if rs is not None else move_text(fw, where, ref, move_rs, dry_run).removeprefix(' | '))
            if rs is None or fw.is_success(rs):
                if kind == 'security_rule' and changed and allows_all(new):
                    warnings.append(ALLOWS_ALL)
                if kind in ('security_rule', 'nat_rule') and changed:
                    added = {key: {'member': [v for v in refs.get(col, []) if isinstance(v, str)]}
                             for key, col in (('source', 'Source-ip'), ('destination', 'Destination-ip'))}
                    warnings += bare_ip_warnings(fw, cache, host, token, loc, added, job)
                if changed and kind in GROUP_MEMBERS and group_cycle(kind, pool, new):
                    warnings.append(group_cycle(kind, pool, new))
                if changed and kind in ('address', 'address_group', 'service', 'service_group'):
                    others = [e for e in pool if e.get('@name') != name]
                    dup = getattr(fw, fw.CREATE_KINDS[kind][3])(others, {'entry': new})
                    if dup.lower().startswith('duplicate value'):
                        warnings.append(dup)
                result += ''.join(f' | Warning: {w}' for w in warnings)
        final_result += result + '\n'
        if log:
            log(result)
    return final_result


def edit_columns(fw, kind):
    single_lists = {'nat_rule': ('Destination-zone',), 'security_rule': ('Profile-group',)}.get(kind, ())
    cols = {c: (p[-1] == 'member' and kind in MODE_KINDS and c not in single_lists) for c, p in fw.EDIT_FIELDS[kind].items()}
    extra = {'address': ('Type', 'Value'),
             'service': ('Protocol', 'Source-port', 'Destination-port', 'Override', 'Timeout', 'Halfclose-timeout', 'Timewait-timeout'),
             'nat_rule': tuple(NAT_TYPE_COLUMNS)}.get(kind, ())
    cols.update({c: False for c in extra})
    return cols


def apply_row(fw, kind, row, modes, clears, new, check, warnings, host, token, loc, cache, made):
    changed, refs = False, {}
    rule = kind in ('security_rule', 'nat_rule')
    thing = 'rule' if rule else ('group' if kind.endswith('group') else 'object')
    def fail(text):
        check['status'] = False
        check['msg'] += f' {text} +++'
    for col, mode in modes.items():
        if col in fw.EDIT_FIELDS[kind]:
            path = fw.EDIT_FIELDS[kind][col]
            current = get_path(new, path)
            if col in clears:
                value = None
            elif path[-1] == 'member' and edit_columns(fw, kind)[col]:
                values = str(row[col]).split(',')
                value, error, warning = list_change(col, mode, current, values, col in fw.ANY_LISTS,
                                                    col == 'Service' and kind == 'security_rule', thing)
                if error:
                    fail(error)
                    continue
                if warning:
                    warnings.append(warning)
                if mode != 'remove':
                    refs[col] = [v for v in values if v not in current or mode == 'replace']
            else:
                value = str(row[col])
                if col == 'Color':
                    value = fw.TAG_COLORS[value.strip().lower()]
                if path[-1] == 'member':
                    value = value.split(',') if col == 'Tag' else [value]
                refs[col] = value if isinstance(value, list) else [value]
            if col == 'Disable' and value != get_path(new, path):
                warnings.append(f"rule will be {'disabled' if value == 'yes' else 'enabled'}")
            if (value or None) != (current or None):
                set_path(new, path, value)
                changed = True
        elif kind == 'nat_rule' and col in NAT_TYPE_COLUMNS:
            done, built = nat_translation_change(fw, row, col, new, check)
            changed |= done
            refs[col] = built
    if kind == 'address' and 'Type' in modes and 'Value' in modes and check['status']:
        changed |= edit_address_value(fw, row, new, check, host, token, loc, cache, made)
    if kind == 'service' and check['status']:
        changed |= edit_service_protocol(fw, row, modes, clears, new, check)
    return changed, refs


#firewall accepts ip-wildcard in a static group / NAT source PUT but the commit fails
def edit_address_value(fw, row, new, check, host, token, loc, cache, made):
    kind, value = str(row['Type']), str(row['Value'])
    old = {t: new[t] for t in fw.ADDRESS_TYPES if t in new}
    if old == {kind: value}:
        return False
    if kind == 'ip-wildcard':
        groups, not_read = cached_list(cache, ('groups', host, loc['@vsys']), palib.get_Objects_AddressGroups, host, token, loc)
        inside = [g['@name'] for g in groups + made['address_group'] if new['@name'] in fw.member_set(g.get('static'))]
        if inside:
            check['status'] = False
            check['msg'] += f" Type: address object '{new['@name']}' is a member of group '{inside[0]}': ip-wildcard is not allowed in a static group +++"
            return False
        nats, not_read = cached_list(cache, ('nat_rules', host, loc['@vsys']), palib.get_nat_rule, host, token, loc)
        for key, col in (('source', 'Source-ip'), ('destination', 'Destination-ip')):
            used = [r['@name'] for r in nats + made['create_nat'] if new['@name'] in fw.member_set(r.get(key))]
            if used:
                check['status'] = False
                check['msg'] += f" Type: address object '{new['@name']}' is {col} of NAT rule '{used[0]}': ip-wildcard is not valid in a NAT rule +++"
                return False
    for t in fw.ADDRESS_TYPES:
        new.pop(t, None)
    new[kind] = value
    return True


#timeouts only with Override yes, Halfclose / Timewait only for tcp
def edit_service_protocol(fw, row, modes, clears, new, check):
    protocol = new.get('protocol') or {}
    cur_proto = next(iter(protocol), 'tcp')
    cur = protocol.get(cur_proto) or {}
    cur_override = cur.get('override') or {}
    cur_times = cur_override.get('yes') or {}
    def value(col, current):
        if col in clears:
            return None
        return str(row[col]) if col in modes else current
    proto = value('Protocol', cur_proto)
    port = value('Destination-port', cur.get('port'))
    source = value('Source-port', cur.get('source-port'))
    override = value('Override', 'yes' if 'yes' in cur_override else 'no')
    times = {k: value(c, cur_times.get(k)) for c, k in (('Timeout', 'timeout'), ('Halfclose-timeout', 'halfclose-timeout'),
                                                         ('Timewait-timeout', 'timewait-timeout'))}
    for c, k in (('Timeout', 'timeout'), ('Halfclose-timeout', 'halfclose-timeout'), ('Timewait-timeout', 'timewait-timeout')):
        if c in modes and c not in clears and k != 'timeout' and proto != 'tcp':
            check['status'] = False
            check['msg'] += f' {c} Input Error (only for tcp) +++'
        elif c in modes and c not in clears and override != 'yes':
            check['status'] = False
            check['msg'] += f' {c} Input Error (only with Override yes) +++'
    if not check['status']:
        return False
    sub = {'port': port}
    if source:
        sub['source-port'] = source
    if override == 'yes':
        sub['override'] = {'yes': {k: int(v) for k, v in times.items() if v is not None and (k == 'timeout' or proto == 'tcp')}}
    elif 'override' in cur:
        sub['override'] = {'no': {}}
    normal = lambda d: {k: (str(v) if not isinstance(v, dict) else {a: {x: str(y) for x, y in (b or {}).items()} for a, b in v.items()})
                        for k, v in d.items()}
    if proto == cur_proto and normal(sub) == normal(cur):
        return False
    new['protocol'] = {proto: sub}
    return True


def remember_dry_edit(fw, dry_ctx, kind, host, loc, current, new, known):
    known[:] = [new if e.get('@name') == new['@name'] else e for e in known]
    created = dry_ctx.entries.get((host, loc['@vsys'], CREATE_KIND.get(kind, kind)), [])
    created[:] = [new if e.get('@name') == new['@name'] else e for e in created]
    if kind == 'address':
        refused = fw.MEMBER_REFUSED.get('ip-wildcard')
        if 'ip-wildcard' in new and 'ip-wildcard' not in current:
            dry_ctx.add('refused', host, loc, new['@name'])
            dry_ctx.refused[(host, loc['@vsys'], new['@name'])] = refused
        elif 'ip-wildcard' in current and 'ip-wildcard' not in new:
            dry_ctx.created.get((host, loc['@vsys'], 'refused'), set()).discard(new['@name'])
            dry_ctx.refused.pop((host, loc['@vsys'], new['@name']), None)
            dry_ctx.add('address', host, loc, new['@name'])
