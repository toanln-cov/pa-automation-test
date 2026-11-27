# Field checks shared by every PAN-OS version class: the building blocks (length, choices, number range, ports, IP)
# and the engine that checks one Excel row. The LIMITS (max lengths, allowed values, patterns) are attributes of the
# version classes (v11_1.py: PanOS11_1), so a version with other limits only overrides those attributes.
# Each check returns '' (valid) or the reason shown after '<Column> Input Error'.
import ipaddress
import math
import re


#every member of list a is in list b
def is_subset(a, b):
    return all(elem in b for elem in a)

#mandatory cell: empty (NaN) -> ValueError, caught by the sheet code as '<Column> Input Error'
def check_nan_value(value):
    if isinstance(value, float) and math.isnan(value):
        raise ValueError('Empty Value')

def empty(value):
    return value is None or (isinstance(value, float) and math.isnan(value))

#characters not allowed, shown readable (newline / control characters as \n, \x07...), at most 5
def bad_chars(text, allowed):
    bad = []
    for c in text:
        if not allowed.fullmatch(c) and c not in bad:
            bad.append(c)
    shown = ' '.join(repr(c)[1:-1] if not c.isprintable() else c for c in bad[:5])
    return shown + (' ...' if len(bad) > 5 else '')

def text_max(limit):
    def check(value):
        return f'max {limit} characters, has {len(value)}' if len(value) > limit else ''
    return check

#length in bytes (UTF-8): the firewall counts bytes for descriptions, a letter with accents takes 2-3 bytes (BUG-61)
def bytes_max(limit):
    def check(value):
        size = len(value.encode('utf-8'))
        return f'max {limit} bytes (UTF-8, a letter with accents counts 2-3), has {size}' if size > limit else ''
    return check

def one_of(*choices):
    def check(value):
        return '' if value in choices else ' / '.join(choices)
    return check

def integer(low, high):
    def check(value):
        if not re.fullmatch(r'\d+', value) or not low <= int(value) <= high:
            return f'whole number {low}-{high}'
        return ''
    return check

def items(value):
    return value.split(',')

def list_of(item_max, max_items=None, what='name'):
    def check(value):
        parts = items(value)
        if max_items and len(parts) > max_items:
            return f'max {max_items} values, has {len(parts)}'
        long = [p for p in parts if len(p) > item_max]
        return f'{what} max {item_max} characters: {long[0][:20]}...' if long else ''
    return check

#port list: single port, range a-b (a <= b), comma separated
def ports(port_max):
    def check(value):
        for part in items(value):
            m = re.fullmatch(r'(\d+)(?:-(\d+))?', part)
            if not m or int(m.group(1)) > port_max or (m.group(2) and not int(m.group(1)) <= int(m.group(2)) <= port_max):
                return f'0-{port_max}: port, range a-b or comma list; wrong: {part[:20]}'
        return ''
    return check

def integer_or(word, low, high):
    def check(value):
        return '' if value == word else integer(low, high)(value)
    return check

def single(value):
    return 'one value only (no comma)' if ',' in value else ''

def interface_ip(value):
    if value == 'no':
        return ''
    try:
        ipaddress.ip_interface(value)
        return ''
    except ValueError:
        return 'IP address (with or without /mask) or no'

#value of an address object by its type
def address_value(kind, fqdn, fqdn_max):
    def check(value):
        try:
            if kind == 'ip-netmask':
                ipaddress.ip_network(value, strict=False)
            elif kind == 'ip-range':
                first, last = [ipaddress.ip_address(p) for p in value.split('-')]
                if first.version != last.version or first > last:
                    return 'first-last of the same IP version, first <= last'
            elif kind == 'ip-wildcard':
                ip, mask = value.split('/')
                ipaddress.IPv4Address(ip)
                if int(ipaddress.IPv4Address(mask)) >> 31:
                    return 'IPv4/mask, the mask must begin with a zero bit (e.g. 192.0.2.1/0.0.0.254)'
            elif kind == 'fqdn':
                if len(value) > fqdn_max or not fqdn.fullmatch(value):
                    return f'domain name: letters, digits, . _ -, max {fqdn_max}, no dot at the end'
            return ''
        except ValueError:
            return {'ip-netmask': 'IPv4 / IPv6 address, with or without /mask', 'ip-range': 'first-last IP addresses',
                    'ip-wildcard': 'IPv4/mask (e.g. 192.0.2.1/0.0.0.254)'}[kind]
    return check


#list cell -> (names, reason): spaces around the commas removed; an empty value (extra comma) or a repeated name is an
#error, the admin must send an exact list (FEAT-23); names compared exactly (case sensitive, like the firewall);
#any_words: written in lower case whatever the case typed ('Any' -> 'any')
def list_cell(value, any_words=()):
    parts = [p.strip() for p in str(value).split(',')]
    parts = [p.lower() if p.lower() in any_words else p for p in parts]
    if '' in parts:
        return parts, 'empty value (extra comma)'
    repeated = list(dict.fromkeys(p for p in parts if parts.count(p) > 1))
    if repeated:
        return parts, ', '.join(f"'{p}'" for p in repeated) + ' repeated'
    return parts, ''


#check one row: columns = {column: (check, lower case, optional)}; list_columns checked first (no empty / repeated
#values: error, FEAT-23), any_words {column: words} written in lower case; choices written in lower case. Invalid optional values are
#emptied so the sheet code does not report them a second time; empty mandatory values are reported by the sheet code.
#conditional(row) = columns that depend on another column, read after the lower case step. Return [(column, reason)].
def check_columns(row, columns, list_columns, any_words, conditional):
    errors = []
    for col in list_columns:
        if col in row and not empty(row[col]):
            parts, reason = list_cell(row[col], any_words.get(col, ()))
            row[col] = ','.join(parts)
            if reason:
                errors.append((col, reason))
    columns = dict(columns)
    for col, (check, lower, optional) in columns.items():
        if lower and col in row and not empty(row[col]):
            row[col] = str(row[col]).lower()
    columns.update(conditional(row))
    for col, (check, lower, optional) in columns.items():
        if col not in row or empty(row[col]) or any(c == col for c, _ in errors):
            continue
        value = str(row[col]).lower() if lower else str(row[col])
        row[col] = value
        reason = check(value)
        if reason:
            errors.append((col, reason))
            if optional:
                row[col] = float('nan')
    return errors
