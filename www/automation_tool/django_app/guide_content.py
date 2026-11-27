# Guide text per sheet (EN / VI), column tables come from template_spec.py
from . import template_spec as spec

REQUIRED = {spec.REQ: {'en': 'yes', 'vi': 'có'}, spec.COND: {'en': 'depends', 'vi': 'tùy trường hợp'}, spec.OPT: {'en': 'no', 'vi': 'không'}}

# Vietnamese column descriptions, EN uses the template hint
VI_COLUMNS = {
    'Device-ip': 'IP của firewall (IPv4).',
    'Name': 'Tên mới, tối đa 63 ký tự (chữ, số, dấu cách, . _ -), bắt đầu bằng chữ hoặc số, không được là any (mọi kiểu chữ).',
    ('edit', 'Name'): 'Tên của entry ĐÃ CÓ cần sửa (không đổi tên được).',
    ('add_tag', 'Name'): 'Tên tag mới, tối đa 127 ký tự. Không tạo được tag có sẵn của firewall (Sanctioned).',
    ('edit_tag', 'Name'): 'Tên tag ĐÃ CÓ cần sửa (không đổi tên được). Không sửa được tag có sẵn của firewall (Sanctioned).',
    ('add_address_object', 'Value'): 'Giá trị theo Type: 192.0.2.1, 192.0.2.0/24, 192.0.2.1-192.0.2.9, www.example.com. Không nhận giá trị bao toàn bộ địa chỉ (0.0.0.0/0, ::/0): dùng any của firewall.',
    ('add_address_group', 'Member'): 'Address object (ip-netmask / ip-range / fqdn) hoặc address group, cách nhau dấu phẩy. Không nhận: EDL, region, address ip-wildcard, any, IP trần.',
    ('add_service_object', 'Protocol'): 'tcp | udp. ICMP: dùng application icmp / ping trong rule. Không hỗ trợ SCTP.',
    ('add_service_group', 'Member'): 'Service, service group, service-http, service-https. Không nhận: any, application-default.',
    ('add_security_rule', 'Source-ip'): 'Tên address / group, mã vùng (VN), any đứng một mình, hoặc IP / CIDR / dải IP trần (cảnh báo: không phải object).',
    ('add_security_rule', 'Destination-ip'): 'Tên address / group, mã vùng (VN), any đứng một mình, hoặc IP / CIDR / dải IP trần (cảnh báo: không phải object).',
    ('add_security_rule', 'Source-user'): 'User / group, hoặc pre-logon / known-user / unknown (đứng một mình), hoặc any. Dry-run không kiểm tên user.',
    ('add_nat_rule', 'Destination-interface'): 'Một interface hoặc any, ví dụ ethernet1/1. Dry-run không kiểm interface.',
    ('edit_address_object', 'Type'): 'Type và Value luôn điền cùng nhau: ip-netmask | ip-range | ip-wildcard | fqdn. Không đổi sang ip-wildcard khi address đang ở static group.',
    ('edit_address_object', 'Tag'): 'Danh sách tag mới đầy đủ (thay danh sách cũ).',
    ('edit_service_object', 'Tag'): 'Danh sách tag mới đầy đủ (thay danh sách cũ).',
    ('edit_service_object', 'Protocol'): 'Protocol và Destination-port luôn điền cùng nhau: tcp | udp.',
    ('edit_service_object', 'Destination-port'): 'Protocol và Destination-port luôn điền cùng nhau; danh sách cổng mới đầy đủ.',
    ('edit_service_object', 'Timeout'): 'Chỉ khi Override yes (Override trống = giá trị hiện tại): giây 1-604800.',
    ('edit_address_group', 'Name'): 'Tên address group tĩnh ĐÃ CÓ cần sửa. Không hỗ trợ dynamic group.',
    ('edit_address_group', 'Member'): 'Address object / group. Group không được rỗng.',
    ('edit_service_group', 'Member'): 'Service / group. Group không được rỗng.',
    ('edit_security_rule', 'Service'): 'Tên service / group, application-default hoặc any. application-default và any phải đứng một mình: muốn đổi thì dùng replace.',
    ('edit_security_rule', 'Disable'): 'yes = tắt rule, no = bật rule. Install cần tick ô "Allow disabling / enabling rules".',
    ('edit_nat_rule', 'Disable'): 'yes = tắt rule, no = bật rule. Install cần tick ô "Allow disabling / enabling rules".',
    ('edit_nat_rule', 'Destination-translation-type'): 'static | dynamic | none, kèm mọi cột của kiểu mới (các cột đó không sửa riêng được).',
    ('edit_nat_rule', 'Source-translation-type'): 'none | dynamic-ip-and-port with ... | dynamic-ip | static-ip, kèm mọi cột của kiểu mới.',
    'Color': 'Tên màu như trên web UI firewall: Red, Green, Light Green... (trống = không màu).',
    'Comments': 'Ghi chú, tối đa 1023 byte (chữ có dấu tính 2-3 byte).',
    'Type': 'ip-netmask | ip-range | ip-wildcard | fqdn.',
    'Value': 'Giá trị theo Type: 192.0.2.1, 192.0.2.0/24, 192.0.2.1-192.0.2.9, www.example.com.',
    'Description': 'Mô tả, tối đa 1023 byte (object) / 1024 byte (rule).',
    'Tag': 'Tag đã có (trên firewall hoặc tạo ở sheet add_tag cùng file), cách nhau dấu phẩy.',
    'Vsys': 'vsys1, vsys2... hoặc shared (không phân biệt hoa thường). Rule luôn ở vsys.',
    'Member': 'Tên object / group, cách nhau dấu phẩy.',
    'Protocol': 'tcp | udp.',
    'Source-port': 'Cổng nguồn, ví dụ 1024-65535 (trống = any).',
    'Destination-port': 'Cổng đích: 443, 80,443 hoặc 1000-2000.',
    'Override': 'yes = dùng các cột timeout; trống / no = timeout mặc định.',
    'Timeout': 'Giây 1-604800, chỉ khi Override = yes.',
    'Halfclose-timeout': 'Giây 1-604800, chỉ khi Override = yes và tcp.',
    'Timewait-timeout': 'Giây 1-600, chỉ khi Override = yes và tcp.',
    'Position': 'top | bottom | before | after (trống = bottom; sheet edit: trống = không di chuyển).',
    'Reference-rule': 'Rule ĐÃ CÓ trên firewall, dùng với before / after.',
    'Source-zone': 'Zone nguồn hoặc any.',
    'Destination-zone': 'Zone đích hoặc any.',
    ('add_nat_rule', 'Source-ip'): 'Tên address / group, mã vùng (VN) hoặc any. Không nhận address ip-wildcard.',
    ('edit_nat_rule', 'Source-ip'): 'Tên address / group, mã vùng (VN) hoặc any. Không nhận address ip-wildcard.',
    ('add_nat_rule', 'Destination-zone'): 'MỘT zone (NAT không nhận any).',
    ('edit_nat_rule', 'Destination-zone'): 'MỘT zone (NAT không nhận any).',
    ('add_nat_rule', 'Disable'): 'yes | no (bắt buộc).',
    'Source-ip': 'Tên address / group, mã vùng (VN) hoặc any.',
    'Destination-ip': 'Tên address / group, mã vùng (VN) hoặc any.',
    'Application': 'Ứng dụng hoặc any, ví dụ ssl,web-browsing.',
    'Service': 'Tên service / group, application-default hoặc any (đứng một mình). NAT: một giá trị.',
    'Action': 'allow | deny | drop | reset-client | reset-server | reset-both.',
    'Disable': 'yes | no (add: trống = no; edit: yes = tắt, no = bật rule).',
    'Profile-group': 'Một security profile group.',
    'Log-forwarding': 'Log forwarding profile.',
    'Log-start': 'yes | no (trống = no).',
    'Log-end': 'yes | no (trống = yes).',
    'Url-category': 'URL category hoặc any.',
    'Source-user': 'User / group, hoặc pre-logon / known-user / unknown (đứng một mình), hoặc any.',
    'Destination-interface': 'Một interface hoặc any, ví dụ ethernet1/1.',
    'Destination-translation-type': 'static | dynamic | none (NAT đích).',
    'Dns-rewrite': 'Bắt buộc khi NAT đích static: no | forward | reverse.',
    'Distribution': 'Bắt buộc khi NAT đích dynamic: round-robin | source-ip-hash | ip-modulo | ip-hash | least-sessions.',
    'Dst-translate-address': 'Bắt buộc khi NAT đích static / dynamic: MỘT tên address hoặc IP.',
    'Translate-port': 'Bắt buộc khi NAT đích static / dynamic: cổng 1-65535, hoặc all (giữ cổng).',
    'Source-translation-type': 'none | dynamic-ip-and-port with ... | dynamic-ip | static-ip (NAT nguồn).',
    'static-bi-directional': 'Bắt buộc khi NAT nguồn static-ip: yes | no.',
    'Src-translate-address': 'Bắt buộc khi NAT nguồn Translate address / dynamic-ip (tên hoặc IP, cách nhau dấu phẩy) hoặc static-ip (MỘT).',
    'Src-translate-interface': 'Bắt buộc khi NAT nguồn Interface address IP / Floating IP: MỘT interface.',
    'Src-translate-address-ip': 'Bắt buộc khi NAT nguồn Interface address IP / Floating IP: IP của interface, hoặc no.',
    ('edit_nat_rule', 'Dns-rewrite'): 'Chỉ khi Destination-translation-type = replace static: no | forward | reverse.',
    ('edit_nat_rule', 'Distribution'): 'Chỉ khi Destination-translation-type = replace dynamic.',
    ('edit_nat_rule', 'Dst-translate-address'): 'Chỉ khi Destination-translation-type = replace static / dynamic: MỘT tên address hoặc IP.',
    ('edit_nat_rule', 'Translate-port'): 'Chỉ khi Destination-translation-type = replace static / dynamic: cổng, hoặc all.',
    ('edit_nat_rule', 'static-bi-directional'): 'Chỉ khi Source-translation-type = replace static-ip: yes | no.',
    ('edit_nat_rule', 'Src-translate-address'): 'Chỉ khi Source-translation-type = replace Translate address / dynamic-ip / static-ip.',
    ('edit_nat_rule', 'Src-translate-interface'): 'Chỉ khi Source-translation-type = replace Interface address IP / Floating IP.',
    ('edit_nat_rule', 'Src-translate-address-ip'): 'Chỉ khi Source-translation-type = replace Interface address IP / Floating IP: IP hoặc no.',
    'Nat-type': 'ipv4 (nat64 / nptv6 tool không hỗ trợ).',
    'Active-active-device-binding': 'primary | both | 0 | 1, chỉ dùng khi HA active-active. Trống = primary.',
    'Group-tag': 'MỘT tag đã có.',
}
VI_EDIT_PREFIX = 'Trống = giữ nguyên. '


def column_rows(sheet, lang):
    editable = spec.editable(sheet)
    rows = []
    for c in spec.sheet_columns(sheet):
        name = c['name']
        if name.startswith('Edit-') and name.endswith('-mode'):
            target = name[5:-5]
            modes = ' · '.join(spec.MODES[editable[target]])
            rows.append({'name': name, 'required': {'en': f'with {target}', 'vi': f'khi điền {target}'}[lang], 'choices': modes,
                         'text': {'en': f'How {target} is applied. Empty / remain = kept.',
                                  'vi': f'Cách áp dụng {target}. Trống / remain = giữ nguyên.'}[lang]})
            continue
        if lang == 'en':
            text = c['hint'].removeprefix('EXAMPLE ROW - replace or delete before upload. ')
        else:
            edit = sheet.startswith('edit_')
            text = VI_COLUMNS.get((sheet, name)) or VI_COLUMNS.get(('edit', name) if edit else name) or VI_COLUMNS.get(name, '')
            if edit and name in editable:
                text = VI_EDIT_PREFIX + text + (' none = xóa.' if name in spec.clearable(sheet) else '')
        rows.append({'name': name, 'required': REQUIRED[c['level']][lang], 'choices': (c['choices'] or '').replace(',', ' · '), 'text': text})
    return rows


def t(en, vi):
    return {'en': en, 'vi': vi}


# results common to all sheets

S = {}

S['add_tag'] = {
    'synopsis': t('Create tags. Runs first, so objects and rules of the same file can use the new tags.',
                  'Tạo tag. Chạy đầu tiên, nên object và rule trong cùng file dùng được tag mới.'),
    'notes': [],
    'examples': [(t('New tag with a color', 'Tag mới có màu'), 'Name = PROD · Color = Light Green · Vsys = vsys1', t('tag PROD, color Light Green', 'tag PROD, màu Light Green')),
                 (t('Tag for every vsys', 'Tag dùng cho mọi vsys'), 'Name = PCI · Vsys = shared', t('tag PCI in shared', 'tag PCI ở shared'))],
}
S['add_address_object'] = {
    'synopsis': t('Create address objects (ip-netmask, ip-range, ip-wildcard, fqdn).', 'Tạo address object (ip-netmask, ip-range, ip-wildcard, fqdn).'),
    'notes': [],
    'examples': [(t('Host', 'Một máy'), 'Name = WEB01 · Type = ip-netmask · Value = 192.0.2.10', t('address WEB01', 'address WEB01')),
                 (t('Subnet with a tag', 'Dải mạng có tag'), 'Type = ip-netmask · Value = 192.0.2.0/24 · Tag = PROD', t('address with tag PROD', 'address có tag PROD')),
                 (t('Range', 'Dải IP'), 'Type = ip-range · Value = 192.0.2.1-192.0.2.9', t('address ip-range', 'address ip-range')),
                 (t('Domain', 'Tên miền'), 'Type = fqdn · Value = www.example.com', t('address fqdn', 'address fqdn')),
                 (t('Everything', 'Toàn bộ'), 'Value = 0.0.0.0/0', t("✗ Value Input Error (covers all addresses: use 'any')", "✗ Value Input Error (covers all addresses: use 'any')"))],
}
S['add_address_group'] = {
    'synopsis': t('Create static address groups (members = address objects / address groups).', 'Tạo address group tĩnh (member = address object / address group).'),
    'notes': [],
    'examples': [(t('Group of 2 servers', 'Group 2 server'), 'Name = WEB_GRP · Member = WEB01, WEB02', t('group WEB_GRP', 'group WEB_GRP')),
                 (t('Group of groups', 'Group lồng group'), 'Member = WEB_GRP, DB_GRP', t('nested group', 'group lồng')),
                 (t('EDL as member', 'EDL làm member'), 'Member = MY_EDL', t("✗ member 'MY_EDL' is an EDL: a static address group only accepts ...", "✗ member 'MY_EDL' is an EDL: a static address group only accepts ..."))],
}
S['add_service_object'] = {
    'synopsis': t('Create tcp / udp services.', 'Tạo service tcp / udp.'),
    'notes': [],
    'examples': [(t('HTTPS on 8443', 'HTTPS cổng 8443'), 'Name = TCP_8443 · Protocol = tcp · Destination-port = 8443', t('service TCP_8443', 'service TCP_8443')),
                 (t('Long session', 'Phiên dài'), 'Override = yes · Timeout = 7200', t('service with timeout 7200', 'service timeout 7200')),
                 (t('ICMP', 'ICMP'), 'Protocol = icmp', t('✗ Protocol Input Error (tcp / udp: for ICMP use Application icmp / ping in the rule)', '✗ Protocol Input Error (tcp / udp: for ICMP use ...)'))],
}
S['add_service_group'] = {
    'synopsis': t('Create service groups.', 'Tạo service group.'),
    'notes': [],
    'examples': [(t('Web ports', 'Cổng web'), 'Name = WEB_SVC · Member = TCP_8443, service-https', t('group WEB_SVC', 'group WEB_SVC'))],
}
S['add_security_rule'] = {
    'synopsis': t('Create security rules, at the position you choose.', 'Tạo security rule, ở vị trí bạn chọn.'),
    'notes': [t('Several new rows on the same anchor: "before X" and "bottom" keep the file order; "after X" and "top" reverse it. For a block in file order use before <the existing rule just below>.',
                'Nhiều dòng mới cùng một mốc: "before X" và "bottom" giữ thứ tự file; "after X" và "top" bị đảo ngược. Muốn một khối đúng thứ tự file: dùng before <rule có sẵn ngay bên dưới>.')],
    'examples': [(t('Allow web from LAN', 'Cho LAN ra web'), 'Source-zone = Inside · Destination-zone = Outside · Source-ip = LAN_NET · Destination-ip = any · Application = ssl,web-browsing · Service = application-default · Action = allow',
                  t('rule at the bottom', 'rule ở cuối')),
                 (t('Block above an existing rule', 'Chặn ở trên một rule có sẵn'), 'Action = deny · Position = before · Reference-rule = Allow-Web', t("rule just above 'Allow-Web'", "rule ngay trên 'Allow-Web'")),
                 (t('Bare IP without an object', 'IP trần chưa có object'), 'Source-ip = 192.0.2.77', t("created + Warning: source '192.0.2.77' is not an address object: the firewall uses it as a bare IP", "tạo được + Warning: source '192.0.2.77' is not an address object: the firewall uses it as a bare IP"))],
}
S['add_nat_rule'] = {
    'synopsis': t('Create NAT rules (source NAT, destination NAT, both, or no-NAT).', 'Tạo NAT rule (NAT nguồn, NAT đích, cả hai, hoặc no-NAT).'),
    'notes': [],
    'examples': [(t('Source NAT to a public IP', 'NAT nguồn ra IP public'), 'Destination-translation-type = none · Source-translation-type = dynamic-ip-and-port with Translate address · Src-translate-address = 192.0.2.120',
                  t('SNAT rule', 'rule SNAT')),
                 (t('Publish a server (DNAT)', 'Public một server (DNAT)'), 'Destination-translation-type = static · Dns-rewrite = no · Dst-translate-address = WEB01 · Translate-port = 443 · Source-translation-type = none',
                  t('DNAT rule', 'rule DNAT')),
                 (t('Wrong column for the type', 'Cột sai kiểu'), 'Destination-translation-type = dynamic · Dns-rewrite = no', t('✗ Dns-rewrite Input Error (not used with dynamic)', '✗ Dns-rewrite Input Error (not used with dynamic)'))],
}
S['edit_tag'] = {
    'synopsis': t('Change the color or comments of an existing tag.', 'Đổi màu hoặc ghi chú của tag đã có.'),
    'notes': [],
    'examples': [(t('New color', 'Đổi màu'), 'Name = PROD · Color = Red', t('color Red', 'màu Red')),
                 (t('Remove the comments', 'Xóa ghi chú'), 'Comments = none', t('no comments', 'không còn ghi chú'))],
}
S['edit_address_object'] = {
    'synopsis': t('Change the value, description or tags of an existing address object.', 'Đổi giá trị, mô tả hoặc tag của address object đã có.'),
    'notes': [],
    'examples': [(t('Server moved to a new IP', 'Server đổi IP'), 'Name = WEB01 · Type = ip-netmask · Value = 192.0.2.20', t('WEB01 = 192.0.2.20', 'WEB01 = 192.0.2.20')),
                 (t('Only the description', 'Chỉ đổi mô tả'), 'Description = moved to DC2', t('value kept', 'giá trị giữ nguyên')),
                 (t('Only the Type', 'Chỉ điền Type'), 'Type = ip-range', t('✗ Type and Value must be filled together', '✗ Type and Value must be filled together'))],
}
S['edit_address_group'] = {
    'synopsis': t('Add / remove members of an existing static group, replace its member list, change Description or Tag.',
                  'Thêm / bỏ member của group tĩnh đã có, thay cả danh sách member, đổi Description hoặc Tag.'),
    'notes': [],
    'examples': [(t('Add 1 server', 'Thêm 1 server'), 'Member = SRV3 · Edit-Member-mode = add', t('SRV1, SRV2, SRV3', 'SRV1, SRV2, SRV3')),
                 (t('Add a server created in the same file', 'Thêm server tạo trong cùng file'), t('Member = SRV9 (row in add_address_object) · add', 'Member = SRV9 (có dòng ở sheet add_address_object) · add'), t('SRV1, SRV2, SRV9', 'SRV1, SRV2, SRV9')),
                 (t('Remove 1 server', 'Bỏ 1 server'), 'Member = SRV2 · remove', t('SRV1', 'SRV1')),
                 (t('Swap SRV2 → SRV4', 'Đổi SRV2 → SRV4'), t('2 rows: SRV4 add, then SRV2 remove', '2 dòng: SRV4 add, rồi SRV2 remove'), t('SRV1, SRV4', 'SRV1, SRV4')),
                 (t('Replace the list', 'Thay cả danh sách'), 'Member = SRV5, SRV6 · replace', t('SRV5, SRV6', 'SRV5, SRV6')),
                 (t('Remove every member', 'Bỏ hết member'), 'Member = SRV1, SRV2 · remove', t('✗ Member: group would be empty', '✗ Member: group would be empty'))],
    'intro': t('Group WEB_GRP currently has SRV1, SRV2.', 'Group WEB_GRP đang có SRV1, SRV2.'),
}
S['edit_service_object'] = {
    'synopsis': t('Change ports, protocol, timeouts, description or tags of an existing service.', 'Đổi cổng, protocol, timeout, mô tả hoặc tag của service đã có.'),
    'notes': [],
    'examples': [(t('Change the port', 'Đổi cổng'), 'Protocol = tcp · Destination-port = 9443', t('port 9443', 'cổng 9443')),
                 (t('Longer timeout', 'Tăng timeout'), 'Timeout = 7200 (service already Override yes)', t('timeout 7200', 'timeout 7200'))],
}
S['edit_service_group'] = {
    'synopsis': t('Add / remove members of an existing service group, or replace the list.', 'Thêm / bỏ member của service group đã có, hoặc thay cả danh sách.'),
    'notes': [],
    'examples': [(t('Add a service', 'Thêm service'), 'Member = TCP_9443 · Edit-Member-mode = add', t('member added', 'đã thêm member'))],
}
S['edit_security_rule'] = {
    'synopsis': t('Change an existing security rule: add / remove values in its lists, replace single values, move it, disable / enable it.',
                  'Sửa security rule đã có: thêm / bỏ giá trị trong các danh sách, thay giá trị đơn, di chuyển, tắt / bật rule.'),
    'notes': [t('A cell that is any cannot get more names (use replace); add any → the cell becomes any + warning; removing every name → error (empty = any).',
                'Ô đang là any không thêm được tên (dùng replace); add any → ô thành any + cảnh báo; bỏ hết tên → lỗi (rỗng = any).')],
    'intro': t('Rule R1 currently has Source-ip H1.', 'Rule R1 đang có Source-ip H1.'),
    'examples': [(t('Add a source', 'Thêm nguồn'), 'Source-ip = H2 · Edit-Source-ip-mode = add', t('H1, H2', 'H1, H2')),
                 (t('Add a new address created in the same file', 'Thêm address mới tạo trong cùng file'), 'Source-ip = NEW01 · add', t('H1, NEW01', 'H1, NEW01')),
                 (t('Open to any', 'Mở ra any'), 'Source-ip = any · add', t('any + Warning: Source-ip widened to any', 'any + Warning: Source-ip widened to any')),
                 (t('Remove the last source', 'Bỏ nguồn cuối cùng'), 'Source-ip = H1 · remove', t('✗ Source-ip: would be empty (= any), use replace any', '✗ Source-ip: would be empty (= any), use replace any')),
                 (t('Move to the top', 'Đưa lên đầu'), 'Position = top', t('moved to top', 'moved to top')),
                 (t('Disable the rule', 'Tắt rule'), t('Disable = yes · Edit-Disable-mode = replace (+ box on the form)', 'Disable = yes · Edit-Disable-mode = replace (+ tick ô trên form)'), t('disabled + Warning: rule will be disabled', 'tắt + Warning: rule will be disabled')),
                 (t('Remove the security profile', 'Bỏ security profile'), 'Profile-group = none · replace', t('no profile', 'không còn profile'))],
}
S['edit_nat_rule'] = {
    'synopsis': t('Change an existing NAT rule: zones, addresses, service, translation, move, disable / enable.', 'Sửa NAT rule đã có: zone, địa chỉ, service, translation, di chuyển, tắt / bật.'),
    'notes': [],
    'examples': [(t('Change the DNAT port', 'Đổi cổng DNAT'), 'Destination-translation-type = static · replace · Dns-rewrite = no · Dst-translate-address = WEB01 · Translate-port = 8443',
                  t('new destination translation', 'translation đích mới')),
                 (t('Port alone', 'Chỉ điền cổng'), 'Translate-port = 8443', t('✗ Translate-port: only with Destination-translation-type replace', '✗ Translate-port: only with Destination-translation-type replace'))],
}

LIMITS = [
    t('No delete: deleting can have a large impact, so this version of the tool only creates and edits. Delete by hand on the firewall.',
      'Không xóa: Hành động xoá có thể gây ảnh hưởng lớn, cho nên Tool phiên bản này mới chỉ hỗ trợ tạo và sửa. Hành động xóa khuyến nghị làm thủ công trên firewall.'),
    t('Address groups: static address groups only. Dynamic address groups are not supported.',
      'Address Group: Chỉ hỗ trợ static address group. Không hỗ trợ dynamic address group.'),
    t('Services: tcp / udp only.', 'Service: chỉ hỗ trợ tcp/udp.'),
    t('NAT: ipv4 only (no nat64 / nptv6). Source NAT persistent dynamic-ip-and-port and the fallback of dynamic-ip-and-port / dynamic-ip are not supported.',
      'NAT: chỉ hỗ trợ ipv4 (không nat64 / nptv6). Không hỗ trợ NAT nguồn persistent dynamic-ip-and-port và fallback của dynamic-ip-and-port / dynamic-ip.'),
    t('Security rule: the multicast destination zone is not supported.', 'Security rule: không hỗ trợ destination zone multicast.'),
    t('Other kinds (EDL, application, profile, zone, interface, schedule...) cannot be created / edited.',
      'Các loại khác (EDL, application, profile, zone, interface, schedule...) không tạo / sửa được'),
    t('The Dry-run checks most cases before the Install, but not 100%: some special cases are only known at Install. Run a Dry-run before the Install to reduce errors.',
      'Dry-run kiểm tra được phần lớn các trường hợp trước khi install, nhưng không phải 100% các trường hợp. Một số trường hợp đặc biệt vẫn cần install mới biết được kết quả. Recommend chạy Dry-Run trước khi install để giảm thiểu lỗi.'),
    t('Not for firewalls managed by Panorama, to avoid configuration conflicts.', 'Không dùng cho firewall do Panorama quản lý để tránh xung đột về cấu hình.'),
    t('HA firewalls: fill only the IP of the active firewall.', 'Với firewall chạy HA: Chỉ cần điền ip của firewall active.'),
    t('Install does not commit: the tool only writes the candidate config, to keep the impact as low as possible. Commit check and commit are on the separate Commit tab, after the admin has reviewed the candidate config.',
      'Install không tự commit: Tool chỉ tạo cấu hình vào candidate và không commit để giảm thiểu tối đa ảnh hưởng. Tool hỗ trợ commit check và commit ở Tab commit riêng sau khi admin đã review candidate config.'),
]


#context of the Guide page for one language
def guide_context(lang):
    sheets = []
    for name in spec.SHEET_ORDER:
        d = S[name]
        sheets.append({'name': name, 'synopsis': d['synopsis'][lang], 'intro': d.get('intro', {}).get(lang, ''),
                       'columns': column_rows(name, lang), 'notes': [n[lang] for n in d['notes']],
                       'examples': [{'case': c[lang], 'cells': cells if isinstance(cells, str) else cells[lang], 'result': r[lang]} for c, cells, r in d['examples']],
                       'add': name.startswith('add_')})
    return {'sheets': sheets, 'limits': [x[lang] for x in LIMITS]}
