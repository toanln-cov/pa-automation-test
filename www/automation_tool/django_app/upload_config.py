import pandas as pd
from io import BytesIO
from django.http import HttpResponse
from django.shortcuts import render, redirect
from django.views.decorators.http import require_POST
from django.contrib.auth.decorators import login_required
from .lib_tool import PA_tool
from .lib_tool import edit_sheet
from . import job_runner
from . import template_spec
from .file_check import check_structure
from .security import xlsx_error
import logging

logger = logging.getLogger('django_app.upload')

# sheet run order: all adds, then all edits
SHEETS = {
    'add_tag': ('tag', 'Add tag result'),
    'add_address_object': ('address', 'Add address object result'),
    'add_address_group': ('address_group', 'Add address group result'),
    'add_service_object': ('service', 'Add service object result'),
    'add_service_group': ('service_group', 'Add service group result'),
    'add_security_rule': ('security_rule', 'Add Security Rule result'),
    'add_nat_rule': ('nat_rule', 'Add Nat Rule result'),
    'edit_tag': ('tag', 'Edit tag result'),
    'edit_address_object': ('address', 'Edit address object result'),
    'edit_address_group': ('address_group', 'Edit address group result'),
    'edit_service_object': ('service', 'Edit service object result'),
    'edit_service_group': ('service_group', 'Edit service group result'),
    'edit_security_rule': ('security_rule', 'Edit Security Rule result'),
    'edit_nat_rule': ('nat_rule', 'Edit Nat Rule result'),
}
DISABLE_SHEETS = ('edit_security_rule', 'edit_nat_rule')

#unexpected error: generic message on the form, details in server log
@login_required
@require_POST
def palo_alto_upload(request):
    try:
        return _palo_alto_upload(request)
    except Exception:
        logger.exception('upload failed')
        return render(request, 'pages/palo_alto.html',{'error': 'Unexpected error while preparing the job. Nothing was sent to the firewalls. Details are in the server log.'})


def _palo_alto_upload(request):
    username = request.POST.get('username', '')
    password = request.POST.get('password', '')
    mode = request.POST.get('config_type_value', '')
    # Stop duplicated: Install only
    stop_duplicate = mode == 'install' and request.POST.get('stop_duplicate', '') == 'stop_duplicate'
    # disable / enable rows: Install only when the box is ticked
    allow_disable = request.POST.get('allow_disable', '') == 'allow_disable'
    file = request.FILES.get('file')

    response = HttpResponse()
    if mode not in ('install', 'dry-run') and mode:
        return render(request, 'pages/palo_alto.html',{'error': f'Unknown configure type: {mode[:30]}'})
    if not (mode and file and username and password):
        text = "Please fill full configure information"
        response = HttpResponse(text, content_type='text/plain')
        return response


    # only .xlsx, old .xls rejected
    head = file.read(8)
    file.seek(0)
    if not file.name.lower().endswith('.xlsx') or not head.startswith(b'PK'):
        return render(request, 'pages/palo_alto.html',{'error': 'Only .xlsx files are supported: open the file in Excel and save it as .xlsx (Excel Workbook).'})
    problem = xlsx_error(file)
    if problem:
        return render(request, 'pages/palo_alto.html',{'error': problem})

    sheet_list = []
    try:
        sheet_list = pd.ExcelFile(file).sheet_names
    except Exception as e:
        logger.warning('cannot read uploaded excel: %r', e)
        return render(request, 'pages/palo_alto.html',{'error': 'Cannot read the Excel file (corrupted, password protected or not an .xlsx workbook).'})

    structure_errors = check_structure(file, sheet_list)
    if structure_errors:
        return render(request, 'pages/palo_alto.html',{'error': 'The file does not follow the template:\n- ' + '\n- '.join(structure_errors)})

    # sheets in template order, workbook position ignored
    op_sheets = [sh for sh in template_spec.SHEET_ORDER if sh in sheet_list]
    if not op_sheets:
        return render(request, 'pages/palo_alto.html',{'error': 'No supported sheet in the file. Use the template of the Configure page.'})

    # rules disabled / enabled by the file need the confirmation box
    if mode == 'install' and not allow_disable:
        toggled = []
        for sheet in DISABLE_SHEETS:
            if sheet in op_sheets and 'Disable' in PA_tool.read_sheet(file, sheet):
                df = PA_tool.read_sheet(file, sheet)
                toggled += [f"{sheet} row {i + 2} ({r.get('Name')}: Disable {str(r['Disable']).strip().lower()})"
                            for i, r in df.iterrows() if not PA_tool.check_nan_value_no_except(r['Disable'])]
        if toggled:
            listed = ', '.join(toggled[:10]) + (f' ... (+{len(toggled) - 10})' if len(toggled) > 10 else '')
            return render(request, 'pages/palo_alto.html',{'error': f'The file disables / enables rules ({listed}). Tick "Allow disabling / enabling rules" '
                          'to accept, or empty the Disable column. Nothing was sent.'})

    # checked before contacting firewalls, each keygen creates an API key
    disk_error = job_runner.free_space_error()
    if disk_error:
        return render(request, 'pages/palo_alto.html',{'error': disk_error})
    running = job_runner.running_job_id()
    if running:
        return render(request, 'pages/palo_alto.html',{'running_job': running, 'error': 'Another job is running (see the link above). Please wait until it finished.'})

    # one token per device, reused for the whole request
    list_all_device = []
    for sheet_i in op_sheets:
        df = PA_tool.read_sheet(file, sheet_i)
        list_all_device += df.to_dict(orient='records')
    dict_device_token, token_failures = PA_tool.get_device_tokens(username,password,list_all_device)

    #firewall without key / version: only its part fails
    if not dict_device_token:
        return render(request, 'pages/palo_alto.html',{'error': '\n'.join(token_failures.values())})
    firewalls = list(dict.fromkeys(row['Device-ip'] for row in list_all_device))


    if mode in ('install', 'dry-run'):
        #keep file content in memory, upload is closed after the response
        file.seek(0)
        file_content = BytesIO(file.read())

        # one firewall after the other, in file order
        #   install: version, lock, backup, sheets, unlock
        #   dry-run: version, sheets
        # lock / backup failed: nothing written to that firewall, job goes on
        state = {ip: {'go': True, 'locked': []} for ip in dict_device_token}
        #config lock per vsys, empty Vsys = default vsys
        #shared locked last, PAN-OS allows shared after vsys but not vsys after shared
        #shared lock blocks every other admin until released
        #no lock for rows with empty / invalid Vsys
        def scopes(ip):
            fw = PA_tool.palib.api(ip, dict_device_token[ip])
            found = {PA_tool.row_location(fw, row, None)['@vsys'] for row in list_all_device
                     if row['Device-ip'] == ip and not fw.vsys_value(row.get('Vsys'))[1]}
            return sorted(found - {fw.SHARED_NAME}) + ([fw.SHARED_NAME] if fw.SHARED_NAME in found else [])
        vsys_of = {ip: scopes(ip) for ip in dict_device_token}
        lock_scope = lambda ip, vsys: None if vsys == PA_tool.palib.api(ip, dict_device_token[ip]).SHARED_NAME else vsys   # no vsys = shared
        lock_owner = f'PA Automation Tool - web user {request.user.username}'

        def call(func, *args):
            try:
                return func(*args)
            except Exception as e:
                return False, PA_tool.palib.safe_error(e)

        def version_step(ip):
            def step(log):
                log(f'Device-IP: {ip} | {PA_tool.palib.describe(ip)}')
            return step

        #firewall without API key / version: reported, skipped
        def failed_step(ip):
            def step(log):
                log(f'Device-IP: {ip} | API key FAILED: {token_failures[ip]} -> nothing done on this firewall, next firewall')
            return step

        #rows of a firewall per vsys
        def rows_in_vsys(ip, vsys):
            fw = PA_tool.palib.api(ip, dict_device_token[ip])
            found = []
            for sheet in op_sheets:
                for r in PA_tool.sheet_rows(PA_tool.read_sheet(file_content, sheet)):
                    if str(r['Device-ip']) == ip and not fw.vsys_value(r.get('Vsys'))[1] and PA_tool.row_location(fw, r, None)['@vsys'] == vsys:
                        found.append(f"{sheet} row {r['_row']}")
            return found

        #vsys not on the firewall: nothing written to it
        #vsys list unreadable: firewall refuses the lock anyway
        def vsys_error(ip):
            fw = PA_tool.palib.api(ip, dict_device_token[ip])
            known = PA_tool.DryRunContext().names('vsys', ip, dict_device_token[ip], {'location': 'vsys', '@vsys': 'firewall'})
            if known is None:
                return ''
            known = known or {fw.DEFAULT_VSYS}
            missing = [v for v in vsys_of[ip] if v != fw.SHARED_NAME and v not in known]
            if not missing:
                return ''
            return 'vsys not found on this firewall: ' + '; '.join(f"'{v}' ({', '.join(rows_in_vsys(ip, v)[:10])})" for v in missing) + \
                   f" (firewall vsys: {', '.join(sorted(known))})"

        #lock every vsys or nothing, release locks already taken
        def lock_step(ip):
            def step(log):
                bad = vsys_error(ip)
                if bad:
                    state[ip]['go'] = False
                    log(f'Device-IP: {ip} | cannot lock config: {bad} -> nothing written to this firewall, fix the Vsys column, next firewall')
                    return
                for vsys in vsys_of[ip]:
                    ok, msg = call(PA_tool.palib.add_config_lock, ip, dict_device_token[ip], lock_owner, lock_scope(ip, vsys))
                    if not ok:
                        state[ip]['go'] = False
                        log(f'Device-IP: {ip} | cannot lock config ({vsys}): {msg} -> nothing written to this firewall, next firewall')
                        release(ip, log)
                        return
                    state[ip]['locked'].append(vsys)
                log(f'Device-IP: {ip} | config locked ({", ".join(state[ip]["locked"])})')
            return step

        def backup_step(ip):
            def step(log):
                ok, msg = call(PA_tool.palib.backup_config, ip, dict_device_token[ip])
                if not ok:
                    state[ip]['go'] = False
                    log(f'Device-IP: {ip} | backup FAILED: {msg} -> nothing written to this firewall, next firewall')
                    return
                log(f'Device-IP: {ip} | backup saved {msg}')
            return step

        def release(ip, log):
            for vsys in list(state[ip]['locked']):
                ok, msg = call(PA_tool.palib.remove_config_lock, ip, dict_device_token[ip], lock_scope(ip, vsys))
                state[ip]['locked'].remove(vsys)
                if ok:
                    log(f'Device-IP: {ip} | config lock released ({vsys})')
                else:
                    log(f'Device-IP: {ip} | config lock NOT released ({vsys}: {msg}) -> remove it manually on the firewall')

        def unlock_step(ip):
            return lambda log: release(ip, log)

        def sheet_step(func, kind, sheet, ip, **kwargs):
            def step(log):
                func(kind,username=username,password=password,input_excel_file_path=file_content,sheet=sheet,dict_device_token=dict_device_token,log=log,device=ip,**kwargs)
            return step

        #sheets of 1 firewall in SHEET_ORDER, no section without rows
        rows_of = {sheet: set(PA_tool.read_sheet(file_content, sheet)['Device-ip'].astype(str)) for sheet in op_sheets}
        dry_ctx = PA_tool.DryRunContext()
        job_state = {}                                   # names created by the file, shared by the sheets
        def sheet_steps(ip, dry_run):
            extra = {'dry_run': True, 'dry_ctx': dry_ctx, 'job': job_state} if dry_run else {'job': job_state}
            prefix = job_runner.DRY_PREFIX if dry_run else ''
            result = []
            for sheet in op_sheets:
                kind, title = SHEETS[sheet]
                add = sheet.startswith('add_')
                func = PA_tool.automatic_create if add else edit_sheet.automatic_edit
                kwargs = {'stop_duplicate': stop_duplicate} if add and not dry_run else {}
                if ip in rows_of[sheet]:
                    result.append((f'{ip} · {prefix}{title}', sheet_step(func, kind, sheet, ip, **kwargs, **extra), lambda ip=ip: state[ip]['go']))
            return result

        steps, cleanup = [], []
        for ip in firewalls:
            if ip in token_failures:
                steps.append((f'{ip} · Firewall version', failed_step(ip)))
                continue
            go = lambda ip=ip: state[ip]['go']
            steps.append((f'{ip} · Firewall version', version_step(ip)))
            if mode == 'dry-run':
                steps += sheet_steps(ip, dry_run=True)
            else:
                steps += [(f'{ip} · Config lock', lock_step(ip)), (f'{ip} · Backup State', backup_step(ip), go)]
                steps += sheet_steps(ip, dry_run=False)
                steps.append((f'{ip} · Config unlock', unlock_step(ip), lambda ip=ip: state[ip]['locked']))
                #lock always released by job_runner cleanup if the job stops mid-firewall
                cleanup.append((f'{ip} · Config unlock', unlock_step(ip)))

        job_id = job_runner.start_job(file.name, username, stop_duplicate if mode == 'install' else None, steps, submitted_by=request.user.username, mode=mode, cleanup=cleanup, extra={'operation': 'configure'})
        if job_id is None:
            running = job_runner.running_job_id()
            return render(request, 'pages/palo_alto.html',{'running_job': running, 'error': 'Another job is running (see the link above). Please wait until it finished.'})
        return redirect(f'/palo_alto/job/{job_id}')


    return render(request, 'pages/palo_alto.html',{'error': f'Unknown configure type: {mode[:30]}'})
