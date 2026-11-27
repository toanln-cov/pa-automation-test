import re
import time
import ipaddress
from concurrent.futures import ThreadPoolExecutor, as_completed
from django.shortcuts import render, redirect
from django.contrib.auth.decorators import login_required
from .lib_tool import palo_alto_api_lib as palib
from . import job_runner
from .security import target_ip_error
import logging

logger = logging.getLogger('django_app.commit')

# Bulk commit: separate feature (not related to the Excel template / configuration jobs)
#   action 'validate' = commit check (validate only, nothing applied)
#   action 'commit'   = commit
MAX_TARGETS = 256
PARALLEL = 5
POLL_INTERVAL = 5            # seconds between job status checks
JOB_TIMEOUT = 30 * 60        # max seconds to wait for a commit / validate job on a firewall


#"10.0.0.1, 10.0.0.5-10.0.0.8, 10.0.1.0/30" -> (list of ip, list of error), keep order, no duplicate
def parse_targets(text):
    ips, errors = [], []
    for token in [t for t in re.split(r'[\s,;]+', text or '') if t]:
        try:
            if '-' in token:
                first, last = [ipaddress.ip_address(x.strip()) for x in token.split('-', 1)]
                if first.version != 4 or last.version != 4:
                    raise ValueError('IPv6 is not supported, use IPv4')
                if int(last) < int(first):
                    raise ValueError('invalid range')
                if int(last) - int(first) + 1 > MAX_TARGETS:
                    raise ValueError(f'range larger than {MAX_TARGETS}')
                found = [str(ipaddress.IPv4Address(i)) for i in range(int(first), int(last) + 1)]
            elif '/' in token:
                net = ipaddress.ip_network(token, strict=False)
                if net.version != 4:
                    raise ValueError('IPv6 is not supported, use IPv4')
                if net.num_addresses > MAX_TARGETS + 2:
                    raise ValueError(f'network larger than {MAX_TARGETS}')
                hosts = list(net.hosts()) or [net.network_address]
                found = [str(i) for i in hosts]
            else:
                found = [str(ipaddress.ip_address(token))]
        except ValueError as e:
            errors.append(f"'{token[:60]}': {'invalid IPv4 / range / network' if not str(e) else str(e)[:120]}")
            continue
        bad = [e for e in (target_ip_error(ip) for ip in found) if e]
        if bad:
            errors.append(f"'{token[:60]}': {bad[0]}")
            continue
        for ip in found:
            if ip not in ips:
                ips.append(ip)
    if len(ips) > MAX_TARGETS:
        errors.append(f'{len(ips)} firewalls, maximum is {MAX_TARGETS}')
    return ips, errors


#wait until firewall job finished, return status dict
def wait_job(host,token,job_id):
    start = time.time()
    while True:
        st = palib.get_job_status(host, token, job_id)
        if palib.job_finished(host, token, st):          # job states of the PAN-OS version (version class)
            return st
        if time.time() - start > JOB_TIMEOUT:
            raise palib.FirewallError(f'job {job_id} not finished after {JOB_TIMEOUT // 60} minutes (status {st["status"]}, progress {st["progress"]}%)')
        time.sleep(POLL_INTERVAL)


#commit check / commit on 1 firewall, return result line (same format as configuration jobs for job page)
def run_one(ip,username,password,action,admin,description):
    label = 'Commit check' if action == 'validate' else 'Commit'
    start = time.time()
    try:
        token = palib.get_token(ip, username, password)
        palib.detect_rest_version(ip, token)          # API class of this firewall's PAN-OS version (read only)
        if palib.check_pending_changes(ip, token) != 'yes':
            return f'Device-IP: {ip} => SKIPPED: no pending changes'
        if action == 'validate':
            job_id, msg = palib.start_validate(ip, token, admin)
        else:
            job_id, msg = palib.start_commit(ip, token, description, admin)
        if not job_id:
            return f'Device-IP: {ip} => SKIPPED: {msg}'      # e.g. no changes of this admin to commit
        st = wait_job(ip, token, job_id)
        took = f'{label} job {job_id} ({int(time.time() - start)}s)'
        if palib.job_ok(ip, token, st):
            line = f'Device-IP: {ip} => command succeeded | {took}'
            if st.get('warnings'):
                line += ' | Warning:\n' + st['warnings']      # <warnings> of the job as the firewall shows them, 1 line each (BUG-77) -> warning on job page
            elif 'warning' in st['details'].lower():
                line += ' | ' + st['details']      # details contain 'warning' -> shown as warning on job page
            return line
        return f'Device-IP: {ip} => {label} FAILED | {took} | {st["details"]}'
    except Exception as e:
        logger.exception('%s on %s failed', label, ip)
        return f'Device-IP: {ip} => {label} FAILED | {palib.safe_error(e)}'


#unexpected error while preparing the job -> generic message on the form, details only in the server log
@login_required
def bulk_commit(request):
    try:
        return _bulk_commit(request)
    except Exception:
        logger.exception('bulk commit failed')
        return render(request, 'pages/commit.html', {'errors': ['Unexpected error while preparing the job. Nothing was sent to the firewalls. Details are in the server log.']})


def _bulk_commit(request):
    ctx = {'running_job': job_runner.running_job_id(), 'form': request.POST}
    if request.method != 'POST':
        return render(request, 'pages/commit.html', ctx)

    targets = request.POST.get('targets', '')
    username = request.POST.get('username', '')
    password = request.POST.get('password', '')
    action = request.POST.get('action', '')
    scope = request.POST.get('scope', '')            # no default: the user must choose (BUG-57)
    description = request.POST.get('description', '').strip()

    errors = []
    ips, parse_errors = parse_targets(targets)
    errors += parse_errors
    if not ips and not parse_errors:
        errors.append('Enter at least 1 firewall IP')
    if not (username and password):
        errors.append('Enter firewall username and password')
    if action not in ('validate', 'commit'):
        errors.append('Choose an action')
    if scope not in ('admin', 'full'):
        errors.append('Choose a scope')
    if len(description) > 255:
        errors.append('Commit description: max 255 characters')
    if errors:
        ctx['errors'] = errors
        return render(request, 'pages/commit.html', ctx)

    admin = username if scope == 'admin' else None
    label = 'Commit check' if action == 'validate' else 'Commit'

    #all firewalls in 1 section, max PARALLEL at the same time, result shown as soon as a firewall finished
    def step(log):
        with ThreadPoolExecutor(max_workers=PARALLEL) as pool:
            futures = [pool.submit(run_one, ip, username, password, action, admin, description) for ip in ips]
            for f in as_completed(futures):
                log(f.result())

    logger.info('%s requested by %s: %s firewall(s), scope=%s', label, request.user.username, len(ips), scope)
    disk_error = job_runner.free_space_error()
    if disk_error:
        ctx['errors'] = [disk_error]
        return render(request, 'pages/commit.html', ctx)
    job_id = job_runner.start_job(f'{len(ips)} firewall(s)', username, False, [(f'{label} ({len(ips)} firewalls)', step)],
                                  submitted_by=request.user.username, mode=action,
                                  extra={'targets': ips, 'scope': scope, 'description': description})
    if job_id is None:
        ctx['errors'] = ['Another job is running, wait until it finished.']
        return render(request, 'pages/commit.html', ctx)
    return redirect(f'/palo_alto/job/{job_id}')
