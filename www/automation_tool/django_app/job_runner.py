import os
import re
import json
import gzip
import shutil
import secrets
import threading
import logging
from datetime import datetime, timezone, timedelta
from django.conf import settings

# job files always UTF-8, mod_wsgi runs with an ASCII locale
# jobs/<id>.json = metadata, <id>.log = result lines, append only, <id>.log.gz once finished
# oldest jobs deleted when jobs/ exceeds APP_JOB_MAX_SIZE_MB
JOB_DIR = os.path.join(settings.BASE_DIR, 'jobs')
JOB_ID_PATTERN = re.compile(r'^\d{8}-\d{6}-[0-9a-f]{4}$')
TZ = timezone(timedelta(hours=settings.RUNTIME.get('TZ_OFFSET_HOURS', 7)))
TZ_LABEL = 'GMT%+g' % settings.RUNTIME.get('TZ_OFFSET_HOURS', 7)
MAX_JOBS_MB = settings.RUNTIME.get('JOB_MAX_SIZE_MB', 1024)

logger = logging.getLogger('django_app.jobs')
from .lib_tool.palo_alto_api_lib import safe_error

# 1 job at a time; single mod_wsgi process, in-memory lock is enough
run_lock = threading.Lock()
active_jobs = set()


def now_str():
    return datetime.now(TZ).strftime('%Y-%m-%d %H:%M:%S')


def job_path(job_id):
    return os.path.join(JOB_DIR, job_id + '.json')


def log_path(job_id):
    return os.path.join(JOB_DIR, job_id + '.log')


def gz_path(job_id):
    return log_path(job_id) + '.gz'


save_lock = threading.Lock()   # written by several threads in bulk commit

def save_job(job):
    with save_lock:
        os.makedirs(JOB_DIR, exist_ok=True)
        tmp = job_path(job['id']) + '.tmp'
        try:
            with open(tmp, 'w', encoding='utf-8') as f:
                json.dump(job, f, ensure_ascii=False)
            os.replace(tmp, job_path(job['id']))
        except Exception:                       # disk full: no .tmp left, last good file kept
            try:
                os.remove(tmp)
            except OSError:
                pass
            raise


#append 1 result line
def append_line(job_id, section_index, line):
    with save_lock:
        os.makedirs(JOB_DIR, exist_ok=True)
        with open(log_path(job_id), 'a', encoding='utf-8') as f:
            f.write(json.dumps([section_index, str(line), now_str()], ensure_ascii=False) + '\n')


TRUNCATED_LINE = '(line truncated: disk full)'

#all result lines of a job
#line cut by a full disk shown as TRUNCATED_LINE
def read_lines(job):
    if any('lines' in s for s in job['sections']):
        return [[i, l] for i, s in enumerate(job['sections']) for l in s.get('lines', [])]
    for path, opener in ((log_path(job['id']), open), (gz_path(job['id']), gzip.open)):
        try:
            lines = []
            with opener(path, 'rt', encoding='utf-8', errors='replace') as f:
                for l in f:
                    if not l.strip():
                        continue
                    try:
                        line = json.loads(l)
                        if not (isinstance(line, list) and len(line) >= 2 and isinstance(line[0], int)):
                            raise ValueError
                    except ValueError:
                        line = [lines[-1][0] if lines else 0, TRUNCATED_LINE]
                    lines.append(line)
            return lines
        except FileNotFoundError:
            continue
        except (OSError, EOFError):             # .gz cut by a full disk
            return lines + [[lines[-1][0] if lines else 0, TRUNCATED_LINE]]
    return []


#compress lines of a finished job, .gz written before .log is removed
def compress_log(job_id):
    src, dst = log_path(job_id), gz_path(job_id)
    if not os.path.exists(src):
        return
    try:
        with open(src, 'rb') as f, gzip.open(dst + '.tmp', 'wb') as g:
            shutil.copyfileobj(f, g)
        os.replace(dst + '.tmp', dst)
        os.remove(src)
    except OSError as e:                        # disk full: keep .log, retry at next job end
        logger.error('job %s: cannot compress result lines (%s)', job_id, e)
        try:
            os.remove(dst + '.tmp')
        except OSError:
            pass


maintenance_lock = threading.Lock()

#keep jobs/ under MAX_JOBS_MB, oldest first, never the running or newest job
#runs only at the end of a job
def maintenance():
    if not maintenance_lock.acquire(blocking=False):
        return
    try:
        if not os.path.isdir(JOB_DIR):
            return
        files = {}
        for entry in os.scandir(JOB_DIR):
            job_id = entry.name.split('.')[0]
            if entry.is_file() and JOB_ID_PATTERN.match(job_id):
                files.setdefault(job_id, []).append(entry.name)
        for job_id, names in files.items():
            if job_id + '.log' in names and job_id not in active_jobs:
                compress_log(job_id)
                files[job_id] = [n for n in os.listdir(JOB_DIR) if n.split('.')[0] == job_id]
        if MAX_JOBS_MB <= 0:
            return
        size = {job_id: sum(os.path.getsize(os.path.join(JOB_DIR, n)) for n in names) for job_id, names in files.items()}
        total, limit = sum(size.values()), MAX_JOBS_MB * 1024 * 1024
        deleted = 0
        for job_id in sorted(size)[:-1]:
            if total <= limit:
                break
            if job_id in active_jobs:
                continue
            for name in files[job_id]:
                try:
                    os.remove(os.path.join(JOB_DIR, name))
                except OSError as e:
                    logger.error('job %s: cannot delete %s (%s)', job_id, name, e)
            total -= size[job_id]
            deleted += 1
        if deleted:
            logger.info('job retention: %s oldest job(s) deleted, job results above %s MB', deleted, MAX_JOBS_MB)
    finally:
        maintenance_lock.release()


#return job dict or None, read only
#file still 'running' but job not running here = interrupted
def load_job(job_id):
    if not JOB_ID_PATTERN.match(job_id or ''):
        return None
    running_now = job_id in active_jobs          # checked before reading: thread writes final state, then leaves active_jobs
    try:
        with open(job_path(job_id), encoding='utf-8') as f:
            job = json.load(f)
    except Exception:
        return None
    if job['status'] == 'running' and not running_now:
        job['status'] = 'interrupted'
    job['badge'], job['badge_text'] = badge(job)
    return job


#job badge: finished job with failures is not plain green
#some failed = yellow, all failed = red; status stays 'done'
def badge(job):
    status = job.get('status', '')
    fail = job.get('fail', 0) + job.get('info_fail', 0)
    if status == 'done' and fail:
        return ('done-warn' if job.get('ok') else 'done-fail'), f"done · {fail} failed"
    return status, status


def list_jobs():
    if not os.path.isdir(JOB_DIR):
        return []
    jobs = []
    for name in sorted(os.listdir(JOB_DIR), reverse=True):
        if name.endswith('.json'):
            job = load_job(name[:-5])
            if job:
                jobs.append(job)
    return jobs


#free MB on the jobs/ disk, None if unknown
def free_mb():
    try:
        st = os.statvfs(JOB_DIR if os.path.isdir(JOB_DIR) else settings.BASE_DIR)
    except OSError:
        return None
    return st.f_bavail * st.f_frsize // (1024 * 1024)


#job history stats: count, size, free disk
def storage_info():
    count = size = 0
    if os.path.isdir(JOB_DIR):
        for entry in os.scandir(JOB_DIR):
            if entry.is_file():
                size += entry.stat().st_size
                count += entry.name.endswith('.json')
    minimum = settings.RUNTIME.get('MIN_FREE_DISK_MB', 100)
    free = free_mb()
    return {'count': count, 'size_mb': round(size / (1024 * 1024), 1), 'free_mb': free, 'min_free_mb': minimum,
            'max_mb': MAX_JOBS_MB, 'low': free is not None and free < 2 * minimum}


#refuse new jobs when the jobs/ disk is almost full
def free_space_error():
    minimum = settings.RUNTIME.get('MIN_FREE_DISK_MB', 100)
    free = free_mb()
    if free is not None and free < minimum:
        logger.error('disk almost full: %s MB free in %s, minimum %s MB (APP_MIN_FREE_DISK_MB): new jobs refused', free, JOB_DIR, minimum)
        return (f'Not enough free disk space on the server for job results ({free} MB free, minimum {minimum} MB). '
                'Ask the administrator to free disk space.')
    return None


def running_job_id():
    for job_id in list(active_jobs):
        return job_id
    return None


INFO_SECTIONS = ('Firewall version', 'Backup State', 'Dry-run check', 'Config lock', 'Config unlock')
DRY_PREFIX = '[Dry-run] '

#strip the '<firewall> · ' prefix
def section_kind(title):
    return title.split(' · ', 1)[-1]

#result line status: ok / warn / skip / fail
def classify(line):
    if 'SKIPPED' in line:
        return 'skip'
    if '=> command succeeded' in line or '=> CAN ' in line or '=> WOULD ' in line or '=> moved ' in line:
        return 'warn' if ('warning' in line.lower() or 'failed' in line.lower()) else 'ok'
    if '=> NOT EDITED: nothing to change' in line:      # edit row already matching the firewall, nothing written
        return 'warn'
    return 'fail'

#row sections to count: install if any, else dry-run
def row_sections(job):
    rows = [i for i, s in enumerate(job['sections']) if section_kind(s['title']) not in INFO_SECTIONS]
    real = [i for i in rows if not section_kind(job['sections'][i]['title']).startswith(DRY_PREFIX)]
    return real if real else rows

#counters per section + job totals
def counts(job, lines):
    per = [{'ok': 0, 'warn': 0, 'skip': 0, 'fail': 0, 'info': 0} for _ in job['sections']]
    for i, line, *_ in lines:
        if i >= len(per):
            continue
        if section_kind(job['sections'][i]['title']) in INFO_SECTIONS:
            per[i]['fail' if ('cannot lock' in line or 'NOT released' in line or 'backup FAILED' in line or 'API key FAILED' in line) else 'info'] += 1
        else:
            per[i][classify(line)] += 1
    total = {'rows': 0, 'ok': 0, 'warn': 0, 'skip': 0, 'fail': 0}
    for i in row_sections(job):
        for k in ('ok', 'warn', 'skip', 'fail'):
            total[k] += per[i][k]
            total['rows'] += per[i][k]
    return per, total

def count_result(job):
    per, total = counts(job, read_lines(job))
    job['ok'] = total['ok'] + total['warn']
    job['skip'] = total['skip']
    job['fail'] = total['fail']
    job['info_fail'] = sum(c['fail'] for c in per) - sum(per[i]['fail'] for i in row_sections(job))

#job state for the job page, lines from `since` on
def status(job, since=0):
    lines = read_lines(job)
    per, total = counts(job, lines)
    data = {k: v for k, v in job.items() if k != 'sections'}
    data['sections'] = [{'title': s['title']} for s in job['sections']]
    data['section_counts'] = per
    data['total'] = total
    data['line_count'] = len(lines)
    data['lines'] = lines[since:]
    return data


#run steps one by one in a background thread, return job_id or None if busy
#step = (title, func) or (title, func, when); a step returning False blocks the job
#cleanup steps always run at the end
def start_job(filename, username, stop_duplicate, steps, submitted_by='', mode='install', cleanup=(), extra=None):
    if not run_lock.acquire(blocking=False):
        return None
    job = {
        'id': datetime.now(TZ).strftime('%Y%m%d-%H%M%S') + '-' + secrets.token_hex(2),
        'status': 'running',
        'started': now_str(),
        'finished': '',
        'filename': filename,
        'username': username,
        'submitted_by': submitted_by,
        'stop_duplicate': stop_duplicate,
        'mode': mode,
        'current': '',
        'sections': [],
        'error': '',
    }
    job.update(extra or {})
    try:
        active_jobs.add(job['id'])
        save_job(job)
    except Exception:
        active_jobs.discard(job['id'])
        run_lock.release()                     # release the lock if the job could not be created
        raise
    logger.info('job %s started by %s: mode=%s file=%s', job['id'], submitted_by, mode, filename)

    def run():
        try:
            for title, func, *when in steps:
                if when and not when[0]():
                    continue
                job['sections'].append({'title': title})
                job['current'] = title
                save_job(job)

                def log(line, index=len(job['sections']) - 1):
                    append_line(job['id'], index, line)

                if func(log) is False:
                    job['status'] = 'blocked'
                    break
            else:
                job['status'] = 'done'
        except Exception as e:
            # traceback only in server log, short message on the page
            logger.exception('job %s failed', job['id'])
            job['status'] = 'failed'
            job['error'] = safe_error(e)
        finally:
            # cleanup always runs, even if its lines cannot be written
            for title, func in cleanup:
                created = []
                def log(line, title=title, created=created):
                    try:
                        if not created:
                            job['sections'].append({'title': title})
                            created.append(len(job['sections']) - 1)
                            save_job(job)
                        append_line(job['id'], created[0], line)
                    except OSError as e:
                        logger.error('job %s: cannot write job file (%s): %s', job['id'], e, line)
                try:
                    func(log)
                except Exception as e:
                    logger.exception('job %s cleanup "%s" failed', job['id'], title)
                    job['error'] += f'\n{title}: {safe_error(e)}'
            # lock always released
            try:
                job['current'] = ''
                job['finished'] = now_str()
                count_result(job)
                save_job(job)
                compress_log(job['id'])
            except Exception as e:
                logger.error('job %s: cannot write final job state (%s), last saved state kept on disk', job['id'], e)
            finally:
                active_jobs.discard(job['id'])
                run_lock.release()
            try:
                maintenance()
            except Exception:
                logger.exception('job maintenance failed')

    try:
        threading.Thread(target=run, daemon=True).start()
    except Exception:
        job['status'] = 'failed'
        job['error'] = 'Could not start the job.'
        job['finished'] = now_str()
        save_job(job)
        active_jobs.discard(job['id'])
        run_lock.release()
        raise
    return job['id']
