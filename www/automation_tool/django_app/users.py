import re
from django.conf import settings
from django.contrib import messages
from functools import wraps
from django.contrib.auth.decorators import login_required
from django.contrib.auth.models import User
from django.contrib.auth.password_validation import validate_password
from django.core.exceptions import ValidationError, PermissionDenied
from django.shortcuts import render, redirect
from django.utils import timezone
from django.views.decorators.http import require_POST
from . import job_runner
from axes.models import AccessAttempt
from axes.utils import reset as axes_reset
import logging

logger = logging.getLogger('django_app.security')

# Users page (Admin only): 2 roles only
#   User  = is_active                               -> portal (Configure, Commit, Job history, Guide)
#   Admin = is_active + is_staff + is_superuser     -> portal + manage users
ROLES = ('user', 'admin')

#logged-in non-admin -> 403 (not a redirect to login: login would redirect back here = loop)
def admin_required(view):
    @wraps(view)
    def wrapper(request, *args, **kwargs):
        if not (request.user.is_active and request.user.is_superuser):
            raise PermissionDenied
        return view(request, *args, **kwargs)
    return wrapper


def set_role(user, role):
    user.is_staff = user.is_superuser = (role == 'admin')


def role_of(user):
    return 'admin' if user.is_superuser else 'user'


#active admins other than `user` (at least 1 active admin must always remain)
def other_active_admins(user):
    return User.objects.filter(is_active=True, is_superuser=True).exclude(pk=user.pk).count()


#username -> failed attempts still in the lockout window (django-axes)
def locked_usernames():
    since = timezone.now() - settings.AXES_COOLOFF_TIME
    locked = {}
    for attempt in AccessAttempt.objects.filter(attempt_time__gte=since, failures_since_start__gte=settings.AXES_FAILURE_LIMIT):
        locked[attempt.username] = max(locked.get(attempt.username, 0), attempt.failures_since_start)
    return locked


#password checked with AUTH_PASSWORD_VALIDATORS, return list of error messages
def password_errors(password, user=None):
    try:
        validate_password(password, user)
        return []
    except ValidationError as e:
        return list(e.messages)


@login_required
@admin_required
def user_list(request):
    locked = locked_usernames()
    # last login in the same timezone as the job pages (APP_TZ_OFFSET_HOURS), not UTC
    rows = [{'user': u, 'role': role_of(u), 'locked': locked.get(u.username, 0),
             'last_login': u.last_login.astimezone(job_runner.TZ).strftime('%Y-%m-%d %H:%M:%S') if u.last_login else ''}
            for u in User.objects.order_by('username')]
    return render(request, 'pages/users.html', {'rows': rows, 'form': {}, 'tz_label': job_runner.TZ_LABEL,
                                                'unknown_locked': sorted(set(locked) - {u.username for u in User.objects.all()})})


@login_required
@admin_required
@require_POST
def user_create(request):
    username = request.POST.get('username', '').strip()
    password = request.POST.get('password', '')
    role = request.POST.get('role', 'user')
    errors = []
    if not username:
        errors.append('Enter a username.')
    elif len(username) > 150:
        errors.append('Username: max 150 characters.')
    elif not re.fullmatch(r'[\w.@+-]+', username):
        errors.append('Username: only letters, digits and @ . + - _ (no space).')
    elif User.objects.filter(username__iexact=username).exists():
        errors.append(f"User '{username}' already exists.")
    if role not in ROLES:
        errors.append('Choose a role.')
    if not errors:
        errors += password_errors(password, User(username=username))
    if errors:
        for e in errors:
            messages.error(request, e)
        return redirect('/palo_alto/users')
    user = User(username=username, is_active=True)
    set_role(user, role)
    user.set_password(password)
    user.save()
    logger.info('user %s created (%s) by %s', username, role, request.user.username)
    messages.success(request, f"User '{username}' created ({role}).")
    return redirect('/palo_alto/users')


@login_required
@admin_required
@require_POST
def user_action(request, user_id):
    try:
        user = User.objects.get(pk=user_id)
    except User.DoesNotExist:
        messages.error(request, 'User not found.')
        return redirect('/palo_alto/users')
    action = request.POST.get('action', '')
    me = (user.pk == request.user.pk)
    removes_admin = user.is_superuser and user.is_active

    if action in ('disable', 'delete', 'role') and me:
        messages.error(request, 'You cannot change your own role, disable or delete yourself.')
    elif action in ('disable', 'delete') and removes_admin and other_active_admins(user) == 0:
        messages.error(request, 'At least one active Admin must remain.')
    elif action == 'role':
        role = request.POST.get('role', '')
        if role not in ROLES:
            messages.error(request, 'Choose a role.')
        elif role == 'user' and removes_admin and other_active_admins(user) == 0:
            messages.error(request, 'At least one active Admin must remain.')
        else:
            set_role(user, role)
            user.save()
            messages.success(request, f"'{user.username}' is now {role}.")
    elif action == 'disable':
        user.is_active = False
        user.save()
        messages.success(request, f"'{user.username}' disabled.")
    elif action == 'enable':
        user.is_active = True
        user.save()
        messages.success(request, f"'{user.username}' enabled.")
    elif action == 'password':
        # own password: only on /password/ (asks the current password); other user: confirm with the admin's current password
        if me:
            messages.error(request, 'Change your own password on the Change password page (current password required).')
        elif not request.user.check_password(request.POST.get('admin_password', '')):
            messages.error(request, 'Your current password is wrong: password not changed.')
        else:
            password = request.POST.get('password', '')
            errors = password_errors(password, user)
            if errors:
                for e in errors:
                    messages.error(request, e)
            else:
                user.set_password(password)
                user.save()
                messages.success(request, f"Password of '{user.username}' changed.")
    elif action == 'unlock':
        count = axes_reset(username=user.username)
        messages.success(request, f"'{user.username}' unlocked ({count} failed-login record(s) cleared).")
    elif action == 'delete':
        username = user.username
        user.delete()
        messages.success(request, f"User '{username}' deleted.")
    else:
        messages.error(request, 'Unknown action.')
    logger.info('user action %s on %s by %s', action[:20], user.username, request.user.username)    # audit (result in the page message)
    return redirect('/palo_alto/users')
