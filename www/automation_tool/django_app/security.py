import ipaddress
import logging
import re
import time
import zipfile
from urllib.parse import quote
from django.conf import settings
from django.contrib import messages
from django.contrib.auth import logout, views as auth_views
from django.contrib.auth.forms import AuthenticationForm
from axes.helpers import set_retry_after_header
from django.contrib.auth.password_validation import validate_password
from django.contrib.auth.signals import user_logged_in, user_logged_out, user_login_failed
from django.core.exceptions import ValidationError
from django.dispatch import receiver
from django.shortcuts import redirect, render
from django.utils.cache import add_never_cache_headers

# security helpers: target IP check (SSRF), upload limits (DoS / zip bomb), forced password change,
# security headers, audit log, error views rendered with the request (CSP nonce)
logger = logging.getLogger('django_app.security')

MAX_UPLOAD_BYTES = 10 * 1024 * 1024          # uploaded .xlsx
MAX_UNZIPPED_BYTES = 100 * 1024 * 1024       # total size of the files inside the .xlsx (zip bomb)
MAX_ZIP_ENTRIES = 1000


#firewall IP given by a user (Device-ip, commit targets): IPv4 only (IPv6 not supported), unicast address of a real device,
#not this container / host (loopback), not cloud metadata / link-local (169.254.x.x), not multicast / reserved
def target_ip_error(value):
    try:
        ip = ipaddress.ip_address(str(value).strip())
    except ValueError:
        return 'is not a valid IPv4 address'
    if ip.version != 4:
        return 'IPv6 is not supported, use the IPv4 address of the firewall'
    if (ip.is_loopback or ip.is_link_local or ip.is_multicast or ip.is_unspecified or ip.is_reserved
            or ip in ipaddress.ip_network('0.0.0.0/8') or ip == ipaddress.ip_address('255.255.255.255')):
        return 'loopback, link-local, multicast, reserved, broadcast or unspecified address is not allowed'
    return None


#uploaded .xlsx: size and content of the zip container checked BEFORE it is parsed, return error message or None
def xlsx_error(file):
    if file.size > MAX_UPLOAD_BYTES:
        return f'File too large (max {MAX_UPLOAD_BYTES // (1024 * 1024)} MB).'
    try:
        with zipfile.ZipFile(file) as z:
            entries = z.infolist()
            if len(entries) > MAX_ZIP_ENTRIES or sum(e.file_size for e in entries) > MAX_UNZIPPED_BYTES:
                return 'File content too large: not a normal Excel workbook.'
    except (zipfile.BadZipFile, ValueError):
        return 'Cannot read the Excel file (corrupted, password protected or not an .xlsx workbook).'
    finally:
        file.seek(0)
    return None


#password must contain an uppercase letter, a lowercase letter, a digit and a special character (any other character)
class CharacterClassesValidator:
    CLASSES = (('an uppercase letter', str.isupper), ('a lowercase letter', str.islower), ('a digit', str.isdigit),
               ('a special character', lambda c: not c.isalnum()))

    def validate(self, password, user=None):
        missing = [name for name, test in self.CLASSES if not any(test(c) for c in password)]
        if missing:
            raise ValidationError('The password must contain ' + ', '.join(missing) + '.', code='password_character_classes')

    def get_help_text(self):
        return 'Your password must contain an uppercase letter, a lowercase letter, a digit and a special character.'


def weak_password(password, user):
    try:
        validate_password(password, user)
        return False
    except ValidationError:
        return True


#username allowed in the tool (same characters as Django admin / page Users): letters, digits, @ . + - _ ; max 150
def valid_username(username):
    return len(username) <= 150 and re.fullmatch(r'[\w.@+-]+', username) is not None


#login with a username the tool cannot have (line break, control or other special characters): refused as a wrong login,
#no authentication, the typed text is not written to the log (no fake log lines, SEC-42)
class LoginForm(AuthenticationForm):
    def clean(self):
        username = self.cleaned_data.get('username') or ''
        if username and not valid_username(username):
            logger.warning('login failed: invalid username (%s characters, not letters / digits / @.+-_) from %s', len(username), client_ip(self.request))
            raise self.get_invalid_login_error()
        return super().clean()


#lockout page (django-axes): wait shown in minutes ('Try again in 15 minutes.'), not the ISO text 'PT15M' (UI-13); status 429 + Retry-After kept
def lockout_response(request, original_response=None, credentials=None):
    minutes = int(settings.AXES_COOLOFF_TIME.total_seconds() // 60)
    response = render(request, 'pages/lockout.html', {'failure_limit': settings.AXES_FAILURE_LIMIT,
                                                      'cooloff_minutes': minutes}, status=settings.AXES_HTTP_RESPONSE_CODE)
    set_retry_after_header(request, response)
    return response


#login: a password that does not pass the password rules (e.g. default admin/admin) -> must change it before using the tool
class LoginView(auth_views.LoginView):
    authentication_form = LoginForm

    def form_valid(self, form):
        response = super().form_valid(form)          # new session (no session fixation)
        self.request.session['auth_time'] = int(time.time())     # start of the absolute session timeout
        if weak_password(form.cleaned_data.get('password', ''), form.get_user()):
            self.request.session['must_change_password'] = True
        return response


class PasswordChangeView(auth_views.PasswordChangeView):
    def form_valid(self, form):
        response = super().form_valid(form)
        self.request.session.pop('must_change_password', None)
        messages.success(self.request, 'Password changed.')
        logger.info('password changed by %s', self.request.user.username)
        return response


#session: idle timeout = SESSION_COOKIE_AGE, renewed by user actions only (job status polling does not keep the session alive);
#absolute timeout = SESSION_ABSOLUTE_AGE after login
class SessionTimeoutMiddleware:
    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        if request.user.is_authenticated:
            now = int(time.time())
            started = request.session.setdefault('auth_time', now)
            if now - started > settings.SESSION_ABSOLUTE_AGE:
                request.session_expired = True          # audit line says 'session expired', not 'logout'
                logout(request)
                return redirect(f'/login/?next={quote(request.path)}')
            if not request.path.endswith('/status'):
                request.session.modified = True          # saved -> cookie and DB expiry renewed
        return self.get_response(request)


#Trusted Types: DOM XSS sinks (innerHTML, eval...) blocked by the browser on the tool pages;
#not on /admin/ (Django admin scripts use innerHTML)
class TrustedTypesMiddleware:
    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        response = self.get_response(request)
        csp = response.get('Content-Security-Policy')
        if csp and not request.path.startswith('/admin/'):
            response['Content-Security-Policy'] = csp + "; require-trusted-types-for 'script'"
        return response


#every page except the password change / logout -> redirect to /password/ while the flag is set
class ForcePasswordChangeMiddleware:
    ALLOWED_PATHS = ('/password/', '/logout/')                        # exact path
    ALLOWED_PREFIXES = ('/static/', '/palo_alto/guide', '/about/')

    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        if (request.user.is_authenticated and request.session.get('must_change_password')
                and request.path not in self.ALLOWED_PATHS and not request.path.startswith(self.ALLOWED_PREFIXES)):
            return redirect('/password/')
        return self.get_response(request)


#headers not covered by Django settings; pages are never cached (job results, user list are sensitive)
class SecurityHeadersMiddleware:
    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        response = self.get_response(request)
        response.setdefault('Permissions-Policy', settings.PERMISSIONS_POLICY)
        response.setdefault('Cross-Origin-Resource-Policy', 'same-origin')
        response.setdefault('X-Permitted-Cross-Domain-Policies', 'none')
        if 'Cache-Control' not in response:
            add_never_cache_headers(response)
        return response


#500 / CSRF failure pages rendered with the request: CSP nonce available (styled page), no internal detail
def server_error(request):
    return render(request, '500.html', status=500)


def csrf_failure(request, reason=''):
    logger.warning('CSRF failure %s %s: %s', request.method, request.path, reason)
    return render(request, '403_csrf.html', status=403)


#audit log (stderr -> docker logs): who logged in / out, failed logins (no password)
def client_ip(request):
    return request.META.get('REMOTE_ADDR', '-') if request else '-'


@receiver(user_logged_in)
def _logged_in(sender, request, user, **kwargs):
    logger.info('login ok: %s from %s', user.username, client_ip(request))


@receiver(user_logged_out)
def _logged_out(sender, request, user, **kwargs):
    if user is None:                                    # logout without session (already signed out / expired): nothing to audit
        return
    if getattr(request, 'session_expired', False):
        logger.info('session expired (%g h maximum): %s from %s', settings.SESSION_ABSOLUTE_AGE / 3600, user.username, client_ip(request))
    else:
        logger.info('logout: %s from %s', user.username, client_ip(request))


@receiver(user_login_failed)
def _login_failed(sender, credentials, request=None, **kwargs):
    logger.warning('login failed: %s from %s', str(credentials.get('username', ''))[:150], client_ip(request))
