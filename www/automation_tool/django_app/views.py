from django.conf import settings
from django.shortcuts import render, redirect
from django.http import JsonResponse, Http404
from django.contrib.auth.decorators import login_required
from . import job_runner
from . import guide_content


#dashboard when signed in, else About
def index(request):
   if not request.user.is_authenticated:
      return redirect('/about/')
   jobs = job_runner.list_jobs()
   return render(request, 'pages/index.html', {'recent_jobs': jobs[:5], 'job_count': len(jobs), 'running_job': job_runner.running_job_id(), 'tz_label': job_runner.TZ_LABEL})

@login_required
def palo_alto(request):
   return render(request, 'pages/palo_alto.html', {'running_job': job_runner.running_job_id()})

#job result page
@login_required
def job_page(request, job_id):
   job = job_runner.load_job(job_id)
   if job is None:
      raise Http404('Job not found')
   return render(request, 'pages/job.html', {'job': job, 'tz_label': job_runner.TZ_LABEL})

#job state json, polled by the job page
@login_required
def job_status(request, job_id):
   job = job_runner.load_job(job_id)
   if job is None:
      raise Http404('Job not found')
   try:
      since = max(int(request.GET.get('since', 0)), 0)
   except ValueError:
      since = 0
   return JsonResponse(job_runner.status(job, since))

#About page, public
def about(request):
   return bilingual(request, 'pages/about.html')

#Guide page, public
def guide(request):
   return bilingual(request, 'pages/guide.html', guide_content.guide_context)

#language: ?lang, then cookie, else English
def bilingual(request, template, extra=None):
   asked = request.GET.get('lang')
   lang = asked if asked in ('en', 'vi') else request.COOKIES.get('lang')
   lang = 'vi' if lang == 'vi' else 'en'
   context = {'lang': lang, 'app_version': settings.APP_VERSION}
   if extra:
      context.update(extra(lang))
   response = render(request, template, context)
   if asked in ('en', 'vi'):
      response.set_cookie('lang', lang, max_age=365 * 24 * 3600, secure=True, httponly=True, samesite='Strict')
   return response

#job history
@login_required
def job_list(request):
   return render(request, 'pages/jobs.html', {'jobs': job_runner.list_jobs(), 'running_job': job_runner.running_job_id(), 'tz_label': job_runner.TZ_LABEL,
                                              'storage': job_runner.storage_info()})
