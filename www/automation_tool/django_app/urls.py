"""django_app URL Configuration

The `urlpatterns` list routes URLs to views. For more information please see:
    https://docs.djangoproject.com/en/3.2/topics/http/urls/
Examples:
Function views
    1. Add an import:  from my_app import views
    2. Add a URL to urlpatterns:  path('', views.home, name='home')
Class-based views
    1. Add an import:  from other_app.views import Home
    2. Add a URL to urlpatterns:  path('', Home.as_view(), name='home')
Including another URLconf
    1. Import the include() function: from django.urls import include, path
    2. Add a URL to urlpatterns:  path('blog/', include('blog.urls'))
"""
from django.contrib import admin
from django.contrib.auth import views as auth_views
from django.urls import path
from django.views.generic import RedirectView
from . import views, upload_config, bulk_commit, users, security

handler500 = 'django_app.security.server_error'

urlpatterns = [
    # one login page for portal and /admin (brute-force lock, forced password change)
    path('admin/login/', RedirectView.as_view(url='/login/', query_string=True)),
    path('admin/', admin.site.urls),
    path('login/', security.LoginView.as_view(template_name='pages/login.html', redirect_authenticated_user=True)),
    path('logout/', auth_views.LogoutView.as_view()),
    # after a change -> Dashboard with a 'Password changed' message (no separate done page)
    path('password/', security.PasswordChangeView.as_view(template_name='pages/password_change.html', success_url='/')),
    path('password/done/', RedirectView.as_view(url='/')),           # old link
    path('favicon.ico', RedirectView.as_view(url='/static/picture/favicon.svg', permanent=True)),   # browsers ask /favicon.ico
    path('',views.index),
    path('palo_alto/',views.palo_alto),
    path('palo_alto/upload',upload_config.palo_alto_upload),
    path('palo_alto/commit',bulk_commit.bulk_commit),
    path('palo_alto/jobs',views.job_list),
    path('about/',views.about),
    path('palo_alto/guide',views.guide),
    path('palo_alto/users',users.user_list),
    path('palo_alto/users/create',users.user_create),
    path('palo_alto/users/<int:user_id>',users.user_action),
    path('palo_alto/job/<str:job_id>',views.job_page),
    path('palo_alto/job/<str:job_id>/status',views.job_status),
]
