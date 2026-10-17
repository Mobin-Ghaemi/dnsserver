from django.contrib import admin
from django.contrib.auth import views as auth_views
from django.urls import include, path
from dnsmanager.forms import LoginForm, PasswordForm

urlpatterns = [
    path('admin/', admin.site.urls),
    path('login/', auth_views.LoginView.as_view(template_name='registration/login.html', authentication_form=LoginForm, redirect_authenticated_user=True), name='login'),
    path('logout/', auth_views.LogoutView.as_view(), name='logout'),
    path('account/password/', auth_views.PasswordChangeView.as_view(template_name='registration/password.html', form_class=PasswordForm, success_url='/account/password/done/'), name='password_change'),
    path('account/password/done/', auth_views.PasswordChangeDoneView.as_view(template_name='registration/password_done.html'), name='password_change_done'),
    path('', include('dnsmanager.urls')),
]
handler404 = 'dnsmanager.views.not_found'
handler500 = 'dnsmanager.views.server_error'
