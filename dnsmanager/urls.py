from django.urls import path
from . import views

urlpatterns = [
    path('', views.dashboard, name='dashboard'),
    path('domains/', views.zone_list, name='zones'),
    path('domains/new/', views.zone_form, name='zone_create'),
    path('domains/discover/', views.discover, name='discover'),
    path('domains/check/', views.domain_check, name='domain_check'),
    path('domains/<int:pk>/check/', views.domain_check, name='zone_check'),
    path('domains/<int:pk>/', views.zone_detail, name='zone_detail'),
    path('domains/<int:pk>/settings/', views.zone_form, name='zone_edit'),
    path('domains/<int:pk>/delete/', views.zone_delete, name='zone_delete'),
    path('domains/<int:pk>/publish/', views.zone_publish, name='zone_publish'),
    path('domains/<int:pk>/pull/', views.zone_pull, name='zone_pull'),
    path('domains/<int:pk>/export/', views.zone_export, name='zone_export'),
    path('domains/<int:pk>/records/new/', views.record_form, name='record_create'),
    path('domains/<int:pk>/records/<int:record_pk>/', views.record_form, name='record_edit'),
    path('domains/<int:pk>/records/<int:record_pk>/details/', views.record_detail, name='record_detail'),
    path('domains/<int:pk>/records/<int:record_pk>/toggle/', views.record_toggle, name='record_toggle'),
    path('domains/<int:pk>/records/<int:record_pk>/delete/', views.record_delete, name='record_delete'),
    path('activity/', views.activity_list, name='activity'),
    path('connection/', views.connection, name='connection'),
    path('guide/', views.guide, name='guide'),
    path('healthz/', views.health, name='health'),
]
