from django.contrib import admin
from .models import Zone, Activity


@admin.register(Zone)
class ZoneAdmin(admin.ModelAdmin):
    list_display = ['name', 'owner', 'revision', 'published_revision', 'last_published_at']
    search_fields = ['name', 'owner__username']
    def has_add_permission(self, request):
        return False
    def has_change_permission(self, request, obj=None):
        return False
    def has_delete_permission(self, request, obj=None):
        return False


@admin.register(Activity)
class ActivityAdmin(admin.ModelAdmin):
    list_display = ['created_at', 'user', 'zone_name', 'action', 'detail']
    search_fields = ['zone_name', 'user__username']
    def has_add_permission(self, request):
        return False
    def has_change_permission(self, request, obj=None):
        return False
    def has_delete_permission(self, request, obj=None):
        return False
