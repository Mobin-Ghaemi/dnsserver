from django.conf import settings
from django.contrib import messages
from django.contrib.auth.decorators import login_required
from django.core.cache import cache
from django.core.exceptions import ValidationError
from django.core.paginator import Paginator
from django.db import IntegrityError, transaction
from django.db.models import Count, F, Q
from django.http import HttpResponse, JsonResponse
from django.shortcuts import get_object_or_404, redirect, render
from django.template.loader import render_to_string
from django.urls import reverse
from django.views.decorators.cache import never_cache
from django.views.decorators.http import require_POST

from .dns import RECORD_TYPES
from .forms import ZoneForm, RecordForm, DomainCheckForm
from .models import Zone, Record, Activity
from .powerdns import PowerDNS, ProviderError
from .services import ZoneBusy, audit, changed, editable_zone, publish_zone, delete_zone


def modal_request(request):
    return request.headers.get('X-Orbit-Modal') == '1'


def form_response(request, template, context):
    if modal_request(request):
        return JsonResponse({'ok': False, 'html': render_to_string('dnsmanager/modal_form.html', context, request=request)},
                            status=422 if request.method == 'POST' else 200)
    return render(request, template, context)


def owned(request, pk):
    return get_object_or_404(Zone, pk=pk, owner=request.user)


@login_required
def dashboard(request):
    zones = Zone.objects.filter(owner=request.user)
    records = Record.objects.filter(zone__owner=request.user)
    counts = list(records.values('type').annotate(total=Count('pk')).order_by('-total'))
    total = records.count()
    return render(request, 'dnsmanager/dashboard.html', {
        'zone_count': zones.count(), 'record_count': total, 'enabled_count': records.filter(enabled=True).count(),
        'published_count': zones.filter(revision=F('published_revision'), last_error='').count(),
        'draft_count': zones.exclude(revision=F('published_revision')).count(),
        'recent_zones': zones.annotate(record_total=Count('records')).order_by('-updated_at', '-pk')[:5],
        'activities': Activity.objects.filter(user=request.user).select_related('zone')[:5],
        'distribution': [dict(row, percent=round(row['total'] / total * 100) if total else 0) for row in counts],
    })


@login_required
def zone_list(request):
    zones = Zone.objects.filter(owner=request.user).annotate(record_total=Count('records')).order_by('-updated_at', '-pk')
    q = request.GET.get('q', '').strip()[:253]
    state = request.GET.get('status', '')
    ns_state = request.GET.get('ns', '')
    if q:
        zones = zones.filter(Q(name__icontains=q) | Q(description__icontains=q))
    if state == 'published':
        zones = zones.filter(revision=F('published_revision'), last_error='')
    elif state == 'draft':
        zones = zones.exclude(revision=F('published_revision')).filter(last_error='')
    elif state == 'error':
        zones = zones.exclude(last_error='')
    if ns_state in ('matched', 'mismatch', 'propagating', 'unavailable', 'not_found'):
        zones = zones.filter(ns_check__status=ns_state)
    check_result = request.session.pop('domain_check_result', None)
    try:
        from .domain_check import expected_nameservers, expected_groups
        expected_ns = expected_nameservers()
        ns_groups = expected_groups()
    except ValidationError:
        expected_ns = []
        ns_groups = []
    return render(request, 'dnsmanager/zones.html', {'page_obj': Paginator(zones, 12).get_page(request.GET.get('page')), 'q': q, 'state': state,
                                                  'total_zones': Zone.objects.filter(owner=request.user).count(), 'ns_state': ns_state,
                                                  'check_form': DomainCheckForm(initial={'add_on_match': True}), 'check_result': check_result, 'expected_ns': expected_ns, 'ns_groups': ns_groups})


@login_required
def zone_form(request, pk=None):
    zone = owned(request, pk) if pk else Zone(owner=request.user)
    form = ZoneForm(request.POST or None, instance=zone, initial={'name': request.GET.get('name', '')[:253]} if not pk else None)
    if request.method == 'POST' and form.is_valid():
        try:
            with transaction.atomic():
                if pk:
                    current = editable_zone(pk, request.user)
                    current.description = form.cleaned_data['description']
                    current.default_ttl = form.cleaned_data['default_ttl']
                    current.save(update_fields=['description', 'default_ttl', 'updated_at'])
                    changed(current)
                    zone = current
                else:
                    zone = form.save(commit=False)
                    zone.owner = request.user
                    zone.save()
                audit(request.user, zone, 'ویرایش دامنه' if pk else 'افزودن دامنه')
            messages.success(request, 'دامنه ذخیره شد. برای اعمال روی DNS از دکمهٔ انتشار استفاده کنید.')
            if modal_request(request):
                result = {'ok': True, 'redirect_url': reverse('zone_detail', args=[zone.pk])}
                if not pk:
                    result['html'] = render_to_string('dnsmanager/nameserver_modal.html', {'zone': zone, 'nameservers': zone.nameservers}, request=request)
                return JsonResponse(result)
            return redirect(reverse('zone_detail', args=[zone.pk]) + ('?setup=1' if not pk else ''))
        except ZoneBusy as error:
            form.add_error(None, str(error))
        except IntegrityError:
            form.add_error('name', 'این دامنه قبلاً ثبت شده است.')
    return form_response(request, 'dnsmanager/zone_form.html', {'form': form, 'zone': zone, 'editing': bool(pk), 'form_kind': 'zone', 'submit_url': request.path})


@login_required
def zone_detail(request, pk):
    zone = owned(request, pk)
    records = zone.records.all()
    q = request.GET.get('q', '').strip()[:253]
    kind = request.GET.get('type', '')
    if q:
        relative_q = q.rstrip('.').lower()
        if relative_q == zone.name:
            relative_q = '@'
        elif relative_q.endswith('.' + zone.name):
            relative_q = relative_q[:-(len(zone.name) + 1)]
        records = records.filter(Q(name__icontains=relative_q) | Q(content__icontains=q))
    if kind in RECORD_TYPES:
        records = records.filter(type=kind)
    enabled = request.GET.get('enabled', '')
    if enabled in ('1', '0'):
        records = records.filter(enabled=enabled == '1')
    return render(request, 'dnsmanager/zone_detail.html', {
        'zone': zone, 'page_obj': Paginator(records, 20).get_page(request.GET.get('page')), 'q': q, 'kind': kind,
        'record_types': RECORD_TYPES, 'record_count': zone.records.count(), 'enabled_count': zone.records.filter(enabled=True).count(),
        'activities': zone.activity_set.filter(user=request.user)[:6],
        'nameservers': zone.nameservers, 'show_setup': request.GET.get('setup') == '1',
        'enabled_filter': enabled,
        'type_counts': zone.records.values('type').annotate(total=Count('pk')).order_by('type'),
        'host_count': zone.records.values('name').distinct().count(),
    })


@login_required
def record_detail(request, pk, record_pk):
    zone = owned(request, pk)
    record = get_object_or_404(Record, pk=record_pk, zone=zone)
    context = {'zone': zone, 'record': record}
    if modal_request(request):
        return JsonResponse({'html': render_to_string('dnsmanager/record_details.html', context, request=request)})
    return render(request, 'dnsmanager/record_details_page.html', context)


@login_required
@require_POST
def domain_check(request, pk=None):
    zone = owned(request, pk) if pk else None
    form = DomainCheckForm({'name': zone.name} if zone else request.POST)
    if not form.is_valid():
        error = ' '.join(str(error) for errors in form.errors.values() for error in errors)
        result = {'error': error}
        status = 400
    elif not cache.add(f'ns-check-user:{request.user.pk}', True, 5):
        result, status = {'error': 'لطفاً چند ثانیه تا بررسی بعدی صبر کنید.'}, 429
    else:
        try:
            from .domain_check import check_domain
            result = check_domain(form.cleaned_data['name'])
            with transaction.atomic():
                existing = Zone.objects.filter(name=result['domain']).first()
                if existing and existing.owner_id == request.user.pk:
                    Zone.objects.filter(pk=existing.pk, owner=request.user).update(ns_check=result)
                    result = dict(result, zone_url=reverse('zone_detail', args=[existing.pk]))
                elif result['status'] == 'matched' and form.cleaned_data['add_on_match']:
                    if existing:
                        result = dict(result, add_note='این دامنه در پنل قابل افزودن نیست؛ با مدیر سامانه هماهنگ کنید.')
                    else:
                        created = Zone.objects.create(owner=request.user, name=result['domain'], ns_check=result,
                                                      detected_nameservers=result['found'], description='افزوده‌شده پس از تطبیق NS عمومی')
                        audit(request.user, created, 'افزودن دامنه', 'هر دو NS عمومی با نام‌سرورهای تنظیم‌شده مطابق بودند؛ دامنه به‌صورت پیش‌نویس اضافه شد.')
                        result = dict(result, added=True, zone_url=reverse('zone_detail', args=[created.pk]))
            status = 200
        except ValidationError as error:
            result, status = {'error': ' '.join(error.messages)}, 400
        except IntegrityError:
            result, status = {'error': 'وضعیت دامنه هم‌زمان تغییر کرد؛ فهرست را تازه کنید.'}, 409
    if request.headers.get('Accept') == 'application/json':
        if result.get('added'):
            request.session['domain_check_result'] = result
        return JsonResponse({'html': render_to_string('dnsmanager/check_result.html', {'result': result}, request=request), 'result': result}, status=status)
    request.session['domain_check_result'] = result
    return redirect('zones')


@login_required
def record_form(request, pk, record_pk=None):
    zone = owned(request, pk)
    record = get_object_or_404(Record, pk=record_pk, zone=zone) if record_pk else Record(zone=zone)
    form = RecordForm(request.POST or None, instance=record, zone=zone)
    if request.method == 'POST':
        try:
            with transaction.atomic():
                locked = editable_zone(pk, request.user)
                # Validation happens after locking, including duplicate/CNAME checks.
                if form.is_valid():
                    record = form.save()
                    changed(locked)
                    audit(request.user, locked, 'ویرایش رکورد' if record_pk else 'افزودن رکورد', f'{record.name} · {record.type}')
                    messages.success(request, 'رکورد ذخیره شد؛ برای اعمال تغییرات، دامنه را منتشر کنید.')
                    if modal_request(request):
                        return JsonResponse({'ok': True, 'redirect_url': reverse('zone_detail', args=[pk])})
                    return redirect('zone_detail', pk=pk)
        except ZoneBusy as error:
            form.add_error(None, str(error))
        except IntegrityError:
            form.add_error(None, 'این رکورد قبلاً ثبت شده است؛ صفحه را تازه کنید.')
    return form_response(request, 'dnsmanager/record_form.html', {'form': form, 'zone': zone, 'record': record, 'editing': bool(record_pk), 'form_kind': 'record', 'submit_url': request.path})


@login_required
@require_POST
def record_toggle(request, pk, record_pk):
    zone = owned(request, pk)
    try:
        with transaction.atomic():
            zone = editable_zone(pk, request.user)
            record = get_object_or_404(Record, pk=record_pk, zone=zone)
            record.enabled = not record.enabled
            record.full_clean()
            record.save(update_fields=['enabled', 'updated_at'])
            changed(zone)
            audit(request.user, zone, 'فعال‌سازی رکورد' if record.enabled else 'غیرفعال‌سازی رکورد', f'{record.name} · {record.type}')
        messages.success(request, 'وضعیت رکورد ذخیره شد؛ انتشار دامنه لازم است.')
    except ZoneBusy as error:
        messages.error(request, str(error))
    return redirect('zone_detail', pk=pk)


@login_required
def record_delete(request, pk, record_pk):
    zone = owned(request, pk)
    record = get_object_or_404(Record, pk=record_pk, zone=zone)
    if request.method == 'POST':
        try:
            with transaction.atomic():
                zone = editable_zone(pk, request.user)
                record = get_object_or_404(Record, pk=record_pk, zone=zone)
                audit(request.user, zone, 'حذف رکورد', f'{record.name} · {record.type}')
                record.delete()
                changed(zone)
            messages.success(request, 'رکورد حذف شد؛ برای حذف از DNS، دامنه را منتشر کنید.')
            return redirect('zone_detail', pk=pk)
        except ZoneBusy as error:
            messages.error(request, str(error))
    return render(request, 'dnsmanager/confirm.html', {'zone': zone, 'record': record})


@login_required
@require_POST
def zone_publish(request, pk):
    zone = owned(request, pk)
    if request.POST.get('revision') != str(zone.revision):
        messages.error(request, 'دامنه از زمان باز شدن صفحه تغییر کرده است. نسخهٔ جدید را بررسی و دوباره منتشر کنید.')
    else:
        try:
            publish_zone(zone, request.user, int(request.POST['revision']))
            messages.success(request, 'نسخهٔ فعلی در PowerDNS منتشر شد. انتشار عمومی به تنظیم NS و انقضای کش وابسته است.')
        except (ProviderError, ZoneBusy) as error:
            messages.error(request, str(error))
    return redirect('zone_detail', pk=pk)


@login_required
def zone_delete(request, pk):
    zone = owned(request, pk)
    if request.method == 'POST':
        if request.POST.get('confirm_name') != zone.name:
            messages.error(request, 'برای تأیید، نام دامنه را دقیقاً وارد کنید.')
        else:
            try:
                delete_zone(zone, request.user)
                messages.success(request, 'دامنه و رکوردهای آن حذف شدند.')
                return redirect('zones')
            except (ProviderError, ZoneBusy) as error:
                messages.error(request, str(error))
    return render(request, 'dnsmanager/confirm.html', {'zone': zone})


@login_required
@never_cache
def zone_export(request, pk):
    zone = owned(request, pk)
    lines = [f'; faral dns server — draft revision {zone.revision}', '; Disabled records are commented out.',
             f'$ORIGIN {zone.name}.', f'$TTL {zone.default_ttl}',
             f'@ IN SOA {zone.nameservers[0] if zone.nameservers else "ns1.example.net."} hostmaster.{zone.name}. ( {zone.revision} 10800 3600 604800 3600 )']
    for ns in zone.nameservers:
        lines.append(f'@ {zone.default_ttl} IN NS {ns}')
    for record in zone.records.all():
        prefix = '' if record.enabled else '; DISABLED '
        lines.append(f'{prefix}{record.name} {record.ttl} IN {record.type} {record.dns_content}')
    response = HttpResponse('\n'.join(lines) + '\n', content_type='text/plain; charset=utf-8')
    response['Content-Disposition'] = f'attachment; filename="{zone.name}.zone"'
    return response


@login_required
@require_POST
def discover(request):
    if not request.user.is_staff:
        return JsonResponse({'error': 'شناسایی دامنه‌های سرور فقط برای مدیر سامانه مجاز است.'}, status=403)
    from .discovery import discover_zones
    try:
        result = discover_zones(request.user, force=request.POST.get('force') == '1')
        if request.headers.get('Accept') != 'application/json':
            messages.success(request, 'شناسایی سرور انجام شد؛ دامنه‌های قابل دریافت به پنل اضافه شدند.')
            return redirect('zones')
        return JsonResponse(result)
    except (ProviderError, ZoneBusy) as error:
        if request.headers.get('Accept') != 'application/json':
            messages.error(request, str(error))
            return redirect('zones')
        return JsonResponse({'error': str(error)}, status=503)


@login_required
def zone_pull(request, pk):
    zone = owned(request, pk)
    error = ''
    if request.method == 'POST':
        if request.POST.get('confirm_name') != zone.name:
            error = 'نام دامنه را دقیقاً وارد کنید تا کنارگذاشتن پیش‌نویس تأیید شود.'
        elif request.POST.get('revision') != str(zone.revision):
            error = 'نسخهٔ دامنه تغییر کرده است؛ اطلاعات فعلی را بررسی کنید.'
        else:
            from .discovery import pull_zone
            try:
                pull_zone(zone, request.user, zone.revision)
                messages.success(request, 'نسخهٔ فعلی سرور دریافت شد؛ رکوردهای پنل به‌روز شدند.')
                if modal_request(request):
                    return JsonResponse({'ok': True, 'redirect_url': reverse('zone_detail', args=[pk])})
                return redirect('zone_detail', pk=pk)
            except (ProviderError, ZoneBusy) as failure:
                error = str(failure)
    context = {'zone': zone, 'error': error}
    if modal_request(request):
        return JsonResponse({'ok': False, 'html': render_to_string('dnsmanager/modal_pull.html', context, request=request)}, status=422 if error else 200)
    return render(request, 'dnsmanager/pull_confirm.html', context)


@login_required
def activity_list(request):
    activities = Activity.objects.filter(user=request.user).select_related('zone')
    q = request.GET.get('q', '').strip()[:253]
    if q:
        activities = activities.filter(Q(zone_name__icontains=q) | Q(action__icontains=q) | Q(detail__icontains=q))
    return render(request, 'dnsmanager/activity.html', {'page_obj': Paginator(activities, 25).get_page(request.GET.get('page')), 'q': q})


@login_required
def connection(request):
    result = None
    if request.method == 'POST':
        if not request.user.is_staff:
            messages.error(request, 'آزمایش اتصال فقط برای مدیر سامانه در دسترس است.')
        else:
            try:
                with PowerDNS() as provider:
                    provider.health()
                result = True
                messages.success(request, 'پاسخ معتبر از API سرور PowerDNS دریافت شد.')
            except ProviderError as error:
                result = False
                messages.error(request, str(error))
    return render(request, 'dnsmanager/connection.html', {'connection_result': result})


@login_required
def guide(request):
    return render(request, 'dnsmanager/guide.html')


def health(request):
    from django.db import connection
    try:
        with connection.cursor() as cursor:
            cursor.execute('SELECT 1')
        return HttpResponse('ok', content_type='text/plain')
    except Exception:
        return HttpResponse('unavailable', status=503, content_type='text/plain')


def not_found(request, exception):
    return render(request, 'error.html', {'code': '404', 'error_title': 'این صفحه پیدا نشد.'}, status=404)


def server_error(request):
    return render(request, 'error.html', {'code': '500', 'error_title': 'خطایی در سرور رخ داد. دوباره تلاش کنید.'}, status=500)


@login_required
@never_cache
def domain_check_legacy(request):
    from .forms import DomainLookupForm
    from .lookup import check_nameservers
    form = DomainLookupForm(request.POST if request.method == 'POST' else None,
                           initial={'name': request.GET.get('name', '')[:253]})
    result = zone = None
    if request.method == 'POST' and form.is_valid():
        result = check_nameservers(form.cleaned_data['name'])
        zone = Zone.objects.filter(name=result['name'], owner=request.user).first()
    return render(request, 'dnsmanager/domain_check.html', {
        'form': form, 'result': result, 'zone': zone,
        'expected_nameservers': settings.DNS_NAMESERVERS,
    })
