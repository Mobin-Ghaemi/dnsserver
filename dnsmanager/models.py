import uuid
from django.conf import settings
from django.core.exceptions import ValidationError
from django.core.validators import MinValueValidator, MaxValueValidator
from django.db import models
from .dns import RECORD_TYPES, zone_name, record_name, canonical_content


class Zone(models.Model):
    external_id = models.UUIDField(default=uuid.uuid4, unique=True, editable=False)
    owner = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.PROTECT, related_name='zones')
    name = models.CharField('نام دامنه', max_length=253, unique=True)
    description = models.CharField('یادداشت', max_length=250, blank=True)
    default_ttl = models.PositiveIntegerField('TTL پیش‌فرض', default=3600, validators=[MinValueValidator(60), MaxValueValidator(2147483647)])
    revision = models.PositiveIntegerField(default=1)
    published_revision = models.PositiveIntegerField(default=0)
    provisioned = models.BooleanField(default=False)
    source = models.CharField(max_length=10, default='local', choices=[('local', 'پنل'), ('server', 'سرور DNS')])
    provider_identity = models.CharField(max_length=64, blank=True)
    remote_account = models.CharField(max_length=255, blank=True)
    remote_snapshot = models.CharField(max_length=64, blank=True)
    remote_kind = models.CharField(max_length=20, blank=True)
    detected_nameservers = models.JSONField(default=list, blank=True)
    unmanaged_rrsets = models.JSONField(default=list, blank=True)
    last_synced_at = models.DateTimeField(null=True, blank=True)
    sync_note = models.CharField(max_length=500, blank=True)
    ns_check = models.JSONField(default=dict, blank=True)
    publish_token = models.UUIDField(null=True, editable=False)
    publishing_until = models.DateTimeField(null=True, editable=False)
    last_published_at = models.DateTimeField(null=True, blank=True)
    last_error = models.CharField(max_length=500, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ['-updated_at']
        verbose_name = 'دامنه'
        verbose_name_plural = 'دامنه‌ها'

    def __str__(self):
        return self.name

    def clean(self):
        self.name = zone_name(self.name)

    @property
    def status(self):
        if self.last_error:
            return 'error'
        return 'published' if self.published_revision == self.revision else 'draft'

    @property
    def status_label(self):
        return {'published': 'منتشر شده', 'draft': 'پیش‌نویس', 'error': 'خطای انتشار'}[self.status]

    @property
    def is_readonly(self):
        return self.remote_kind.lower() in ('slave', 'secondary', 'consumer')

    @property
    def nameservers(self):
        from .configuration import default_nameservers
        return self.detected_nameservers or default_nameservers()

    @property
    def website_url(self):
        return 'https://' + self.name + '/'


class Record(models.Model):
    zone = models.ForeignKey(Zone, on_delete=models.CASCADE, related_name='records')
    name = models.CharField('نام رکورد', max_length=253, default='@')
    type = models.CharField('نوع رکورد', max_length=5, choices=[(t, t) for t in RECORD_TYPES], default='A')
    content = models.TextField('مقدار رکورد', max_length=4096)
    ttl = models.PositiveIntegerField('TTL (ثانیه)', default=3600, validators=[MinValueValidator(0), MaxValueValidator(2147483647)])
    priority = models.PositiveIntegerField('اولویت', null=True, blank=True, validators=[MaxValueValidator(65535)])
    weight = models.PositiveIntegerField('وزن', null=True, blank=True, validators=[MaxValueValidator(65535)])
    port = models.PositiveIntegerField('پورت', null=True, blank=True, validators=[MaxValueValidator(65535)])
    enabled = models.BooleanField('رکورد فعال باشد', default=True)
    comment = models.CharField('یادداشت', max_length=250, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ['name', 'type', 'pk']
        verbose_name = 'رکورد'
        verbose_name_plural = 'رکوردها'
        constraints = [models.UniqueConstraint(fields=['zone', 'name', 'type', 'content', 'priority', 'weight', 'port'], name='unique_dns_record')]

    @property
    def fqdn(self):
        return self.zone.name + '.' if self.name == '@' else self.name + '.' + self.zone.name + '.'

    @property
    def full_name(self):
        return self.fqdn.rstrip('.')

    @property
    def website_url(self):
        if self.type not in ('A', 'AAAA', 'CNAME') or '*' in self.name or '_' in self.name:
            return ''
        return 'https://' + self.full_name + '/'

    @property
    def purpose(self):
        if self.type == 'TXT':
            if self.name.startswith('_dmarc') or self.content.startswith('v=DMARC1'):
                return 'سیاست ایمیل · DMARC'
            if '._domainkey' in self.name or self.content.startswith('v=DKIM1'):
                return 'امضای ایمیل · DKIM'
            if self.content.startswith('v=spf1'):
                return 'مجوز ارسال ایمیل · SPF'
            return 'متن و تأیید مالکیت'
        return {'A': 'آدرس IPv4', 'AAAA': 'آدرس IPv6', 'CNAME': 'نام مستعار', 'MX': 'سرور ایمیل',
                'NS': 'واگذاری زیردامنه', 'SRV': 'مقصد سرویس', 'CAA': 'مجوز صدور گواهی', 'PTR': 'DNS معکوس'}.get(self.type, self.type)

    @property
    def dns_content(self):
        return canonical_content(self.type, self.content, self.priority, self.weight, self.port)

    def clean(self):
        self.name = record_name(self.name, self.zone.name)
        canonical = self.dns_content
        if self.type in ('A', 'AAAA', 'CNAME', 'NS', 'PTR', 'CAA'):
            self.content = canonical
        elif self.type in ('MX', 'SRV'):
            self.content = canonical.split()[-1]
        if self.type not in ('MX', 'SRV'):
            self.priority = None
        if self.type != 'SRV':
            self.weight = self.port = None
        if self.name == '@' and self.type == 'CNAME':
            raise ValidationError('در ریشهٔ دامنه CNAME مجاز نیست؛ از A یا AAAA استفاده کنید.')
        if self.type == 'CNAME' and self.content == self.fqdn:
            raise ValidationError('CNAME نمی‌تواند به خودش اشاره کند.')
        if self.name == '@' and self.type == 'NS':
            raise ValidationError('NS اصلی دامنه از DNS_NAMESERVERS سرور مدیریت می‌شود؛ NS این فرم برای زیردامنه است.')
        if self.type == 'SRV' and not self.name.startswith('_'):
            raise ValidationError('نام SRV باید مانند _sip._tcp باشد.')
        others = Record.objects.filter(zone=self.zone, name=self.name).exclude(pk=self.pk)
        # Check disabled records too, so enabling one cannot create an invalid zone.
        if (self.type == 'CNAME' and others.exists()) or others.filter(type='CNAME').exists():
            raise ValidationError('CNAME باید تنها رکورد این نام باشد.')
        if others.filter(type=self.type).exclude(ttl=self.ttl).exists():
            raise ValidationError('TTL رکوردهای هم‌نام و هم‌نوع باید یکسان باشد.')
        if others.filter(type=self.type, content=self.content, priority=self.priority, weight=self.weight, port=self.port).exists():
            raise ValidationError('این رکورد قبلاً ثبت شده است.')
        if self.type == 'MX':
            mx = others.filter(type='MX')
            if (self.content == '.' and mx.exists()) or mx.filter(content='.').exists():
                raise ValidationError('Null MX نمی‌تواند کنار MX دیگری باشد.')

    def __str__(self):
        return f'{self.name} {self.type}'


class Activity(models.Model):
    user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.SET_NULL, null=True)
    zone = models.ForeignKey(Zone, on_delete=models.SET_NULL, null=True, blank=True)
    zone_name = models.CharField(max_length=253)
    action = models.CharField(max_length=60)
    detail = models.CharField(max_length=300, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ['-created_at', '-pk']
        verbose_name = 'فعالیت'
        verbose_name_plural = 'فعالیت‌ها'


class DiscoveryState(models.Model):
    """A database-backed discovery lease shared by all Gunicorn workers."""
    last_attempt = models.DateTimeField(null=True)
    last_success = models.DateTimeField(null=True)
    locked_until = models.DateTimeField(null=True)
    token = models.UUIDField(null=True)
    error = models.CharField(max_length=500, blank=True)
    summary = models.JSONField(default=dict)
    cursor = models.PositiveIntegerField(default=0)
