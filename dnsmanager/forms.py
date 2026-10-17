from django import forms
from django.contrib.auth.forms import AuthenticationForm, PasswordChangeForm
from .models import Zone, Record
from .dns import zone_name


class DomainCheckForm(forms.Form):
    name = forms.CharField(label='نام دامنه', max_length=253, widget=forms.TextInput(attrs={
        'class': 'input', 'dir': 'ltr', 'placeholder': 'example.com', 'autocomplete': 'off', 'autocapitalize': 'none'}))
    add_on_match = forms.BooleanField(label='اگر NSها مطابق بودند، به دامنه‌های من اضافه شود', required=False)

    def clean_name(self):
        return zone_name(self.cleaned_data['name'])


class StyledForm:
    def style(self):
        for name, field in self.fields.items():
            field.widget.attrs['class'] = 'check-input' if isinstance(field.widget, forms.CheckboxInput) else 'input'
            if name not in ('description', 'comment'):
                field.widget.attrs['dir'] = 'ltr'


class LoginForm(StyledForm, AuthenticationForm):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.fields['username'].label = 'نام کاربری'
        self.fields['password'].label = 'رمز عبور'
        self.fields['username'].widget.attrs.update(placeholder='نام کاربری', autocomplete='username')
        self.fields['password'].widget.attrs.update(placeholder='رمز عبور', autocomplete='current-password')
        self.style()


class PasswordForm(StyledForm, PasswordChangeForm):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.style()


class ZoneForm(StyledForm, forms.ModelForm):
    class Meta:
        model = Zone
        fields = ['name', 'description', 'default_ttl']
        widgets = {'name': forms.TextInput(attrs={'placeholder': 'example.com', 'autocapitalize': 'none'}),
                   'description': forms.Textarea(attrs={'rows': 3, 'placeholder': 'این دامنه برای چه پروژه‌ای است؟'})}
        help_texts = {'name': 'بدون https:// و مسیر؛ دامنه‌های فارسی نیز پذیرفته می‌شوند.', 'default_ttl': 'برای رکوردهای جدید استفاده می‌شود؛ حداقل ۶۰ ثانیه.'}

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        if self.instance.pk:
            self.fields['name'].disabled = True
        self.style()


class RecordForm(StyledForm, forms.ModelForm):
    class Meta:
        model = Record
        fields = ['type', 'name', 'content', 'ttl', 'priority', 'weight', 'port', 'comment', 'enabled']
        widgets = {'content': forms.Textarea(attrs={'rows': 3, 'placeholder': '203.0.113.10'}),
                   'name': forms.TextInput(attrs={'placeholder': '@ / www / _sip._tcp'})}
        help_texts = {'name': 'برای ریشه @ و برای زیردامنه نام نسبی را بنویسید.',
                      'content': 'TXT را بدون کوتیشن وارد کنید. مقصد MX، CNAME و SRV نام کامل دامنه است.',
                      'ttl': 'زمان نگهداری پاسخ در کش؛ TTL یک RRset باید یکسان باشد.',
                      'priority': 'عدد کمتر، اولویت بیشتر. فقط برای MX و SRV.',
                      'weight': 'فقط برای SRV؛ بین ۰ تا ۶۵۵۳۵.', 'port': 'فقط برای SRV؛ بین ۰ تا ۶۵۵۳۵.'}

    def __init__(self, *args, zone, **kwargs):
        super().__init__(*args, **kwargs)
        self.instance.zone = zone
        if not self.instance.pk:
            self.initial['ttl'] = zone.default_ttl
        self.style()
