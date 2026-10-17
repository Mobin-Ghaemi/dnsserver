(() => {
  'use strict';
  const $ = (selector, root = document) => root.querySelector(selector);
  const toast = (message) => {
    const target = $('#toast');
    if (!target) return;
    target.textContent = message;
    target.classList.add('visible');
    clearTimeout(window.orbitToastTimer);
    window.orbitToastTimer = setTimeout(() => target.classList.remove('visible'), 3000);
  };
  document.addEventListener('click', async (event) => {
    const button = event.target.closest('[data-copy]');
    if (!button) return;
    try { await navigator.clipboard.writeText(button.dataset.copy); toast('در حافظه کپی شد.'); }
    catch (_) { toast('کپی در این مرورگر در دسترس نیست.'); }
  });
  $('[data-theme-toggle]')?.addEventListener('click', () => {
    const theme = document.documentElement.dataset.theme === 'dark' ? 'light' : 'dark';
    document.documentElement.dataset.theme = theme;
    try { localStorage.setItem('orbit-theme', theme); } catch (_) {}
  });
  const closeNav = () => { document.body.classList.remove('nav-open'); $('[data-toggle-nav]')?.setAttribute('aria-expanded', 'false'); };
  $('[data-toggle-nav]')?.addEventListener('click', () => {
    const open = document.body.classList.toggle('nav-open');
    $('[data-toggle-nav]').setAttribute('aria-expanded', String(open));
  });
  $('[data-close-nav]')?.addEventListener('click', closeNav);
  document.addEventListener('keydown', (event) => {
    if (event.key === 'Escape') closeNav();
    if (event.key === '/' && !$('#app-modal')?.open && !event.ctrlKey && !event.metaKey && !['INPUT', 'TEXTAREA', 'SELECT'].includes(document.activeElement.tagName)) {
      event.preventDefault(); $('[data-global-search]')?.focus();
    }
  });
  document.querySelectorAll('[data-dismiss-message]').forEach(button => button.addEventListener('click', () => button.closest('.message').remove()));
  document.querySelectorAll('[data-submit-form]').forEach(form => form.addEventListener('submit', () => {
    const button = form.querySelector('[data-submit-label]');
    if (!button) return;
    button.disabled = true;
    button.dataset.originalLabel = button.innerHTML;
    button.textContent = button.dataset.submitLabel;
  }));
  window.addEventListener('pageshow', () => document.querySelectorAll('[data-original-label]').forEach(button => {
    button.disabled = false; button.innerHTML = button.dataset.originalLabel;
  }));

  const initRecordForm = (root = document) => {
    const form = $('[data-record-form]', root);
    if (!form) return;
    const examples = {
      A: ['یک نام دامنه را به آدرس IPv4 سرور متصل می‌کند.', '203.0.113.10'],
      AAAA: ['یک نام دامنه را به آدرس IPv6 سرور متصل می‌کند.', '2001:db8::10'],
      CNAME: ['یک نام را به نام دامنهٔ دیگری متصل می‌کند. در ریشهٔ دامنه مجاز نیست.', 'example.com.'],
      MX: ['سرور دریافت ایمیل دامنه را مشخص می‌کند. اولویت را جدا وارد کنید.', 'mail.example.com.'],
      TXT: ['برای تأیید مالکیت، SPF و DKIM استفاده می‌شود. متن را بدون کوتیشن وارد کنید.', 'v=spf1 -all'],
      NS: ['مدیریت DNS یک زیردامنه را واگذار می‌کند. NS ریشه جداگانه مدیریت می‌شود.', 'ns1.example.com.'],
      SRV: ['مقصد و پورت یک سرویس را مشخص می‌کند. نامی مثل _sip._tcp وارد کنید.', 'sip.example.com.'],
      CAA: ['مجوز صدور گواهی TLS را به صادرکننده‌های مشخص محدود می‌کند.', '0 issue "letsencrypt.org"'],
      PTR: ['برای DNS معکوس است و نیازمند واگذاری reverse zone توسط ارائه‌دهندهٔ IP است.', 'host.example.com.'],
    };
    const setText = (selector, value) => { const element = $(selector, root); if (element) element.textContent = value; };
    const updateType = () => {
      const kind = $('[name=type]', form).value;
      const info = examples[kind];
      setText('[data-record-title]', `رکورد ${kind} چیست؟`);
      setText('[data-record-description]', info[0]);
      setText('[data-record-example]', info[1]);
      $('[name=content]', form).placeholder = info[1];
      ['priority', 'weight', 'port'].forEach(field => {
        const visible = kind === 'SRV' || (kind === 'MX' && field === 'priority');
        const input = $(`[name=${field}]`, form);
        input.closest('.form-field').hidden = !visible;
        const label = input.closest('.form-field').querySelector('[data-optional-label]');
        if (label) label.textContent = visible ? 'الزامی' : 'اختیاری';
        input.required = visible;
        input.disabled = !visible;
      });
    };
    const updatePreview = () => {
      const name = $('[name=name]', form).value.trim();
      const zone = form.dataset.zone;
      setText('[data-record-preview]', !name || name === '@' ? `${zone}.` : name.endsWith('.') ? name : name.endsWith(`.${zone}`) || name === zone ? `${name}.` : `${name}.${zone}.`);
    };
    $('[name=type]', form).addEventListener('change', updateType);
    $('[name=name]', form).addEventListener('input', updatePreview);
    updateType(); updatePreview();
  };
  initRecordForm();

  const dialog = $('#app-modal');
  const modalBody = $('[data-modal-body]');
  let modalLoad;
  let modalBusy = false;
  let refreshOnClose = false;
  let pendingDiscoveryRefresh = false;
  const renderModal = (html) => {
    // HTML comes only from authenticated, CSRF-protected same-origin Django views.
    modalBody.innerHTML = html;
    $('#modal-title').textContent = $('[data-modal-title]', modalBody)?.dataset.modalTitle || 'مدیریت DNS';
    modalBody.scrollTop = 0;
    initRecordForm(modalBody);
    const alert = $('[role=alert]', modalBody);
    const focus = alert || $('input:not([type=hidden]):not(:disabled),select,textarea,a.button,button', modalBody);
    if (focus) { if (alert) focus.tabIndex = -1; focus.focus({preventScroll:true}); }
  };
  const showModalError = (message) => {
    const box = document.createElement('div');
    box.className = 'form-errors'; box.role = 'alert'; box.textContent = message;
    modalBody.prepend(box); box.tabIndex = -1; box.focus();
  };
  const closeModal = () => { if (!modalBusy) dialog?.close(); };
  document.addEventListener('click', async (event) => {
    if (event.target.closest('[data-close-modal]')) { closeModal(); return; }
    const link = event.target.closest('a[data-modal]');
    if (!link || !dialog?.showModal || event.button !== 0 || event.ctrlKey || event.metaKey || event.shiftKey || event.altKey) return;
    const url = new URL(link.href);
    if (url.origin !== location.origin) return;
    event.preventDefault();
    modalLoad?.abort();
    modalLoad = new AbortController();
    refreshOnClose = false;
    modalBody.innerHTML = '<div class="modal-loading"><span></span>در حال آماده‌سازی فرم…</div>';
    $('#modal-title').textContent = 'یک لحظه…';
    if (!dialog.open) dialog.showModal();
    document.body.classList.add('modal-open');
    try {
      const response = await fetch(url, {headers:{'X-Orbit-Modal':'1','Accept':'application/json'}, credentials:'same-origin', signal:modalLoad.signal});
      if (response.redirected) { location.assign(response.url); return; }
      if (!response.ok) throw new Error('دریافت فرم انجام نشد. صفحه را تازه کنید و دوباره تلاش کنید.');
      const result = await response.json();
      if (dialog.open) renderModal(result.html);
    } catch (error) { if (error.name !== 'AbortError') showModalError(error.message || 'ارتباط با پنل برقرار نشد.'); }
  });
  dialog?.addEventListener('cancel', (event) => { if (modalBusy) event.preventDefault(); });
  dialog?.addEventListener('click', (event) => { if (event.target === dialog) closeModal(); });
  dialog?.addEventListener('close', () => {
    modalLoad?.abort(); document.body.classList.remove('modal-open');
    if (refreshOnClose || pendingDiscoveryRefresh) location.reload();
  });
  document.addEventListener('submit', async (event) => {
    const form = event.target.closest('[data-modal-form]');
    if (!form || !dialog?.open || !dialog.contains(form)) return;
    event.preventDefault();
    if (modalBusy) return;
    const data = new FormData(form);
    const button = $('button[type=submit]', form);
    const original = button.innerHTML;
    button.disabled = true; button.textContent = 'در حال ذخیره…';
    modalBusy = true;
    $('.modal-close').disabled = true;
    try {
      const response = await fetch(form.action, {method:'POST',body:data,credentials:'same-origin',headers:{'X-Orbit-Modal':'1','Accept':'application/json'}});
      if (response.redirected) { location.assign(response.url); return; }
      if (!response.headers.get('content-type')?.includes('application/json')) throw new Error('ذخیره انجام نشد. نشست یا دسترسی شما را بررسی و دوباره تلاش کنید.');
      const result = await response.json();
      if (result.html) {
        renderModal(result.html);
        refreshOnClose = Boolean(result.ok);
      } else if (result.ok) {
        location.reload();
      } else {
        throw new Error(result.error || 'ذخیره انجام نشد. دوباره تلاش کنید.');
      }
    } catch (error) { showModalError(error.message || 'ارتباط قطع شد. پیش از تلاش مجدد، نتیجه را در فهرست بررسی کنید.'); }
    finally {
      modalBusy = false; $('.modal-close').disabled = false;
      if (button.isConnected) { button.disabled = false; button.innerHTML = original; }
    }
  });

  const discovery = $('[data-discovery-url]');
  if (discovery && discovery.dataset.enabled === '1') {
    let running = false;
    const runDiscovery = async (force = false) => {
      if (running || document.hidden || dialog?.open) return;
      running = true;
      const button = $('[data-discover-now]', discovery);
      const status = $('[data-discovery-status]', discovery);
      button.disabled = true;
      discovery.classList.add('is-loading');
      status.textContent = 'در حال دریافت دامنه‌ها و رکوردهای سرور…';
      const data = new FormData($('[data-discovery-form]', discovery));
      data.set('force', force ? '1' : '0');
      try {
        const response = await fetch(discovery.dataset.discoveryUrl, {method:'POST',body:data,credentials:'same-origin',headers:{'Accept':'application/json'}});
        if (response.redirected) { location.assign(response.url); return; }
        const result = await response.json();
        if (!response.ok) throw new Error(result.error || 'دریافت اطلاعات سرور انجام نشد.');
        discovery.classList.remove('has-error');
        if (result.deferred) status.textContent = 'شناسایی خودکار فعال است؛ بررسی‌های سرور با فاصله انجام می‌شوند.';
        else {
          status.textContent = `${result.scanned} دامنه بررسی شد؛ ${result.created} دامنهٔ جدید و ${result.updated} به‌روزرسانی.`;
          if (result.problems?.length) status.textContent += ` دریافت کامل ${result.problems.length} دامنه انجام نشد: ${result.problems.slice(0,3).join('، ')}`;
          if (result.remaining) status.textContent += ` ${result.remaining} دامنه در نوبت بعد بررسی می‌شوند.`;
          if (result.skipped && !result.problems?.length) status.textContent += ' پیش‌نویس‌ها و دامنه‌های سایر کاربران حفظ شدند.';
        }
        if (result.changed || force) {
          if (dialog?.open) pendingDiscoveryRefresh = true;
          else location.reload();
        }
      } catch (error) {
        discovery.classList.add('has-error');
        status.textContent = error.message || 'اتصال به سرویس DNS برقرار نشد.';
      } finally { running = false; button.disabled = false; discovery.classList.remove('is-loading'); }
    };
    $('[data-discovery-form]', discovery).addEventListener('submit', event => { event.preventDefault(); runDiscovery(true); });
    if (discovery.dataset.auto === '1') {
      runDiscovery();
      setInterval(() => runDiscovery(), 60000);
    }
  }
})();
