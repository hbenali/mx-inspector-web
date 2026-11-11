/* MX Checker: client-side MX lookup over DNS-over-HTTPS (dns.google) and BIND line generator.
   No dependencies, no inline code (CSP: script-src 'self'). */
(function () {
  'use strict';

  var DOH = 'https://dns.google/resolve';
  var $ = function (id) { return document.getElementById(id); };

  // ---- Providers (detection by MX host suffix, and generator presets) ----
  var PROVIDERS = [
    { name: 'Google Workspace', match: /(^|\.)(aspmx\.l\.google\.com|googlemail\.com|google\.com)\.?$/i,
      preset: [[1, 'aspmx.l.google.com'], [5, 'alt1.aspmx.l.google.com'], [5, 'alt2.aspmx.l.google.com'], [10, 'alt3.aspmx.l.google.com'], [10, 'alt4.aspmx.l.google.com']] },
    { name: 'Microsoft 365 / Exchange Online', match: /\.mail\.protection\.outlook\.com\.?$/i, preset: 'm365' },
    { name: 'Proton Mail', match: /\.protonmail\.ch\.?$/i, preset: [[10, 'mail.protonmail.ch'], [20, 'mailsec.protonmail.ch']] },
    { name: 'Fastmail', match: /\.messagingengine\.com\.?$/i, preset: [[10, 'in1-smtp.messagingengine.com'], [20, 'in2-smtp.messagingengine.com']] },
    { name: 'Zoho Mail', match: /\.zoho\.(com|eu|in|com\.au|jp)\.?$/i, preset: [[10, 'mx.zoho.com'], [20, 'mx2.zoho.com'], [50, 'mx3.zoho.com']] },
    { name: 'iCloud Mail', match: /\.mail\.icloud\.com\.?$/i, preset: [[10, 'mx01.mail.icloud.com'], [10, 'mx02.mail.icloud.com']] },
    { name: 'OVHcloud Email', match: /\.mail\.ovh\.net\.?$/i, preset: [[1, 'mx1.mail.ovh.net'], [5, 'mx2.mail.ovh.net'], [100, 'mx3.mail.ovh.net']] },
    { name: 'Mailgun', match: /\.mailgun\.org\.?$/i },
    { name: 'Amazon SES / WorkMail', match: /\.amazonaws\.com\.?$/i },
    { name: 'Mimecast', match: /\.mimecast\.com\.?$/i },
    { name: 'Proofpoint', match: /\.pphosted\.com\.?$/i },
    { name: 'Barracuda', match: /\.barracudanetworks\.com\.?$/i },
    { name: 'Yahoo Mail', match: /\.yahoodns\.net\.?$/i },
    { name: 'Gandi Mail', match: /\.gandi\.net\.?$/i },
    { name: 'IONOS', match: /\.(kundenserver|ionos)\.(de|com)\.?$/i },
    { name: 'Cloudflare Email Routing', match: /\.mx\.cloudflare\.net\.?$/i }
  ];
  function detectProvider(host) {
    for (var i = 0; i < PROVIDERS.length; i++) if (PROVIDERS[i].match.test(host)) return PROVIDERS[i].name;
    return null;
  }

  // ---- DNS helpers ----
  function normalizeDomain(input) {
    var d = String(input || '').trim().toLowerCase().replace(/^[a-z]+:\/\//, '').replace(/^.*@/, '').replace(/[\/?#].*$/, '').replace(/\.+$/, '');
    return d;
  }
  function validDomain(d) {
    if (!d || d.length > 253) return false;
    return d.split('.').every(function (l) { return /^[a-z0-9_]([a-z0-9_-]{0,61}[a-z0-9_])?$/i.test(l) || /^xn--[a-z0-9-]+$/i.test(l); });
  }
  async function doh(name, type) {
    var res = await fetch(DOH + '?name=' + encodeURIComponent(name) + '&type=' + type);
    if (!res.ok) throw new Error('DNS query failed (HTTP ' + res.status + ')');
    return res.json();
  }
  function isPrivateV4(ip) {
    var p = ip.split('.').map(Number);
    return p[0] === 10 || p[0] === 127 || p[0] === 0 || (p[0] === 169 && p[1] === 254) || (p[0] === 172 && p[1] >= 16 && p[1] <= 31) || (p[0] === 192 && p[1] === 168) || (p[0] === 100 && p[1] >= 64 && p[1] <= 127);
  }
  function isPrivateV6(ip) {
    return /^(::1?|fe[89ab][0-9a-f]:|f[cd][0-9a-f]{2}:)/i.test(ip);
  }
  async function resolveHost(host) {
    var out = { host: host, a: [], aaaa: [], cname: null, error: null };
    try {
      var r = await Promise.all([doh(host, 'A'), doh(host, 'AAAA')]);
      var a = r[0], aaaa = r[1];
      var all = (a.Answer || []).concat(aaaa.Answer || []);
      var cn = all.filter(function (x) { return x.type === 5; })[0];
      if (cn) out.cname = cn.data.replace(/\.$/, '');
      out.a = (a.Answer || []).filter(function (x) { return x.type === 1; }).map(function (x) { return x.data; });
      out.aaaa = (aaaa.Answer || []).filter(function (x) { return x.type === 28; }).map(function (x) { return x.data; });
      if (a.Status === 3 && aaaa.Status === 3) out.error = 'NXDOMAIN';
    } catch (e) { out.error = e.message; }
    return out;
  }

  function ptrName(ip) {
    if (ip.indexOf(':') === -1) return ip.split('.').reverse().join('.') + '.in-addr.arpa';
    var parts = ip.split('::'), head = parts[0] ? parts[0].split(':') : [], tail = parts[1] ? parts[1].split(':') : [];
    var fill = new Array(Math.max(0, 8 - head.length - tail.length)).fill('0');
    var hex = head.concat(fill, tail).map(function (g) { return ('0000' + g).slice(-4); }).join('');
    return hex.split('').reverse().join('.') + '.ip6.arpa';
  }
  // Extra per-host data: reverse DNS of the first address, and DANE TLSA records.
  async function hostExtras(res) {
    var ip = res.a[0] || res.aaaa[0];
    res.ptr = null; res.tlsa = 0;
    var jobs = [];
    if (ip) jobs.push(doh(ptrName(ip), 'PTR').then(function (d) {
      var p = (d.Answer || []).filter(function (x) { return x.type === 12; })[0];
      res.ptr = p ? p.data.replace(/\.$/, '').toLowerCase() : '';
    }).catch(function () { res.ptr = null; }));
    jobs.push(doh('_25._tcp.' + res.host, 'TLSA').then(function (d) {
      res.tlsa = (d.Answer || []).filter(function (x) { return x.type === 52; }).length;
    }).catch(function () {}));
    await Promise.all(jobs);
  }
  // Domain-level mail transport security: MTA-STS and TLS-RPT TXT records.
  async function transportPolicy(domain) {
    var get = function (name, re) {
      return doh(name, 'TXT').then(function (d) {
        var t = (d.Answer || []).filter(function (x) { return x.type === 16; }).map(function (x) { return x.data.replace(/^"|"$/g, '').replace(/"\s*"/g, ''); });
        return t.filter(function (v) { return re.test(v); })[0] || null;
      }).catch(function () { return null; });
    };
    var r = await Promise.all([get('_mta-sts.' + domain, /^v=STSv1/i), get('_smtp._tls.' + domain, /^v=TLSRPTv1/i)]);
    return { mtasts: r[0], tlsrpt: r[1] };
  }

  // Parse an MX answer "10 mail.example.com." -> {pref, host}
  function parseMX(data) {
    var m = String(data).trim().match(/^(\d+)\s+(\S+)$/);
    if (!m) return null;
    return { pref: parseInt(m[1], 10), host: m[2].replace(/\.$/, '').toLowerCase() || '.' };
  }

  async function queryMX(domain) {
    var data = await doh(domain, 'MX');
    if (data.Status === 3) throw new Error('Domain "' + domain + '" does not exist (NXDOMAIN)');
    if (data.Status !== 0) throw new Error('DNS lookup error: ' + (data.Comment || 'code ' + data.Status));
    var records = (data.Answer || []).filter(function (r) { return r.type === 15; }).map(function (r) { return parseMX(r.data); }).filter(Boolean);
    records.sort(function (x, y) { return x.pref - y.pref || x.host.localeCompare(y.host); });
    return { domain: domain, records: records, dnssec: data.AD === true };
  }

  // ---- Checks ----
  function buildChecks(result, resolved, policy) {
    var checks = [];
    var add = function (level, text) { checks.push({ level: level, text: text }); };
    var recs = result.records;

    var isNull = recs.length === 1 && recs[0].host === '.';
    if (isNull) {
      add('pass', 'Null MX (RFC 7505): the domain states it does not accept email.');
      if (recs[0].pref !== 0) add('warn', 'Null MX should use priority 0, found ' + recs[0].pref + '.');
      return checks;
    }
    if (recs.some(function (r) { return r.host === '.'; })) add('fail', 'A null MX ("."") is mixed with real mail hosts; a null MX must be the only MX record.');

    add('pass', recs.length + ' MX record' + (recs.length > 1 ? 's' : '') + ' found.');
    if (recs.length === 1) add('info', 'Only one MX host: no backup if it is unreachable (senders will queue and retry for days).');

    var prefs = {};
    recs.forEach(function (r) { prefs[r.pref] = (prefs[r.pref] || 0) + 1; });
    var dup = Object.keys(prefs).filter(function (p) { return prefs[p] > 1; });
    if (dup.length) add('info', 'Several hosts share priority ' + dup.join(', ') + ': senders pick among them at random (load sharing).');

    var seen = {}, noV6 = [];
    recs.forEach(function (r) {
      if (r.host === '.') return;
      var res = resolved[r.host];
      var h = r.host;
      if (seen[h]) add('warn', h + ' is listed more than once.');
      seen[h] = true;
      if (/^\d{1,3}(\.\d{1,3}){3}$/.test(h) || h.indexOf(':') !== -1) { add('fail', h + ' is an IP address; an MX target must be a hostname.'); return; }
      if (!res) return;
      if (res.error === 'NXDOMAIN') { add('fail', h + ' does not exist (NXDOMAIN): mail to it cannot be delivered.'); return; }
      if (res.error) { add('warn', h + ': address lookup failed (' + res.error + ').'); return; }
      if (res.cname) add('fail', h + ' is a CNAME to ' + res.cname + '; an MX target must have address records directly (RFC 2181 §10.3).');
      if (!res.a.length && !res.aaaa.length) add('fail', h + ' has no A or AAAA record.');
      else {
        if (res.a.some(isPrivateV4) || res.aaaa.some(isPrivateV6)) add('fail', h + ' resolves to a private or loopback address; it is unreachable from the internet.');
        if (!res.aaaa.length) noV6.push(h);
      }
      if (res.ptr === '') add('warn', h + ': the first address has no reverse DNS (PTR); some receivers distrust such hosts.');
      if (res.tlsa) add('pass', h + ' publishes ' + res.tlsa + ' DANE TLSA record(s) for SMTP.');
      if (h === result.domain) add('info', 'The mail host is the domain apex itself (' + h + ').');
    });
    if (noV6.length) add('info', (noV6.length === 1 ? noV6[0] + ' has' : noV6.length + ' mail hosts have') + ' no IPv6 (AAAA) record' + (noV6.length === 1 ? '.' : ' (' + noV6.join(', ') + ').'));
    if (!checks.some(function (c) { return c.level === 'fail'; })) add('pass', 'Every mail host resolves to an address.');
    if (policy) {
      add(policy.mtasts ? 'pass' : 'info', policy.mtasts ? 'MTA-STS is published (' + policy.mtasts + '): senders can require TLS to your MX hosts.' : 'No MTA-STS record (_mta-sts): TLS to your MX hosts is opportunistic and can be downgraded.');
      add(policy.tlsrpt ? 'pass' : 'info', policy.tlsrpt ? 'TLS-RPT is published: you receive reports on TLS delivery failures.' : 'No TLS-RPT record (_smtp._tls): you will not get reports on TLS failures.');
    }
    if (result.dnssec) add('info', 'The resolver validated the answer with DNSSEC (AD flag set).');
    return checks;
  }

  // ---- Rendering ----
  function el(tag, cls, text) {
    var e = document.createElement(tag);
    if (cls) e.className = cls;
    if (text != null) e.textContent = text;
    return e;
  }
  var views = { placeholder: $('placeholderState'), records: $('recordsContainer'), error: $('errorContainer') };
  function setView(name) { Object.keys(views).forEach(function (k) { views[k].hidden = k !== name; }); }

  function renderResult(result, resolved, checks, fallback) {
    var box = views.records;
    box.replaceChildren();
    var recs = result.records;
    var worst = checks.some(function (c) { return c.level === 'fail'; }) ? 'fail'
      : checks.some(function (c) { return c.level === 'warn'; }) ? 'warn' : 'ok';

    var state = el('div', 'state ' + (recs.length ? worst : 'warn'));
    if (!recs.length) {
      state.append(el('h2', 'state-title', 'No MX records found'));
      var p = el('p');
      p.append('Domain ');
      p.append(el('code', null, result.domain));
      p.append(fallback && fallback.length
        ? ' has no MX record. Per RFC 5321 senders fall back to its address record (' + fallback.join(', ') + '), which works but is rarely intended.'
        : ' has no MX and no address record: it cannot receive email.');
      state.append(p);
      box.append(state);
      return;
    }
    state.append(el('h2', 'state-title', 'MX records for'));
    state.append(el('span', 'badge-domain', result.domain));
    var providers = [];
    recs.forEach(function (r) { var n = detectProvider(r.host); if (n && providers.indexOf(n) < 0) providers.push(n); });
    if (providers.length) {
      var pv = el('p', 'provider');
      pv.append('Detected provider: ');
      pv.append(el('strong', null, providers.join(', ')));
      state.append(pv);
    }
    box.append(state);

    var list = el('ul', 'record-list');
    var primary = recs[0].pref;
    recs.forEach(function (r) {
      var li = el('li', 'mx-item');
      var head = el('div', 'mx-head');
      var pr = el('span', 'flag-tag');
      pr.append(el('span', 'k', 'priority'));
      pr.append(String(r.pref));
      head.append(pr);
      head.append(el('span', 'mx-host', r.host));
      if (r.host !== '.') head.append(el('span', 'mx-role', r.pref === primary ? 'primary' : 'backup'));
      li.append(head);
      var res = resolved[r.host];
      if (res) {
        var ad = el('div', 'mx-addrs');
        var parts = [];
        if (res.cname) parts.push('CNAME → ' + res.cname);
        parts = parts.concat(res.a, res.aaaa);
        if (res.error || !parts.length) { var b = el('span', 'bad', res.error || 'no address records'); ad.append(b); }
        else ad.textContent = parts.join('  ·  ');
        li.append(ad);
      }
      list.append(li);
    });
    box.append(list);
    box.append(el('div', 'count', recs.length + ' record(s) found'));

    var ul = el('ul', 'checks');
    var labels = { pass: 'ok', warn: 'warn', fail: 'fail', info: 'note' };
    var order = { fail: 0, warn: 1, info: 2, pass: 3 };
    checks.slice().sort(function (a, b) { return order[a.level] - order[b.level]; }).forEach(function (c) {
      var li = el('li');
      li.append(el('span', 'chk ' + c.level, labels[c.level]));
      li.append(el('span', null, c.text));
      ul.append(li);
    });
    box.append(ul);
    box.append(siblingLinks(result.domain));
  }

  // Links to the same domain in the sibling tools of the suite.
  function siblingLinks(domain) {
    var wrap = el('p', 'provider');
    wrap.append('Also check ' + domain + ': ');
    [['spf', 'SPF'], ['dkim', 'DKIM'], ['dmarc', 'DMARC'], ['bimi', 'BIMI'], ['dnssec', 'DNSSEC'], ['caa', 'CAA']].forEach(function (t, i) {
      if (i) wrap.append(' · ');
      var a = el('a', 'link', t[1]);
      a.href = 'https://' + t[0] + '.hbenali.ovh/?domain=' + encodeURIComponent(domain);
      a.target = '_blank'; a.rel = 'noopener noreferrer';
      wrap.append(a);
    });
    return wrap;
  }

  function renderError(domain, msg) {
    var box = views.error;
    box.replaceChildren();
    var s = el('div', 'state fail error-message');
    s.setAttribute('role', 'alert');
    s.append(el('h2', 'state-title', domain ? 'Error checking ' + domain : 'Error'));
    s.append(el('p', null, msg));
    box.append(s);
  }

  // ---- Lookup flow ----
  var domainInput = $('domainInput'), checkBtn = $('checkBtn'), btnText = $('btnText'), btnLoader = $('btnLoader');
  var lastRecords = null;

  function setLoading(on) {
    checkBtn.disabled = on;
    btnText.textContent = on ? 'Checking' : 'Check MX';
    btnLoader.hidden = !on;
    btnLoader.className = on ? 'loader' : '';
  }

  async function performLookup() {
    var domain = normalizeDomain(domainInput.value);
    if (!domain) { setView('error'); renderError('', 'Please enter a domain name'); return; }
    if (!validDomain(domain)) { lastRecords = null; setView('error'); renderError(domain, 'That is not a valid domain name.'); return; }
    domainInput.value = domain;
    setLoading(true);
    try {
      var result = await queryMX(domain);
      var hosts = result.records.map(function (r) { return r.host; }).filter(function (h, i, a) { return h !== '.' && a.indexOf(h) === i; });
      var resolved = {};
      var fallback = null;
      var policy = null;
      await Promise.all(hosts.map(function (h) { return resolveHost(h).then(function (x) { resolved[h] = x; return hostExtras(x); }); }));
      if (!result.records.length) {
        var fb = await resolveHost(domain);
        fallback = fb.a.concat(fb.aaaa);
      } else if (!(result.records.length === 1 && result.records[0].host === '.')) {
        policy = await transportPolicy(domain);
      }
      lastRecords = result.records.filter(function (r) { return r.host !== '.' || result.records.length === 1; });
      renderResult(result, resolved, buildChecks(result, resolved, policy), fallback);
      setView('records');
    } catch (err) {
      lastRecords = null;
      renderError(domain, err.message || 'Unknown error');
      setView('error');
    } finally {
      setLoading(false);
    }
  }
  checkBtn.addEventListener('click', performLookup);
  domainInput.addEventListener('keydown', function (e) { if (e.key === 'Enter') performLookup(); });

  // ---- Generator ----
  var genPreset = $('genPreset'), genPref = $('genPref'), genHost = $('genHost'), genError = $('genError');
  var preview = $('generatedPreview'), list = $('generatedList'), count = $('recordCount'), bind = $('bindOutput');
  var loadHint = $('loadExistingHint');
  var generated = []; // {pref, host}

  PROVIDERS.filter(function (p) { return p.preset; }).forEach(function (p, i) {
    var o = el('option', null, p.name); o.value = String(PROVIDERS.indexOf(p)); genPreset.append(o);
  });
  var nullOpt = el('option', null, 'Null MX (domain sends mail only)'); nullOpt.value = 'null'; genPreset.append(nullOpt);
  var none = el('option', null, '— choose a preset —'); none.value = ''; genPreset.prepend(none); genPreset.value = '';

  function fmt(r) { return r.pref + ' ' + (r.host === '.' ? '.' : r.host + '.'); }
  function cleanHost(h) { return h.trim().toLowerCase().replace(/\.$/, ''); }
  function validHost(h) { return h === '.' || (validDomain(h) && !/^\d{1,3}(\.\d{1,3}){3}$/.test(h)); }

  function updatePreview() {
    var h = cleanHost(genHost.value) || '[host]';
    var p = genPref.value === '' ? '[priority]' : genPref.value;
    preview.textContent = p + ' ' + (h === '.' ? '.' : h + '.');
  }
  function renderList() {
    list.replaceChildren();
    count.textContent = String(generated.length);
    if (!generated.length) { list.append(el('li', 'none', 'No MX records added yet. Use the form above.')); return; }
    generated.forEach(function (r, i) {
      var li = el('li');
      li.append(el('span', null, fmt(r)));
      var b = el('button', 'remove-record', '×');
      b.type = 'button';
      b.setAttribute('aria-label', 'Remove record ' + fmt(r));
      b.addEventListener('click', function () { generated.splice(i, 1); renderList(); bind.style.display = 'none'; });
      li.append(b);
      list.append(li);
    });
  }
  function addRecord(r) {
    if (!generated.some(function (x) { return x.pref === r.pref && x.host === r.host; })) generated.push(r);
  }
  function showError(msg) { genError.textContent = msg; genError.classList.toggle('visible', !!msg); }

  genPref.addEventListener('input', updatePreview);
  genHost.addEventListener('input', function () { updatePreview(); showError(''); });
  $('addRecordBtn').addEventListener('click', function () {
    var pref = parseInt(genPref.value, 10), host = cleanHost(genHost.value);
    if (!(pref >= 0 && pref <= 65535)) { showError('Priority must be a number from 0 to 65535.'); genPref.focus(); return; }
    if (!validHost(host)) { showError('Enter a valid hostname (not an IP address), e.g. mail.example.com.'); genHost.focus(); return; }
    showError('');
    addRecord({ pref: pref, host: host });
    renderList(); bind.style.display = 'none';
  });
  $('loadExistingBtn').addEventListener('click', function () {
    if (!lastRecords || !lastRecords.length) {
      loadHint.textContent = lastRecords ? 'No MX records found in the last lookup.' : 'No existing records loaded yet — run a lookup above first.';
      loadHint.classList.add('visible');
      return;
    }
    loadHint.classList.remove('visible');
    lastRecords.forEach(addRecord);
    renderList(); bind.style.display = 'none';
  });
  $('clearGenBtn').addEventListener('click', function () {
    genPref.value = '10'; genHost.value = 'mail.example.com'; genPreset.value = ''; showError(''); updatePreview();
  });
  $('clearAllRecords').addEventListener('click', function () { generated = []; renderList(); bind.style.display = 'none'; });
  genPreset.addEventListener('change', function () {
    var v = genPreset.value;
    if (!v) return;
    var domain = normalizeDomain(domainInput.value) || 'example.com';
    if (v === 'null') { addRecord({ pref: 0, host: '.' }); }
    else {
      var p = PROVIDERS[parseInt(v, 10)];
      var rows = p.preset === 'm365' ? [[0, domain.replace(/\./g, '-') + '.mail.protection.outlook.com']] : p.preset;
      rows.forEach(function (x) { addRecord({ pref: x[0], host: x[1] }); });
    }
    renderList(); bind.style.display = 'none';
  });
  $('generateBindText').addEventListener('click', function () {
    if (!generated.length) bind.textContent = '; no MX records to display';
    else {
      var domain = normalizeDomain(domainInput.value) || 'example.com';
      bind.textContent = '; MX records (BIND format)\n' + generated.map(function (r) { return domain + '. IN MX ' + fmt(r); }).join('\n') + '\n';
    }
    bind.style.display = 'block';
  });

  setView('placeholder');
  updatePreview();
  renderList();

  var param = new URLSearchParams(window.location.search).get('domain');
  if (param) { domainInput.value = param; performLookup(); }

  if ('serviceWorker' in navigator) navigator.serviceWorker.register('/sw.js');
})();
