/**
 * Phishing Shield — Gmail content script.
 *
 * What it does:
 *  1. Opened email: extracts sender/subject/body links, runs the local
 *     detector, and injects a red "DO NOT OPEN LINKS" banner (HIGH) or an
 *     amber caution banner (SUSPICIOUS) above the message body.
 *  2. Inbox list: flags rows whose subject/snippet uses strong pressure
 *     language from a support-like sender (list view has no sender domain
 *     or links, so this is deliberately conservative — the full check
 *     runs when you open the message).
 *  3. Link guard: clicks on risky links inside a flagged message show a
 *     warning modal first. "Go back" is the safe default.
 *
 * No email content leaves the browser. Gmail's DOM classes change over
 * time, so every selector here has a fallback and failures are silent.
 */
(function () {
  'use strict';

  var Detector = window.PhishingDetector;
  if (!Detector) return;

  var URGENCY = /urgent|immediately|within 24 hours|suspended|will be closed|verify your account|action required|password expired|security alert/i;
  var SUPPORT_SENDER = /support|security|service|helpdesk|account|verify|bank/i;
  var enabled = true;
  var results = new Map();
  var seenBodies = new WeakMap();
  var seenRows = new WeakMap();

  function messageKey(sender, subject) {
    return (sender + '\n' + subject).trim().toLowerCase();
  }

  function statusBadge(level, fullCheck) {
    var labels = { HIGH: 'Do not open links', SUSPICIOUS: 'Flagged', SAFE: fullCheck ? 'No obvious risks' : 'Not fully checked' };
    var label = labels[level];
    var badge = document.createElement('span');
    badge.className = 'phishing-shield-status phishing-shield-' + (level === 'SAFE' && !fullCheck ? 'unchecked' : level.toLowerCase());
    var paths = level === 'SAFE' && fullCheck ? '<path d="m5 10 3 3 7-7"/>' : level === 'SAFE' ? '<circle cx="10" cy="10" r="7"/><path d="M10 6v4m0 3h.01"/>' : '<path d="m10 3 8 14H2L10 3Z"/><path d="M10 8v4m0 2h.01"/>';
    badge.innerHTML = '<svg viewBox="0 0 20 20" width="16" height="16" fill="none" stroke="currentColor" stroke-width="1.7" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">' + paths + '</svg><span>' + label + '</span>';
    badge.title = fullCheck
      ? label + '. Local heuristic check of sender, message text and links; this does not verify the sender or guarantee safety.'
      : label + '. Preview check only; open the message for sender, body and link checks.';
    badge.setAttribute('aria-label', badge.title);
    return badge;
  }

  function bump(key) {
    try {
      if (!chrome || !chrome.storage) return;
      chrome.storage.local.get({ scannedCount: 0, flaggedCount: 0, blockedCount: 0 }, function (d) {
        var patch = {};
        patch[key] = (d[key] || 0) + 1;
        chrome.storage.local.set(patch);
      });
    } catch (e) { /* storage is best-effort */ }
  }

  function escapeHtml(s) {
    return String(s).replace(/[&<>"']/g, function (c) {
      return { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c];
    });
  }

  function showLinkWarning(href, reasons) {
    var old = document.querySelector('.phishing-shield-modal-backdrop');
    if (old) old.remove();
    var backdrop = document.createElement('div');
    backdrop.className = 'phishing-shield-modal-backdrop';
    backdrop.innerHTML =
      '<div class="phishing-shield-modal" role="dialog" aria-modal="true">' +
      '<h2>⛔ Do not open this link</h2>' +
      '<p>This link was flagged as risky in a suspicious email:</p>' +
      '<p class="phishing-shield-url">' + escapeHtml(href) + '</p>' +
      '<p>' + escapeHtml(reasons.join(' ')) + '</p>' +
      '<p>Go to the official site or app directly instead — never through a link in a suspicious email.</p>' +
      '<div class="phishing-shield-actions">' +
      '<button class="phishing-shield-safe" type="button">Go back (safe)</button>' +
      '<button class="phishing-shield-risky" type="button">Open anyway (not recommended)</button>' +
      '</div></div>';
    backdrop.querySelector('.phishing-shield-safe').addEventListener('click', function () {
      bump('blockedCount');
      backdrop.remove();
    });
    backdrop.querySelector('.phishing-shield-risky').addEventListener('click', function () {
      backdrop.remove();
      window.open(href, '_blank', 'noopener');
    });
    backdrop.addEventListener('click', function (e) {
      if (e.target === backdrop) { bump('blockedCount'); backdrop.remove(); }
    });
    document.body.appendChild(backdrop);
  }

  function guardLinks(bodyEl, result) {
    var riskyHosts = result.riskyLinks.map(function (l) { return l.host; });
    bodyEl.querySelectorAll('a[href]').forEach(function (a) {
      if (a.dataset.phishingShieldGuarded) return;
      a.dataset.phishingShieldGuarded = '1';
      var host = '';
      try { host = new URL(a.href).hostname.replace(/^www\./, ''); } catch (e) { return; }
      if (riskyHosts.indexOf(host) === -1) return;
      a.addEventListener('click', function (e) {
        if (!enabled) return;
        e.preventDefault();
        e.stopPropagation();
        var link = result.riskyLinks.find(function (l) { return l.host === host; });
        showLinkWarning(a.href, link ? link.reasons : ['This link was flagged as risky.']);
      }, true);
    });
  }

  function injectBanner(bodyEl, result) {
    if (bodyEl.parentElement.querySelector('.phishing-shield-banner')) return;
    var banner = document.createElement('div');
    var high = result.level === 'HIGH';
    banner.className = 'phishing-shield-banner' + (high ? '' : ' phishing-shield-suspicious');
    var title = high
      ? '⛔ DO NOT OPEN LINKS, REPLY, OR DOWNLOAD ATTACHMENTS — this email looks like phishing.'
      : '⚠️ Caution — this email looks suspicious.';
    var html = '<strong>' + title + '</strong>' +
      '<br>Phishing Shield score: ' + result.score + '/100 (' + result.level + ').' +
      (result.senderDomain ? ' Sender domain: ' + escapeHtml(result.senderDomain) + '.' : '');
    if (result.reasons.length) {
      html += '<ul>' + result.reasons.map(function (r) { return '<li>' + escapeHtml(r) + '</li>'; }).join('') + '</ul>';
    }
    html += '<div class="phishing-shield-actions">' +
      '<button type="button" class="phishing-shield-dismiss">I understand — I will not click anything</button></div>';
    banner.innerHTML = html;
    banner.querySelector('.phishing-shield-dismiss').addEventListener('click', function () {
      banner.remove();
    });
    bodyEl.parentElement.insertBefore(banner, bodyEl);
  }

  function scanOpenedMessage() {
    // Gmail message bodies carry class a3s. Each one is scanned once.
    document.querySelectorAll('div.a3s').forEach(function (bodyEl) {
      var container = bodyEl.closest('.adn') || bodyEl.closest('[role="listitem"]') || document;
      var senderEl = container.querySelector('.gD[email], .gD, [email]');
      var from = '';
      var displayName = '';
      if (senderEl) {
        from = senderEl.getAttribute('email') || senderEl.textContent.trim();
        displayName = senderEl.textContent.trim();
        if (from && displayName && from.indexOf('@') === -1) {
          // Sender element held only a name; keep the name as display name.
          displayName = from;
          from = '';
        }
      }
      var subjectEl = document.querySelector('.hP');
      var subject = subjectEl ? subjectEl.textContent.trim() : '';
      var fingerprint = JSON.stringify([from, displayName, subject, bodyEl.textContent, Array.from(bodyEl.querySelectorAll('a[href]'), function (a) { return a.href; })]);
      if (seenBodies.get(bodyEl) === fingerprint) return;
      seenBodies.set(bodyEl, fingerprint);
      bodyEl.dataset.phishingShieldDone = '1';
      bodyEl.parentElement.querySelectorAll('.phishing-shield-banner, .phishing-shield-message-status').forEach(function (el) { el.remove(); });
      var links = Array.prototype.map.call(bodyEl.querySelectorAll('a[href]'), function (a) {
        return { text: a.textContent.trim(), href: a.href };
      });
      var result = Detector.analyzeEmail({
        from: from,
        displayName: displayName,
        subject: subject,
        bodyText: bodyEl.textContent || '',
        links: links,
      });
      results.set(messageKey(from || displayName, subject), result);
      if (results.size > 500) results.delete(results.keys().next().value);
      bump('scannedCount');
      var status = statusBadge(result.level, true);
      status.classList.add('phishing-shield-message-status');
      bodyEl.parentElement.insertBefore(status, bodyEl);
      if (result.level === 'SAFE') return;
      bump('flaggedCount');
      injectBanner(bodyEl, result);
      guardLinks(bodyEl, result);
    });
  }

  function scanInboxList() {
    // Gmail list rows carry class zA. List view has no links or sender
    // domain, so only flag strong pressure-language rows — the full
    // detector runs when the message is opened.
    document.querySelectorAll('tr.zA').forEach(function (row) {
      var subjectEl = row.querySelector('.bog');
      var anchor = subjectEl && (subjectEl.closest('.y6') || subjectEl.parentElement);
      if (!subjectEl || !anchor) return;
      var senderEl = row.querySelector('.yW [email], .yW .zF, .yW .yP, .zF, .yP, [email]');
      var sender = senderEl ? senderEl.textContent.trim() : '';
      var from = senderEl ? senderEl.getAttribute('email') || '' : '';
      var subject = subjectEl.textContent.trim();
      var snippet = row.querySelector('.y2');
      var text = subject + ' ' + (snippet ? snippet.textContent : '');
      var cached = results.get(messageKey(from || sender, subject));
      var preview = Detector.analyzeEmail({ from: from, displayName: sender, subject: text });
      var urgencyHits = (text.match(/urgent|immediately|within 24 hours|suspended|will be closed|verify your account|action required|password expired/gi) || []).length;
      var pressure = SUPPORT_SENDER.test(sender) && (urgencyHits >= 2 || (URGENCY.test(text) && /verify|confirm|restore/i.test(text)));
      var level = cached ? cached.level : pressure && preview.level === 'SAFE' ? 'SUSPICIOUS' : preview.level;
      var signature = JSON.stringify([sender, from, subject, text, level, !!cached]);
      if (seenRows.get(row) === signature && row.querySelector('.phishing-shield-status')) return;
      seenRows.set(row, signature);
      row.querySelectorAll('.phishing-shield-status, .phishing-shield-list-flag').forEach(function (el) { el.remove(); });
      var badge = statusBadge(level, !!cached);
      badge.classList.add('phishing-shield-row-status');
      if (level !== 'SAFE') badge.classList.add('phishing-shield-list-flag');
      anchor.insertBefore(badge, anchor.firstChild);
      row.classList.add('phishing-shield-row');
    });
  }

  function applySettings(data) {
    enabled = data.enabled !== false;
    document.documentElement.classList.toggle('phishing-shield-clean', data.cleanInbox !== false);
    if (!enabled) {
      document.querySelectorAll('.phishing-shield-status, .phishing-shield-banner, .phishing-shield-modal-backdrop').forEach(function (el) { el.remove(); });
      seenBodies = new WeakMap();
      seenRows = new WeakMap();
    } else {
      scanOpenedMessage();
      scanInboxList();
    }
  }

  var timer = null;
  function scan() {
    if (timer) return;
    timer = setTimeout(function () {
      timer = null;
      try {
        if (typeof chrome !== 'undefined' && chrome.storage) {
          chrome.storage.local.get({ enabled: true, cleanInbox: true }, applySettings);
        } else {
          scanOpenedMessage();
          scanInboxList();
        }
      } catch (e) { /* never break Gmail */ }
    }, 400);
  }

  scan();
  if (typeof chrome !== 'undefined' && chrome.storage && chrome.storage.onChanged) {
    chrome.storage.onChanged.addListener(function (changes, area) {
      if (area === 'local' && (changes.enabled || changes.cleanInbox)) scan();
    });
  }
  try {
    new MutationObserver(scan).observe(document.body, { childList: true, subtree: true });
  } catch (e) { /* observer unavailable: initial scan already ran */ }
})();
