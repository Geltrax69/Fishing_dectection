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
      if (bodyEl.dataset.phishingShieldDone) return;
      bodyEl.dataset.phishingShieldDone = '1';

      var container = bodyEl.closest('.adn') || bodyEl.closest('[role="listitem"]') || document;
      var senderEl = container.querySelector('[email]') || document.querySelector('.gD');
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
      var links = Array.prototype.map.call(bodyEl.querySelectorAll('a[href]'), function (a) {
        return { text: a.textContent.trim(), href: a.href };
      });
      var result = Detector.analyzeEmail({
        from: from,
        displayName: displayName,
        subject: subjectEl ? subjectEl.textContent : '',
        bodyText: bodyEl.textContent || '',
        links: links,
      });
      bump('scannedCount');
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
      if (row.dataset.phishingShieldDone) return;
      row.dataset.phishingShieldDone = '1';
      var text = row.textContent || '';
      var senderEl = row.querySelector('.zF, .yP') || row.querySelector('td:first-child');
      var sender = senderEl ? senderEl.textContent : '';
      var urgencyHits = (text.match(/urgent|immediately|within 24 hours|suspended|will be closed|verify your account|action required|password expired/gi) || []).length;
      if (urgencyHits >= 2 && SUPPORT_SENDER.test(sender)) {
        var subjectEl = row.querySelector('.bog');
        var anchor = subjectEl || row.querySelector('td');
        if (!anchor) return;
        var flag = document.createElement('span');
        flag.className = 'phishing-shield-list-flag';
        flag.textContent = '🚩 Suspicious — open with caution';
        flag.title = 'Phishing Shield: this subject uses strong pressure language from a support-like sender. The full check runs when you open it — do not click links inside it.';
        anchor.appendChild(flag);
      } else if (URGENCY.test(text) && /verify|confirm|restore/i.test(text) && SUPPORT_SENDER.test(sender)) {
        // Single strong signal + a verify action is still worth a flag.
        var el = row.querySelector('.bog') || row.querySelector('td');
        if (!el) return;
        var f = document.createElement('span');
        f.className = 'phishing-shield-list-flag';
        f.textContent = '🚩 Check before clicking';
        f.title = 'Phishing Shield: pressure + verify language. The full check runs when you open it.';
        el.appendChild(f);
      }
    });
  }

  var timer = null;
  function scan() {
    if (timer) return;
    timer = setTimeout(function () {
      timer = null;
      try {
        if (chrome && chrome.storage) {
          chrome.storage.local.get({ enabled: true }, function (d) {
            if (d.enabled === false) return;
            scanOpenedMessage();
            scanInboxList();
          });
        } else {
          scanOpenedMessage();
          scanInboxList();
        }
      } catch (e) { /* never break Gmail */ }
    }, 400);
  }

  scan();
  try {
    new MutationObserver(scan).observe(document.body, { childList: true, subtree: true });
  } catch (e) { /* observer unavailable: initial scan already ran */ }
})();
