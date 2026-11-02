/**
 * Phishing Shield — detector engine.
 *
 * Pure JavaScript, no Chrome APIs, no network calls. It works the same
 * in the extension (loaded as a classic script) and in Node tests
 * (via module.exports). All checks are heuristic: a HIGH score means
 * "treat this as phishing until proven otherwise", never proof.
 *
 * Scoring: 0-100.  <30 SAFE, 30-59 SUSPICIOUS, >=60 HIGH.
 */

(function (root) {
  'use strict';

  // Brand name -> official domains. A message claiming to be one of these
  // brands but sent from (or linking to) any other domain is suspicious.
  var BRANDS = {
    paypal: ['paypal.com'],
    google: ['google.com', 'gmail.com'],
    microsoft: ['microsoft.com', 'outlook.com', 'live.com', 'office.com'],
    apple: ['apple.com', 'icloud.com'],
    // AWS documents invoicing@aws.com as its billing sender:
    // https://docs.aws.amazon.com/notifications/latest/userguide/managed-notifications-bcm.html
    amazon: ['amazon.com', 'amazon.in', 'amazon.co.uk', 'aws.com'],
    aws: ['aws.com', 'amazon.com'],
    netflix: ['netflix.com'],
    facebook: ['facebook.com', 'meta.com'],
    instagram: ['instagram.com'],
    whatsapp: ['whatsapp.com'],
    linkedin: ['linkedin.com'],
    github: ['github.com'],
    steam: ['steampowered.com', 'steamcommunity.com'],
    'hdfc bank': ['hdfcbank.com'],
    'state bank': ['sbi.co.in', 'onlinesbi.com'],
    icici: ['icicibank.com'],
  };

  var FREE_MAIL = ['gmail.com', 'yahoo.com', 'yahoo.in', 'outlook.com', 'hotmail.com', 'proton.me', 'protonmail.com', 'mail.com', 'gmx.com', 'aol.com'];

  var SHORTENERS = ['bit.ly', 'tinyurl.com', 't.co', 'goo.gl', 'ow.ly', 'is.gd', 'buff.ly', 'cutt.ly', 'rebrand.ly', 'shorturl.at', 'tiny.cc', 'shorte.st'];

  var URGENCY_PATTERNS = [
    /urgent/i, /immediately/i, /within 24 hours/i, /account (will be )?suspended/i,
    /account (will be )?closed/i, /verify your account/i, /action required/i,
    /password (has )?expired/i, /security alert/i, /unusual activity/i,
    /click (here )?to (verify|confirm|restore)/i, /limited time/i,
  ];

  var CREDENTIAL_PATTERNS = [
    /enter your password/i, /confirm your password/i, /provide your (otp|pin)/i,
    /share your verification code/i, /send us your password/i,
  ];

  var RISKY_ATTACHMENTS = ['.exe', '.scr', '.bat', '.cmd', '.js', '.vbs', '.html', '.htm', '.iso', '.zip', '.rar'];

  function lower(s) { return (s || '').toString().toLowerCase(); }

  function domainOfEmail(email) {
    var m = /@([^>\s]+)/.exec(email || '');
    return m ? lower(m[1]).replace(/\.+$/, '') : '';
  }

  function parseEmail(raw) {
    // Accepts "Name <a@b.com>" or plain "a@b.com".
    var m = /<([^>]+)>/.exec(raw || '');
    var addr = m ? m[1] : (raw || '').trim();
    var name = m ? (raw || '').slice(0, m.index).replace(/["']/g, '').trim() : '';
    return { name: name, address: addr, domain: domainOfEmail(addr) };
  }

  function hostOfUrl(raw) {
    try {
      // URL() needs a scheme; bare domains in link text are handled separately.
      var u = new URL(/^https?:\/\//i.test(raw) ? raw : 'https://' + raw);
      return lower(u.hostname);
    } catch (e) {
      return '';
    }
  }

  function stripWww(host) { return host.replace(/^www\./, ''); }

  function registrable(host) {
    var h = stripWww(host);
    var parts = h.split('.');
    // Crude registrable-domain: last two labels (covers .co.in poorly,
    // but that only weakens, never strengthens, a lookalike match).
    return parts.length >= 2 ? parts.slice(-2).join('.') : h;
  }

  function levenshtein(a, b) {
    var m = a.length, n = b.length;
    if (!m) return n;
    if (!n) return m;
    var prev = [], cur = [];
    for (var j = 0; j <= n; j++) prev[j] = j;
    for (var i = 1; i <= m; i++) {
      cur[0] = i;
      for (j = 1; j <= n; j++) {
        cur[j] = Math.min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + (a[i - 1] === b[j - 1] ? 0 : 1));
      }
      var tmp = prev; prev = cur; cur = tmp;
    }
    return prev[n];
  }

  function brandInText(text) {
    var t = lower(text);
    var found = [];
    Object.keys(BRANDS).forEach(function (brand) {
      // Match brand words, not substrings such as "apple" in "Pineapple".
      if (new RegExp('(^|[^a-z0-9])' + brand + '([^a-z0-9]|$)', 'i').test(t)) found.push(brand);
    });
    return found;
  }

  function isOfficialDomain(domain, brand) {
    var d = stripWww(domain);
    return (BRANDS[brand] || []).some(function (official) {
      return d === official || d.endsWith('.' + official);
    });
  }

  function isLookalike(domain, brand) {
    var d = stripWww(domain);
    var official = (BRANDS[brand] || [])[0];
    if (!official || d === official || d.endsWith('.' + official)) return false;
    var core = registrable(d).split('.')[0];
    var officialCore = official.split('.')[0];
    if (core === officialCore) return true; // paypal.com.evil.com style, or paypal.net
    if (core.indexOf(officialCore) !== -1 || officialCore.indexOf(core) !== -1) return true;
    // paypa1, paypaI, goggle, micros0ft, etc.
    if (core.length >= 4 && levenshtein(core, officialCore) <= 2) return true;
    return false;
  }

  function domainInText(text) {
    // Pull a bare domain out of link text like "paypal.com/verify".
    var m = /([a-z0-9-]+\.)+[a-z]{2,}(\/\S*)?/i.exec(text || '');
    return m ? stripWww(lower(m[0]).split('/')[0]) : '';
  }

  function analyzeLink(link) {
    var text = link.text || '';
    var href = link.href || '';
    var reasons = [];
    var score = 0;
    var host = hostOfUrl(href);
    if (!host) return { score: 0, reasons: ['Link has no usable destination.'], isRisky: false, host: '' };

    var shown = domainInText(text);
    if (shown && shown !== stripWww(host) && !stripWww(host).endsWith('.' + shown)) {
      score += 40;
      reasons.push('Link text shows "' + shown + '" but actually goes to "' + stripWww(host) + '".');
    }
    if (SHORTENERS.indexOf(stripWww(host)) !== -1 || SHORTENERS.indexOf(registrable(host)) !== -1) {
      score += 30;
      reasons.push('Link uses a URL shortener (' + stripWww(host) + '), hiding its real destination.');
    }
    if (/^\d+\.\d+\.\d+\.\d+$/.test(host)) {
      score += 40;
      reasons.push('Link goes to a raw IP address (' + host + ') instead of a named site.');
    }
    if (host.indexOf('xn--') !== -1) {
      score += 30;
      reasons.push('Link domain uses punycode (xn--), a common lookalike trick.');
    }
    brandInText(text).forEach(function (brand) {
      if (!isOfficialDomain(host, brand)) {
        if (isLookalike(host, brand)) {
          score += 35;
          reasons.push('Link domain "' + stripWww(host) + '" looks like ' + brand + ' but is not its official site.');
        } else {
          score += 25;
          reasons.push('Link mentions ' + brand + ' but goes to "' + stripWww(host) + '", which is not in our known ' + brand + ' domain list. This list may be incomplete.');
        }
      }
    });
    if (/^http:/i.test(href) && /(login|sign.?in|verify|account|password)/i.test(href)) {
      score += 15;
      reasons.push('Login-style link is served over plain http, not https.');
    }
    return { score: score, reasons: reasons, isRisky: score >= 30, host: stripWww(host) };
  }

  function analyzeEmail(input) {
    input = input || {};
    var reasons = [];
    var score = 0;
    function add(points, reason) {
      if (reasons.indexOf(reason) === -1) reasons.push(reason);
      score += points;
    }

    var from = parseEmail(input.from || '');
    var displayName = input.displayName || from.name || '';
    var subject = input.subject || '';
    var body = input.bodyText || '';
    var combined = subject + '\n' + body;

    // 1. Sender impersonation.
    if (from.domain) {
      brandInText(displayName).forEach(function (brand) {
        if (!isOfficialDomain(from.domain, brand)) {
          if (isLookalike(from.domain, brand)) {
            add(40, 'Claims to be ' + brand + ' but was sent from lookalike domain "' + from.domain + '".');
          } else {
            add(40, 'Sender name mentions ' + brand + ' but its domain "' + from.domain + '" is not in our known ' + brand + ' domain list. This list may be incomplete; check sender authentication in Gmail.');
          }
        }
      });
      if (FREE_MAIL.indexOf(from.domain) !== -1 && /(support|security|team|service|bank|helpdesk)/i.test(displayName)) {
        add(20, 'Sent from a free mailbox (' + from.domain + ') while posing as a support/security team.');
      }
    } else if (input.from) {
      add(10, 'Sender address could not be parsed.');
    }

    // 2. Reply-To mismatch.
    if (input.replyTo) {
      var replyDomain = domainOfEmail(input.replyTo);
      if (replyDomain && from.domain && replyDomain !== from.domain) {
        add(25, 'Reply-To address (' + replyDomain + ') differs from the sender domain (' + from.domain + ').');
      }
    }

    // 3. Urgency / pressure language.
    var urgencyHits = URGENCY_PATTERNS.filter(function (re) { return re.test(combined); });
    if (urgencyHits.length) {
      add(Math.min(25, urgencyHits.length * 10), 'Uses urgent/threatening language to pressure a quick click.');
    }

    // 4. Credential harvesting language.
    if (CREDENTIAL_PATTERNS.some(function (re) { return re.test(combined); })) {
      add(30, 'Asks you to enter or share a password, OTP or verification code.');
    }

    // 5. Links.
    var riskyLinks = [];
    (input.links || []).forEach(function (link) {
      var r = analyzeLink(link);
      if (r.isRisky) {
        riskyLinks.push({ text: link.text || '', href: link.href || '', host: r.host, reasons: r.reasons });
        r.reasons.slice(0, 2).forEach(function (reason) { add(0, reason); });
      }
      score += r.score; // total score is capped at 100 below
    });
    if (riskyLinks.length) {
      // Re-balance: link points already added above; nothing extra needed.
    }

    // 6. Risky attachments.
    (input.attachments || []).forEach(function (name) {
      var ext = '.' + lower(name).split('.').pop();
      if (RISKY_ATTACHMENTS.indexOf(ext) !== -1) {
        add(30, 'Has a risky attachment (' + name + ') that can run code or hide a fake login page.');
      }
    });

    score = Math.max(0, Math.min(100, score));
    var level = score >= 60 ? 'HIGH' : score >= 30 ? 'SUSPICIOUS' : 'SAFE';
    return {
      score: score,
      level: level,
      doNotOpen: level === 'HIGH',
      reasons: reasons,
      riskyLinks: riskyLinks,
      senderDomain: from.domain,
      displayName: displayName,
    };
  }

  var api = { analyzeEmail: analyzeEmail, analyzeLink: analyzeLink, BRANDS: BRANDS };
  if (typeof module !== 'undefined' && module.exports) module.exports = api;
  root.PhishingDetector = api;
})(typeof window !== 'undefined' ? window : globalThis);
