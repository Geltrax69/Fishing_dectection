// Popup: reads protection state + stats from chrome.storage.local,
// and lets the user turn protection on/off. No network calls.
(function () {
  const enabledEl = document.getElementById('enabled');
  const cleanInboxEl = document.getElementById('cleanInbox');
  const statusEl = document.getElementById('status');
  const scannedEl = document.getElementById('scanned');
  const flaggedEl = document.getElementById('flagged');
  const blockedEl = document.getElementById('blocked');

  function render(data) {
    const enabled = data.enabled !== false; // default ON
    enabledEl.checked = enabled;
    cleanInboxEl.checked = data.cleanInbox !== false;
    statusEl.textContent = enabled
      ? 'Protection is ON. Each email shows its check status in Gmail.'
      : 'Protection is OFF. Gmail will not be flagged until you turn it back on.';
    statusEl.className = 'status ' + (enabled ? 'on' : 'off');
    scannedEl.textContent = data.scannedCount || 0;
    flaggedEl.textContent = data.flaggedCount || 0;
    blockedEl.textContent = data.blockedCount || 0;
  }

  if (typeof chrome !== 'undefined' && chrome.storage) {
    chrome.storage.local.get(
      { enabled: true, cleanInbox: true, scannedCount: 0, flaggedCount: 0, blockedCount: 0 },
      render
    );
    enabledEl.addEventListener('change', () => {
      chrome.storage.local.set({ enabled: enabledEl.checked }, () => {
        chrome.storage.local.get(
          { enabled: true, scannedCount: 0, flaggedCount: 0, blockedCount: 0 },
          render
        );
      });
    });
    cleanInboxEl.addEventListener('change', () => {
      chrome.storage.local.set({ cleanInbox: cleanInboxEl.checked });
    });
    chrome.storage.onChanged.addListener(() => {
      chrome.storage.local.get({ enabled: true, cleanInbox: true, scannedCount: 0, flaggedCount: 0, blockedCount: 0 }, render);
    });
  } else {
    // Opened outside an extension context (e.g. previewing the file).
    render({ enabled: true, scannedCount: 0, flaggedCount: 0, blockedCount: 0 });
  }
})();
