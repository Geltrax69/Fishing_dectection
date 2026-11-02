// Popup: reads protection state + stats from chrome.storage.local,
// and lets the user turn protection on/off. No network calls.
(function () {
  const enabledEl = document.getElementById('enabled');
  const statusEl = document.getElementById('status');
  const scannedEl = document.getElementById('scanned');
  const flaggedEl = document.getElementById('flagged');
  const blockedEl = document.getElementById('blocked');

  function render(data) {
    const enabled = data.enabled !== false; // default ON
    enabledEl.checked = enabled;
    statusEl.textContent = enabled
      ? 'Protection is ON. Suspicious emails will be flagged in Gmail.'
      : 'Protection is OFF. Gmail will not be flagged until you turn it back on.';
    statusEl.className = 'status ' + (enabled ? 'on' : 'off');
    scannedEl.textContent = data.scannedCount || 0;
    flaggedEl.textContent = data.flaggedCount || 0;
    blockedEl.textContent = data.blockedCount || 0;
  }

  if (typeof chrome !== 'undefined' && chrome.storage) {
    chrome.storage.local.get(
      { enabled: true, scannedCount: 0, flaggedCount: 0, blockedCount: 0 },
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
  } else {
    // Opened outside an extension context (e.g. previewing the file).
    render({ enabled: true, scannedCount: 0, flaggedCount: 0, blockedCount: 0 });
  }
})();
