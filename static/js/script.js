/* script.js — Digital Signature System */

// ── Sidebar toggle (mobile) ──────────────────────────────────────
function toggleSidebar() {
  const sidebar = document.getElementById('sidebar');
  const overlay = document.getElementById('overlay');
  if (sidebar) sidebar.classList.toggle('open');
  if (overlay) overlay.classList.toggle('open');
}

function closeSidebar() {
  const sidebar = document.getElementById('sidebar');
  const overlay = document.getElementById('overlay');
  if (sidebar) sidebar.classList.remove('open');
  if (overlay) overlay.classList.remove('open');
}

// ── Auto-dismiss flash alerts after 5s ──────────────────────────
document.addEventListener('DOMContentLoaded', function () {
  const alerts = document.querySelectorAll('.alert');
  alerts.forEach(function (alert) {
    // Add close button
    const closeBtn = document.createElement('button');
    closeBtn.innerHTML = '&times;';
    closeBtn.style.cssText =
      'background:none;border:none;cursor:pointer;font-size:18px;line-height:1;' +
      'margin-left:auto;opacity:0.6;padding:0 0 0 12px;';
    closeBtn.onclick = function () { alert.remove(); };
    alert.appendChild(closeBtn);

    // Auto-dismiss after 6 seconds
    setTimeout(function () {
      alert.style.transition = 'opacity 0.5s';
      alert.style.opacity = '0';
      setTimeout(function () { alert.remove(); }, 500);
    }, 6000);
  });
});

// ── File drag-and-drop highlight (global) ───────────────────────
document.addEventListener('DOMContentLoaded', function () {
  const zones = document.querySelectorAll('.upload-zone');
  zones.forEach(function (zone) {
    zone.addEventListener('dragover', function (e) {
      e.preventDefault();
      zone.classList.add('drag-over');
    });
    zone.addEventListener('dragleave', function () {
      zone.classList.remove('drag-over');
    });
    zone.addEventListener('drop', function (e) {
      e.preventDefault();
      zone.classList.remove('drag-over');
      const input = zone.querySelector('input[type=file]');
      if (input && e.dataTransfer.files.length) {
        input.files = e.dataTransfer.files;
        const label = zone.querySelector('[id$="-fname"], #file-name, #verify-fname');
        if (label) {
          label.textContent = '\u2714 ' + e.dataTransfer.files[0].name;
          label.style.display = 'block';
        }
        input.dispatchEvent(new Event('change'));
      }
    });
  });
});

// ── Confirm before form submit for destructive actions ───────────
document.addEventListener('DOMContentLoaded', function () {
  const dangerForms = document.querySelectorAll('form[data-confirm]');
  dangerForms.forEach(function (form) {
    form.addEventListener('submit', function (e) {
      if (!confirm(form.dataset.confirm)) {
        e.preventDefault();
      }
    });
  });
});

// ── Hash copy to clipboard ───────────────────────────────────────
document.addEventListener('DOMContentLoaded', function () {
  document.querySelectorAll('.hash-display').forEach(function (el) {
    el.style.cursor = 'pointer';
    el.title = 'Click to copy';
    el.addEventListener('click', function () {
      const text = el.textContent.trim();
      navigator.clipboard.writeText(text).then(function () {
        const orig = el.style.outline;
        el.style.outline = '2px solid #34d399';
        setTimeout(function () { el.style.outline = orig; }, 1200);
      });
    });
  });
});
