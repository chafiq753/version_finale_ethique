// ──────────────────────────────────────────────
// Détection PII temps réel
// ──────────────────────────────────────────────
const PII_PATTERNS = [
  /\b\d{8,}\b/,
  /\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b/,
  /\b0[567]\d{8}\b/,
  /\b\+?\d[\d\s\-]{8,}\d\b/,
  /\b(?:\d{4}[\s\-]?){4}\b/,
  /(mot\s*de\s*passe|password|passwd|mdp|secret)\s*[=:«"']?\s*\S+/i,
  /\b[A-Z]{1,2}\d{5,6}\b/,
  /\b\d{1,4}[\s,]+(rue|avenue|boulevard|impasse|allée|quartier|résidence)\b/i,
];

const SENSITIVE_KEYWORDS = [
  'mot de passe', 'password', 'mon mdp', 'ma carte', 'code secret',
  'code pin', 'mon iban', 'mon cin', 'ma cin', 'mon adresse',
  'date de naissance', 'numéro de sécurité',
];

function hasPii(text) {
  const lower = text.toLowerCase();
  if (SENSITIVE_KEYWORDS.some(k => lower.includes(k))) return true;
  return PII_PATTERNS.some(p => p.test(text));
}

function updateCounter() {
  const ta = document.getElementById('query');
  const cc = document.getElementById('char-count');
  const pw = document.getElementById('pii-warning');
  const sb = document.getElementById('submit-btn');
  if (!ta) return;

  const len = ta.value.length;
  if (cc) {
    cc.textContent = len + ' / 2000';
    cc.className = 'char-count' + (len > 1800 ? ' warn' : '');
  }

  const pii = hasPii(ta.value);
  if (pw) pw.style.display = pii ? 'block' : 'none';
  if (sb) sb.disabled = pii || len < 3;
}

// ──────────────────────────────────────────────
// Sélection du mode (question / résumé)
// ──────────────────────────────────────────────
function setMode(radio) {
  const labelQ = document.getElementById('label-question');
  const labelR = document.getElementById('label-resume');
  const ql     = document.getElementById('query-label');
  const ta     = document.getElementById('query');

  if (labelQ) labelQ.classList.toggle('active', radio.value === 'question');
  if (labelR) labelR.classList.toggle('active', radio.value === 'resume');

  if (ql) {
    ql.textContent = radio.value === 'resume' ? 'Texte à résumer' : 'Votre question';
  }
  if (ta) {
    ta.placeholder = radio.value === 'resume'
      ? 'Collez ici le texte que vous souhaitez résumer...'
      : 'Posez votre question sur le RGPD, l\'IA, la cybersécurité, Python, Flask...';
  }
}

// ──────────────────────────────────────────────
// Topic tag → remplir le textarea
// ──────────────────────────────────────────────
document.addEventListener('DOMContentLoaded', function () {
  const tags = document.querySelectorAll('.topic-tag');
  tags.forEach(tag => {
    tag.addEventListener('click', function () {
      const ta = document.getElementById('query');
      if (ta) {
        ta.value = 'Qu\'est-ce que ' + tag.textContent + ' ?';
        updateCounter();
        ta.focus();
      }
    });
  });

  // Init compteur
  updateCounter();

  // Auto-dismiss flash messages after 5s
  setTimeout(function () {
    const alerts = document.querySelectorAll('.flash-container .alert');
    alerts.forEach(a => { a.style.transition = 'opacity 0.5s'; a.style.opacity = '0'; });
    setTimeout(function () {
      const fc = document.querySelector('.flash-container');
      if (fc) fc.style.display = 'none';
    }, 600);
  }, 5000);
});

// ──────────────────────────────────────────────
// Reset form
// ──────────────────────────────────────────────
function resetForm() {
  const ta = document.getElementById('query');
  const pw = document.getElementById('pii-warning');
  const cc = document.getElementById('char-count');
  const sb = document.getElementById('submit-btn');
  if (ta) ta.value = '';
  if (pw) pw.style.display = 'none';
  if (cc) cc.textContent = '0 / 2000';
  if (sb) sb.disabled = false;
}
