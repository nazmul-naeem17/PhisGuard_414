// content.js

const THRESHOLD = 80;
const API_URL   = 'http://127.0.0.1:5000/predict';
const cache     = new Map();

function renderBadge(link, prediction, confidence, ctLogged) {
  // avoid duplicate badge
  if (link.nextSibling && link.nextSibling.classList && link.nextSibling.classList.contains('phishguard-badge')) {
    return;
  }
  const badge = document.createElement('span');
  badge.className = 'phishguard-badge ' + (prediction==='phishing' ? 'phish' : 'legit');
  badge.textContent = (prediction==='phishing' ? '⚠︎ ' : '✅ ') 
                     + confidence.toFixed(0) + '% ' 
                     + (ctLogged ? '🔒' : '🚨');
  link.parentNode.insertBefore(badge, link.nextSibling);
}

function renderModal(confidence) {
  // if already open, do nothing
  if (document.getElementById('phishguard-modal')) return;
  const overlay = document.createElement('div');
  overlay.id = 'phishguard-modal';
  overlay.innerHTML = `
    <div class="phishguard-modal-content">
      <p>Blocked: This link is ${confidence.toFixed(0)}% likely a phishing attempt.</p>
      <button id="phishguard-close">Close</button>
    </div>`;
  document.body.appendChild(overlay);
  document.getElementById('phishguard-close')
    .addEventListener('click', () => overlay.remove());
}

async function checkLink(link) {
  const href = link.href;
  if (!href || cache.has(href)) return cache.get(href);

  try {
    const resp = await fetch(API_URL, {
      method: 'POST',
      headers: {'Content-Type':'application/json'},
      body: JSON.stringify({url: href})
    });
    const data = await resp.json();
    cache.set(href, data);
    return data;
  } catch (e) {
    console.error('[PhishGuard] API error', e);
    cache.set(href, {prediction:'legit', confidence:0, ct_logged:false});
    return cache.get(href);
  }
}

// Event delegation
document.addEventListener('mouseover', async e => {
  const link = e.target.closest('a[href]');
  if (!link) return;
  const info = await checkLink(link);
  renderBadge(link, info.prediction, info.confidence, info.ct_logged);
});

document.addEventListener('mouseout', e => {
  const link = e.target.closest('a[href]');
  if (!link) return;
  const badge = link.nextSibling;
  if (badge && badge.classList && badge.classList.contains('phishguard-badge')) {
    badge.remove();
  }
});

document.addEventListener('click', async e => {
  const link = e.target.closest('a[href]');
  if (!link) return;
  const info = cache.get(link.href);
  if (info && info.prediction==='phishing' && info.confidence >= THRESHOLD) {
    e.preventDefault();
    renderModal(info.confidence);
  }
});
