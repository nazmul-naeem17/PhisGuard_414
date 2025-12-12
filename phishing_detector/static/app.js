// ---------- utils ----------
function canonicalJSONString(obj){
  // deep, stable canonicalization (sort keys at ALL levels)
  const canon = (v) => {
    if (v === null || typeof v !== "object") return v;
    if (Array.isArray(v)) return v.map(canon);
    const out = {};
    Object.keys(v).sort().forEach(k => { out[k] = canon(v[k]); });
    return out;
  };
  return JSON.stringify(canon(obj));
}

function pemToArrayBuffer(pem){
  const b64 = pem.replace(/-----(BEGIN|END) PUBLIC KEY-----/g,'').replace(/\s+/g,'');
  const raw = atob(b64);
  const buf = new ArrayBuffer(raw.length);
  const view = new Uint8Array(buf);
  for(let i=0;i<raw.length;i++) view[i] = raw.charCodeAt(i);
  return buf;
}

async function verifyRSA(payload, sigB64, pubPem){
  const data = new TextEncoder().encode(canonicalJSONString(payload));
  const key = await crypto.subtle.importKey(
    "spki", pemToArrayBuffer(pubPem),
    {name:"RSASSA-PKCS1-v1_5", hash:"SHA-256"},
    false, ["verify"]
  );
  const sig = Uint8Array.from(atob(sigB64), c => c.charCodeAt(0));
  return crypto.subtle.verify("RSASSA-PKCS1-v1_5", key, sig, data);
}

function ts(unixSeconds){
  try { return new Date(unixSeconds * 1000).toLocaleString(); }
  catch { return String(unixSeconds); }
}

// ---------- DOM refs ----------
const $ = s => document.querySelector(s);

const urlInput   = $("#urlInput");
const checkBtn   = $("#checkBtn");
const quickStats = $("#quickStats");
const verdictPill= $("#verdictPill");
const probBar    = $("#probBar");
const probPct    = $("#probPct");
const tauEl      = $("#tau");

const resultCard = $("#resultCard");
const verifyCard = $("#verifyCard");
const outUrl     = $("#outUrl");
const outPred    = $("#outPred");
const outProb    = $("#outProb");
const outTau     = $("#outTau");
const outFeat    = $("#outFeat");
const outModel   = $("#outModel");
const outIat     = $("#outIat");
const outExp     = $("#outExp");
const outNonce   = $("#outNonce");
const outSig     = $("#outSig");
const outPub     = $("#outPub");
const verifyBtn  = $("#verifyBtn");
const verifyStatus = $("#verifyStatus");

let last = null;

// ---------- main actions ----------
async function check(){
  const url = urlInput.value.trim();
  if(!url){ urlInput.focus(); return; }

  try{
    checkBtn.disabled = true;
    quickStats.hidden = false;
    verdictPill.textContent = "—";
    probBar.style.width = "0%";
    probPct.textContent = "0%";
    verifyStatus.textContent = "—";

    const r = await fetch("/predict", {
      method: "POST",
      headers: {"Content-Type": "application/json"},
      body: JSON.stringify({ url })
    });
    const j = await r.json();
    last = j;

    if(j.error){
      alert("Server error: " + j.error);
      return;
    }

    const { payload, signature, pubkey_pem } = j;
    const p = (payload.probability * 100);
    const verdict = payload.prediction.toUpperCase();

    // quick stats
    verdictPill.textContent = verdict;
    const legit = verdict === "LEGIT";
    verdictPill.style.background = legit ? "#0f5132" : "#3a1220";
    verdictPill.style.color = legit ? "#d1fae5" : "#fecaca";
    probBar.style.width = `${p.toFixed(2)}%`;
    probPct.textContent = `${p.toFixed(2)}%`;
    tauEl.textContent = `${payload.threshold}`;

    // details
    outUrl.textContent = payload.url;
    outPred.textContent = payload.prediction;
    outProb.textContent = payload.probability.toFixed(6);
    outTau.textContent = payload.threshold;
    outFeat.textContent = payload.features_used;
    outModel.textContent = payload.model || "—";
    outIat.textContent = ts(payload.iat);
    outExp.textContent = ts(payload.exp);
    outNonce.textContent = payload.nonce;
    outSig.textContent = signature;
    outPub.textContent = pubkey_pem;

    resultCard.hidden = false;
    verifyCard.hidden = false;
    verifyStatus.textContent = "—";
    verifyBtn.disabled = false;

    // (optional) show warning if fallback used
    if (payload.used_fallback) {
      verifyStatus.textContent = "⚠ network fallback used — probabilities may be less reliable";
    }

  }catch(e){
    alert("Request failed: " + e);
  }finally{
    checkBtn.disabled = false;
  }
}

async function verify(){
  if(!last) return;
  verifyBtn.disabled = true;
  verifyStatus.textContent = "Verifying…";
  const ok = await verifyRSA(last.payload, last.signature, last.pubkey_pem).catch(() => false);
  verifyStatus.textContent = ok ? "✅ RSA signature verified" : "❌ verification failed";
  verifyBtn.disabled = false;
}

// ---------- boot ----------
$("#y").textContent = new Date().getFullYear();
checkBtn.addEventListener("click", check);
urlInput.addEventListener("keydown", e => { if(e.key === "Enter") check(); });
verifyBtn.addEventListener("click", verify);
