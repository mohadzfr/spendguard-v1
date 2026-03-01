from fastapi import FastAPI, UploadFile, File, Form, HTTPException, Request
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse
from pydantic import BaseModel
from typing import Dict, Any, Optional, List
from dotenv import load_dotenv
import pdfplumber
import uuid
import os
import re
import json
import stripe
import time
import hmac
import hashlib
import httpx


# ================= CONFIG =================
load_dotenv()

STRIPE_SECRET_KEY = os.getenv("STRIPE_SECRET_KEY", "")
STRIPE_PUBLISHABLE_KEY = os.getenv("STRIPE_PUBLISHABLE_KEY", "")
STRIPE_WEBHOOK_SECRET = os.getenv("STRIPE_WEBHOOK_SECRET", "")
APP_SECRET = os.getenv("APP_SECRET", "change-me-please")

OPENAI_API_KEY = os.getenv("OPENAI_API_KEY", "")
AI_MODEL = os.getenv("AI_MODEL", "gpt-4.1-mini")  # exemple
AI_ENABLED = bool(OPENAI_API_KEY)

PRICE_CENTS = int(os.getenv("PRICE_CENTS", "900"))
CURRENCY = os.getenv("CURRENCY", "eur")

if not STRIPE_SECRET_KEY or not STRIPE_PUBLISHABLE_KEY or not STRIPE_WEBHOOK_SECRET:
    print("⚠️ Variables Stripe manquantes. Vérifie .env (local) ou env vars Render (prod).")

stripe.api_key = STRIPE_SECRET_KEY

app = FastAPI(title="SpendGuard AI", version="2.0.0")

DATA_DIR = "./data"
os.makedirs(DATA_DIR, exist_ok=True)
STATE_PATH = os.path.join(DATA_DIR, "state.json")


# ================= SECURITY (TOKEN SIGNÉ) =================
def sign_doc(doc_id: str) -> str:
    msg = doc_id.encode("utf-8")
    key = APP_SECRET.encode("utf-8")
    return hmac.new(key, msg, hashlib.sha256).hexdigest()[:16]

def check_sig(doc_id: str, t: Optional[str]) -> bool:
    if not t:
        return False
    return hmac.compare_digest(sign_doc(doc_id), t)


# ================= STATE (state.json) =================
def _default_state() -> Dict[str, Any]:
    return {"reports": {}, "paid": {}}  # paid: {doc_id: {"ts": int, "payment_intent": str}}

def load_state() -> Dict[str, Any]:
    if not os.path.exists(STATE_PATH):
        s = _default_state()
        save_state(s)
        return s
    try:
        with open(STATE_PATH, "r", encoding="utf-8") as f:
            data = json.load(f)

        # migrations soft
        if "reports" not in data or not isinstance(data["reports"], dict):
            data["reports"] = {}
        if "paid" not in data or not isinstance(data["paid"], dict):
            data["paid"] = {}

        return data
    except Exception:
        s = _default_state()
        save_state(s)
        return s

def save_state(state: Dict[str, Any]) -> None:
    tmp = STATE_PATH + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(state, f, ensure_ascii=False, indent=2)
    os.replace(tmp, STATE_PATH)

def get_report(doc_id: str) -> Optional[Dict[str, Any]]:
    state = load_state()
    return state["reports"].get(doc_id)

def set_report(doc_id: str, data: Dict[str, Any]) -> None:
    state = load_state()
    state["reports"][doc_id] = data
    save_state(state)

def mark_paid(doc_id: str, payment_intent: str = "") -> None:
    state = load_state()
    state["paid"][doc_id] = {"ts": int(time.time()), "payment_intent": payment_intent or ""}
    save_state(state)

def is_paid_local(doc_id: str, ttl_days: int = 7) -> bool:
    state = load_state()
    entry = state["paid"].get(doc_id)
    if not entry:
        return False
    ts = int(entry.get("ts", 0))
    if ts <= 0:
        return True
    return ts >= int(time.time()) - ttl_days * 24 * 3600

def is_paid(doc_id: str) -> bool:
    # 1) local state first (fast)
    if is_paid_local(doc_id):
        return True

    # 2) fallback stripe scan (useful if state reset)
    try:
        seven_days_ago = int(time.time()) - 7 * 24 * 3600
        starting_after = None

        while True:
            params = {"limit": 100, "created": {"gte": seven_days_ago}}
            if starting_after:
                params["starting_after"] = starting_after

            intents = stripe.PaymentIntent.list(**params)

            for pi in intents.data:
                md = pi.metadata or {}
                if md.get("doc_id") == doc_id and pi.status == "succeeded":
                    mark_paid(doc_id, payment_intent=pi.id)
                    return True

            if intents.has_more and intents.data:
                starting_after = intents.data[-1].id
            else:
                break

        return False
    except Exception:
        return False


# ================= EXTRACTION FACTURE =================
def detect_currency(text: str) -> str:
    if "€" in text:
        return "EUR"
    if "$" in text:
        return "USD"
    if "£" in text:
        return "GBP"
    return "UNKNOWN"

def normalize_vendor(v: str) -> str:
    v = (v or "UNKNOWN").strip()
    return (
        v.replace("Ia", "IA")
         .replace("Aws", "AWS")
         .replace("Hubspot", "HubSpot")
         .replace("Google workspace", "Google Workspace")
    )

def detect_vendor(raw_text: str) -> str:
    text = raw_text.strip()
    low = text.lower()

    brands = [
        ("google workspace", "Google Workspace"),
        ("google", "Google"),
        ("notion", "Notion"),
        ("microsoft 365", "Microsoft 365"),
        ("office 365", "Microsoft 365"),
        ("microsoft", "Microsoft"),
        ("azure", "Microsoft Azure"),
        ("adobe", "Adobe"),
        ("slack", "Slack"),
        ("stripe", "Stripe"),
        ("amazon web services", "AWS"),
        ("aws", "AWS"),
        ("ovh", "OVHcloud"),
        ("github", "GitHub"),
        ("canva", "Canva"),
        ("dropbox", "Dropbox"),
        ("zoom", "Zoom"),
        ("hubspot", "HubSpot"),
        ("shopify", "Shopify"),
        ("openai", "OpenAI"),
    ]
    for key, name in brands:
        if key in low:
            return name

    patterns = [
        r"(factur[eé]\s*par|fournisseur|vendor|seller|issued by)\s*[:\-]\s*(.+)",
        r"(soci[eé]t[eé]|company)\s*[:\-]\s*(.+)",
    ]
    for p in patterns:
        m = re.search(p, raw_text, re.IGNORECASE)
        if m:
            cand = m.group(m.lastindex).strip()
            cand = cand.split("\n")[0].strip()
            if 3 <= len(cand) <= 80:
                return normalize_vendor(cand.title())

    lines = [l.strip() for l in text.splitlines() if l.strip()]
    head = lines[:12]
    bad = ("facture", "invoice", "date", "total", "tva", "vat", "adresse", "address")
    for l in head:
        ll = l.lower()
        if len(l) < 4 or any(b in ll for b in bad):
            continue
        letters = sum(c.isalpha() for c in l)
        digits = sum(c.isdigit() for c in l)
        if letters >= 6 and digits <= 2 and len(l) <= 60:
            return normalize_vendor(l)

    return "UNKNOWN"

def extract_total_amount(raw_text: str) -> float:
    t = raw_text.replace("\u00a0", " ")
    low = t.lower()

    priority_keys = [
        "total ttc", "montant ttc", "total à payer", "net à payer",
        "amount due", "total due", "grand total", "total"
    ]

    def parse_number(s: str) -> float:
        s = s.strip().replace(" ", "")
        if "," in s and "." in s:
            if s.rfind(",") > s.rfind("."):
                s = s.replace(".", "").replace(",", ".")
            else:
                s = s.replace(",", "")
        else:
            s = s.replace(",", ".")
        try:
            return float(s)
        except Exception:
            return 0.0

    lines = [l.strip() for l in t.splitlines() if l.strip()]
    for l in lines:
        ll = l.lower()
        if any(k in ll for k in priority_keys):
            m = re.search(r"([0-9]{1,3}(?:[ .][0-9]{3})*(?:[.,][0-9]{2})?)", l)
            if m:
                val = parse_number(m.group(1))
                if val > 0:
                    return val

    matches = re.findall(r"([0-9]{1,3}(?:[ .][0-9]{3})*(?:[.,][0-9]{2})?)\s*(€|eur|usd|\$|gbp|£)", low)
    if matches:
        val = parse_number(matches[-1][0])
        if val > 0:
            return val

    m2 = re.findall(r"([0-9]{1,3}(?:[ .][0-9]{3})*(?:[.,][0-9]{2}))", low)
    if m2:
        val = parse_number(m2[-1])
        return val if val > 0 else 0.0

    return 0.0


# ================= IA AUDIT (OpenAI via httpx) =================
async def ai_audit_from_text(
    raw_text: str,
    company: str,
    signer: str,
    tone: str,
    fallback_vendor: str,
    currency: str,
    total: float,
) -> Dict[str, Any]:
    """
    Analyse IA achats B2B:
    - insights / opportunities / questions
    - email vraiment adapté
    Retourne JSON strict.
    """
    fallback_vendor = normalize_vendor(fallback_vendor)

    if not AI_ENABLED:
        return {
            "ai_used": False,
            "confidence": 0.25,
            "vendor": fallback_vendor,
            "category": "unknown",
            "insights": [
                "Analyse IA désactivée (OPENAI_API_KEY absent)."
            ],
            "opportunities": [
                {"title": "Négociation", "why": "Dépense détectée, tenter une remise annuelle.", "impact_estimate": "5–15%"}
            ],
            "questions": [
                "Avez-vous une remise annuelle ?",
                "Pouvons-nous réduire le nombre de licences ?",
                "Existe-t-il un plan moins cher (downgrade) ?"
            ],
            "email_subject": f"Demande d’amélioration tarifaire - {company}",
            "email_body": f"""Bonjour,

Nous utilisons {fallback_vendor}. Avant renouvellement, nous souhaitons discuter d’un ajustement tarifaire.
Avez-vous une remise annuelle, une offre fidélité, ou un plan plus adapté ?

Cordialement,
{signer}""",
        }

    raw_text = (raw_text or "").strip()

    # Limiter le texte envoyé pour coûts/perf:
    head = raw_text[:6000]
    tail = raw_text[-2500:] if len(raw_text) > 8000 else ""
    packed = head + ("\n\n--- FIN DU DOCUMENT ---\n\n" + tail if tail else "")

    system = (
        "Tu es un expert achats B2B (SaaS, cloud, licences) et négociation fournisseur. "
        "Tu analyses une facture/contrat (texte brut) et produis un audit actionnable. "
        "Tu n'inventes pas: si une info n'est pas présente, tu le dis. "
        "Tu réponds UNIQUEMENT par un JSON strict."
    )

    user = f"""
CONTEXTE:
- Entreprise cliente: {company}
- Signataire: {signer}
- Ton souhaité: {tone}
- Fournisseur détecté (fallback): {fallback_vendor}
- Montant détecté: {total} {currency}

TEXTE FACTURE (extrait):
{packed}

TÂCHE:
1) Identifier le fournisseur réel si possible (sinon fallback).
2) Déduire la catégorie (CRM, cloud, design, dev tools, etc.) si possible.
3) Repérer ce qui est utile: périodicité, engagement, renouvellement, quantités, licences, dates, TVA, etc.
4) Donner:
   - confidence (0 à 1)
   - insights (liste bullet: ce qui est vrai/observé ou incertain)
   - opportunities (liste: title + why + impact_estimate)
   - questions (questions concrètes à poser)
5) Rédiger un email de négociation TRÈS PRO adapté à ce document.
   - email_subject
   - email_body

RENVOIE STRICTEMENT CE JSON:
{{
  "ai_used": true,
  "confidence": 0.0,
  "vendor": "string",
  "category": "string",
  "insights": ["..."],
  "opportunities": [{{"title":"...","why":"...","impact_estimate":"..."}}],
  "questions": ["..."],
  "email_subject": "string",
  "email_body": "string"
}}
"""

    payload = {
        "model": AI_MODEL,
        "messages": [
            {"role": "system", "content": system},
            {"role": "user", "content": user},
        ],
        "response_format": {"type": "json_object"},
        "temperature": 0.3,
    }

    try:
        async with httpx.AsyncClient(timeout=45) as client:
            r = await client.post(
                "https://api.openai.com/v1/chat/completions",
                headers={"Authorization": f"Bearer {OPENAI_API_KEY}"},
                json=payload,
            )
            r.raise_for_status()
            data = r.json()
            content = data["choices"][0]["message"]["content"]
            parsed = json.loads(content)

        parsed.setdefault("ai_used", True)
        parsed.setdefault("confidence", 0.4)
        parsed.setdefault("vendor", fallback_vendor)
        parsed.setdefault("category", "unknown")
        parsed.setdefault("insights", [])
        parsed.setdefault("opportunities", [])
        parsed.setdefault("questions", [])
        parsed.setdefault("email_subject", f"Demande d’amélioration tarifaire - {company}")
        parsed.setdefault("email_body", "")

        parsed["vendor"] = normalize_vendor(parsed.get("vendor") or fallback_vendor)

        # hard limits (avoid insanely long outputs)
        parsed["insights"] = (parsed.get("insights") or [])[:12]
        parsed["opportunities"] = (parsed.get("opportunities") or [])[:10]
        parsed["questions"] = (parsed.get("questions") or [])[:10]
        if len(parsed.get("email_body") or "") > 3500:
            parsed["email_body"] = (parsed["email_body"][:3400] + "\n\nCordialement,\n" + signer)

        return parsed

    except Exception as e:
        return {
            "ai_used": False,
            "confidence": 0.2,
            "vendor": fallback_vendor,
            "category": "unknown",
            "insights": [f"Erreur IA: {str(e)}"],
            "opportunities": [
                {"title": "Négociation", "why": "Dépense détectée, tenter une remise.", "impact_estimate": "5–15%"}
            ],
            "questions": [
                "Avez-vous une remise annuelle ?",
                "Pouvons-nous réduire le nombre de licences ?",
                "Existe-t-il un plan moins cher (downgrade) ?"
            ],
            "email_subject": f"Demande d’amélioration tarifaire - {company}",
            "email_body": f"""Bonjour,

Nous utilisons {fallback_vendor}. Avant renouvellement, nous souhaitons discuter d’un ajustement tarifaire.

Cordialement,
{signer}""",
        }


# ================= UI SHELL / DESIGN =================
def shell(title: str, inner: str, wide: bool = False) -> str:
    maxw = "1100px" if wide else "980px"
    return f"""
    <html>
    <head>
      <meta charset="utf-8"/>
      <meta name="viewport" content="width=device-width, initial-scale=1"/>
      <title>{title}</title>
      <style>
        :root {{
          --bg1:#0b1020;
          --bg2:#111a2f;
          --card:rgba(255,255,255,0.06);
          --border:rgba(255,255,255,0.12);
          --text:#e5e7eb;
          --muted:#a8b0c2;
          --brand1:#3b82f6;
          --brand2:#6366f1;
          --green:#22c55e;
          --amber:#fbbf24;
          --shadow: 0 25px 70px rgba(0,0,0,0.55);
        }}
        body {{
          margin:0;
          font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif;
          background: radial-gradient(1200px 600px at 20% 10%, rgba(99,102,241,0.35), transparent 55%),
                      radial-gradient(900px 500px at 85% 30%, rgba(59,130,246,0.30), transparent 55%),
                      linear-gradient(135deg, var(--bg1), var(--bg2));
          color: var(--text);
          min-height:100vh;
          display:flex;
          justify-content:center;
          align-items:flex-start;
          padding:44px 14px;
        }}
        .container {{ width:100%; max-width:{maxw}; }}
        .topbar {{ display:flex; align-items:center; justify-content:space-between; margin-bottom:18px; }}
        .brand {{ display:flex; align-items:center; gap:10px; font-weight:900; letter-spacing:-0.6px; font-size:18px; }}
        .dot {{ width:10px; height:10px; border-radius:999px; background: linear-gradient(90deg, var(--brand1), var(--brand2)); box-shadow: 0 10px 30px rgba(99,102,241,0.45); }}
        .pill {{ font-size:12px; color:#0b1020; background: rgba(34,197,94,0.95); padding:6px 10px; border-radius: 999px; font-weight:900; }}
        .card {{ background: var(--card); border:1px solid var(--border); border-radius: 22px; box-shadow: var(--shadow); padding: 26px; }}
        h1 {{ margin: 0 0 8px 0; font-size: 30px; letter-spacing:-0.8px; }}
        .subtitle {{ margin:0 0 18px 0; color: var(--muted); font-size:14px; line-height:1.45; }}
        .grid {{ display:grid; grid-template-columns: 1.1fr 0.9fr; gap:18px; }}
        @media (max-width: 920px) {{ .grid {{ grid-template-columns: 1fr; }} }}
        .hero {{ display:grid; grid-template-columns: 1.3fr 0.7fr; gap:18px; align-items:start; }}
        @media (max-width: 920px) {{ .hero {{ grid-template-columns: 1fr; }} }}
        .kpi {{ border:1px solid var(--border); background: rgba(255,255,255,0.04); border-radius: 18px; padding: 16px; margin-top: 10px; }}
        .kpi .label {{ color: var(--muted); font-size: 12px; margin-bottom: 6px; }}
        .kpi .value {{ font-size: 22px; font-weight: 900; letter-spacing:-0.5px; }}
        .green {{ color: var(--green); }}
        .btn {{ display:inline-block; width:100%; padding:14px; border-radius: 14px; border:none; background: linear-gradient(90deg, var(--brand1), var(--brand2)); color:white; font-weight:900; cursor:pointer; text-align:center; text-decoration:none; transition:0.2s; margin-top:10px; }}
        .btn:hover {{ transform: translateY(-2px); box-shadow: 0 12px 28px rgba(99,102,241,0.35); }}
        .btn-secondary {{ background: rgba(255,255,255,0.08); border: 1px solid var(--border); }}
        input, select {{ width:100%; padding:12px 12px; margin:10px 0; border-radius:12px; border:1px solid var(--border); background: rgba(255,255,255,0.07); color: var(--text); outline:none; }}
        .muted {{ color: var(--muted); font-size: 13px; }}
        .row-actions {{ display:flex; gap:10px; flex-wrap:wrap; margin-top:12px; }}
        .row-actions .btn {{ width:auto; flex:1; min-width:220px; }}
        pre {{ background: rgba(255,255,255,0.08); padding: 16px; border-radius: 14px; white-space: pre-wrap; border: 1px solid var(--border); margin:0; }}
        .link {{ color: #93c5fd; text-decoration: none; font-weight: 900; }}
        .badge {{ display:inline-flex; align-items:center; gap:8px; padding:8px 10px; border:1px solid var(--border); border-radius:999px; background: rgba(255,255,255,0.04); color: var(--muted); font-size:12px; font-weight:900; }}
        .badge b {{ color: var(--text); }}
        .feature {{ border:1px solid var(--border); background: rgba(255,255,255,0.03); border-radius: 18px; padding: 16px; }}
        .feature h3 {{ margin:0 0 6px 0; font-size: 15px; }}
        .feature p {{ margin:0; color: var(--muted); font-size: 13px; line-height:1.4; }}
        .faq {{ border:1px solid var(--border); border-radius: 18px; padding: 14px 16px; background: rgba(255,255,255,0.03); }}
        .faq summary {{ cursor:pointer; font-weight: 900; color: var(--text); list-style:none; }}
        .faq summary::-webkit-details-marker {{ display:none; }}
        .faq p {{ margin:10px 0 0 0; color: var(--muted); font-size: 13px; line-height:1.5; }}
        .notice {{ margin-top:12px; padding:12px 14px; border:1px solid rgba(251,191,36,0.35); background: rgba(251,191,36,0.10); border-radius: 16px; color: #fde68a; font-size: 13px; line-height:1.45; }}
        .white-panel {{ background: #ffffff; color: #0b1020; border-radius: 18px; padding: 18px; }}
        .white-panel h3 {{ margin: 0 0 10px 0; font-size: 16px; }}
        ul {{ margin: 8px 0 0 18px; padding: 0; }}
        li {{ margin: 6px 0; }}
      </style>
    </head>
    <body>
      <div class="container">
        <div class="topbar">
          <div class="brand"><span class="dot"></span> SpendGuard</div>
          <div class="pill">AI SaaS Optimizer</div>
        </div>
        <div class="card">
          {inner}
        </div>
      </div>
    </body>
    </html>
    """


# ================= ROUTES CONVERSION =================
@app.get("/", response_class=HTMLResponse)
def root():
    return RedirectResponse("/pricing")

@app.get("/pricing", response_class=HTMLResponse)
def pricing():
    price = f"{PRICE_CENTS/100:.0f}€"
    inner = f"""
      <div class="hero">
        <div>
          <h1>Stop payer trop cher tes SaaS.</h1>
          <p class="subtitle">
            Upload une facture PDF → l’agent IA détecte les opportunités → il génère un <b>email</b> + une <b>stratégie</b> + un <b>rapport PDF</b>.
          </p>

          <div style="display:flex;gap:10px;flex-wrap:wrap;margin-top:10px;">
            <span class="badge">⚡ <b>30 sec</b> par audit</span>
            <span class="badge">📉 <b>5–15%</b> d’économies</span>
            <span class="badge">🤖 <b>IA</b> + score confiance</span>
          </div>

          <div class="notice">
            <b>Valeur :</b> un livrable “achats” complet, pas juste un mail.
          </div>

          <div class="row-actions" style="margin-top:16px;">
            <a class="btn" href="#try">Essayer maintenant</a>
            <a class="btn btn-secondary" href="/example">Voir un exemple</a>
          </div>

          <div style="display:grid;grid-template-columns:1fr 1fr;gap:12px;margin-top:18px;">
            <div class="feature">
              <h3>✅ Analyse IA réelle</h3>
              <p>Insights, opportunités, questions à poser, stratégie.</p>
            </div>
            <div class="feature">
              <h3>✅ Email ultra adapté</h3>
              <p>Basé sur le document, pas un template fixe.</p>
            </div>
            <div class="feature">
              <h3>✅ Rapport PDF pro</h3>
              <p>Pour archiver / envoyer à ton boss / achats.</p>
            </div>
            <div class="feature">
              <h3>✅ Paiement sécurisé</h3>
              <p>Stripe (Payment Element).</p>
            </div>
          </div>

          <h2 style="margin-top:22px;font-size:18px;margin-bottom:10px;">FAQ</h2>
          <div style="display:grid;gap:10px;">
            <details class="faq">
              <summary>Est-ce vraiment une IA ?</summary>
              <p>Oui. L’agent IA lit le texte extrait du PDF et retourne un audit structuré + email adapté + score de confiance.</p>
            </details>
            <details class="faq">
              <summary>Pourquoi payer {price} ?</summary>
              <p>L’aperçu est gratuit. Le paiement débloque le rapport complet + PDF export + contenu copiable en 1 clic.</p>
            </details>
            <details class="faq">
              <summary>Si le PDF est scanné (image) ?</summary>
              <p>Selon la qualité, l’extraction peut être limitée. Étape suivante: OCR (plus tard).</p>
            </details>
          </div>
        </div>

        <div class="kpi" id="try" style="margin-top:0;">
          <div class="label">Faire un audit</div>
          <div class="value" style="font-size:18px;">Upload une facture PDF</div>

          <form action="/preview" method="post" enctype="multipart/form-data" style="margin-top:10px;">
            <input type="file" name="file" required />
            <input type="text" name="company_name" placeholder="Nom de l’entreprise" required />
            <input type="text" name="signature_name" placeholder="Votre nom" required />
            <select name="tone">
              <option value="Pro">Professionnel</option>
              <option value="Amical">Amical</option>
              <option value="Direct">Direct</option>
            </select>
            <button class="btn" type="submit">Générer l’aperçu</button>
          </form>

          <p class="muted" style="margin-top:12px;">Rapport complet : <b>{price}</b>.</p>
          <p class="muted" style="margin-top:6px;">Tu peux aussi <a class="link" href="/example">voir un exemple</a> avant.</p>
        </div>
      </div>
    """
    return shell("SpendGuard — Pricing", inner, wide=True)

@app.get("/example", response_class=HTMLResponse)
def example():
    vendor = "Microsoft 365"
    company = "Exemple SARL"
    name = "Mohamed"
    currency = "EUR"
    total = 540.00
    savings = 81.00
    annual = round(savings * 12, 2)

    insights = [
        "Service identifié : suite bureautique / licences utilisateurs.",
        "Montant mensuel probable (à confirmer selon périodicité).",
        "Opportunités : annualisation + réduction licences."
    ]
    opps = [
        {"title":"Annualisation", "why":"Demander un prix annuel réduit.", "impact_estimate":"5–12%"},
        {"title":"Downgrade", "why":"Réduire le plan si fonctions inutiles.", "impact_estimate":"jusqu’à 20%"},
    ]
    questions = [
        "Pouvez-vous proposer une remise annuelle ?",
        "Existe-t-il un plan inférieur adapté ?",
        "Pouvons-nous réduire le nombre de licences ?"
    ]

    subject = f"Demande d’amélioration tarifaire - {company}"
    body = f"""Bonjour,

Nous utilisons {vendor}. Avant renouvellement, nous souhaitons discuter d’un ajustement tarifaire.
Serait-il possible d’obtenir une remise annuelle ou un plan plus adapté à notre usage actuel ?

Cordialement,
{name}"""

    insights_html = "".join([f"<li>{i}</li>" for i in insights])
    opps_html = "".join([f"<li><b>{o['title']}</b> — {o['why']} <span class='muted'>({o['impact_estimate']})</span></li>" for o in opps])
    q_html = "".join([f"<li>{q}</li>" for q in questions])

    inner = f"""
      <h1>Exemple de rapport</h1>
      <p class="subtitle">Voici exactement ce que tu obtiens après paiement : analyse IA, opportunités, questions, email prêt + PDF.</p>

      <div class="grid">
        <div>
          <div class="kpi">
            <div class="label">Montant</div>
            <div class="value">{total:.2f} {currency}</div>
          </div>
          <div class="kpi">
            <div class="label">Économie estimée</div>
            <div class="value green">{savings:.2f} {currency}</div>
          </div>
          <div class="kpi" style="background:rgba(34,197,94,0.10);border:1px solid rgba(34,197,94,0.25);">
            <div class="label">Projection annuelle</div>
            <div class="value green">{annual:.2f} {currency}</div>
          </div>
          <div class="kpi">
            <div class="label">Ce que l’IA a compris</div>
            <ul>{insights_html}</ul>
          </div>
          <div class="kpi">
            <div class="label">Opportunités détectées</div>
            <ul>{opps_html}</ul>
          </div>
          <div class="kpi">
            <div class="label">Questions à poser</div>
            <ul>{q_html}</ul>
          </div>

          <div class="row-actions">
            <a class="btn" href="/pricing#try">Tester avec ma facture</a>
            <a class="btn btn-secondary" href="/pricing">Retour</a>
          </div>
        </div>

        <div>
          <div class="kpi">
            <div class="label">Email prêt</div>
            <pre>Sujet: {subject}

{body}</pre>
          </div>
        </div>
      </div>
    """
    return shell("SpendGuard — Exemple", inner)


# ================= PREVIEW =================
@app.post("/preview", response_class=HTMLResponse)
async def preview(
    file: UploadFile = File(...),
    company_name: str = Form(...),
    signature_name: str = Form(...),
    tone: str = Form("Pro"),
):
    doc_id = str(uuid.uuid4())
    path = os.path.join(DATA_DIR, f"{doc_id}_{file.filename}")

    content = await file.read()
    with open(path, "wb") as f:
        f.write(content)

    raw_parts = []
    with pdfplumber.open(path) as pdf:
        for page in pdf.pages:
            raw_parts.append(page.extract_text() or "")

    raw_text = "\n".join(raw_parts)

    vendor_guess = normalize_vendor(detect_vendor(raw_text))
    currency = detect_currency(raw_text)
    total = extract_total_amount(raw_text)

    # baseline savings (simple)
    rate = 0.10 if total < 1000 else 0.15
    savings = round(min(total * rate, 2500), 2) if total > 0 else 0.0

    # IA audit
    ai = await ai_audit_from_text(
        raw_text=raw_text,
        company=company_name,
        signer=signature_name,
        tone=tone,
        fallback_vendor=vendor_guess,
        currency=currency,
        total=total,
    )

    vendor_final = normalize_vendor(ai.get("vendor") or vendor_guess)
    category = ai.get("category") or "unknown"
    confidence = float(ai.get("confidence") or 0.3)
    ai_used = bool(ai.get("ai_used"))
    insights: List[str] = ai.get("insights") or []
    opps: List[Dict[str, str]] = ai.get("opportunities") or []
    questions: List[str] = ai.get("questions") or []
    email_subject = ai.get("email_subject") or f"Demande d’amélioration tarifaire - {company_name}"
    email_body = ai.get("email_body") or ""

    set_report(doc_id, {
        "company": company_name,
        "name": signature_name,
        "tone": tone,
        "vendor": vendor_final,
        "currency": currency,
        "total": total,
        "savings": savings,
        "filename": file.filename,
        "created_ts": int(time.time()),

        # IA payload
        "ai_used": ai_used,
        "confidence": confidence,
        "category": category,
        "insights": insights,
        "opportunities": opps,
        "questions": questions,
        "email_subject": email_subject,
        "email_body": email_body,
    })

    t = sign_doc(doc_id)

    # small preview blocks
    insights_html = "".join([f"<li>{i}</li>" for i in insights[:5]]) or "<li>—</li>"
    opps_html = "".join([f"<li><b>{o.get('title','')}</b> — {o.get('why','')} <span class='muted'>({o.get('impact_estimate','')})</span></li>" for o in opps[:4]]) or "<li>—</li>"

    inner = f"""
      <h1>Aperçu</h1>
      <p class="subtitle">Aperçu gratuit. Le rapport complet débloque le PDF + email copiable + plan d’action complet.</p>

      <div class="grid">
        <div>
          <div class="kpi">
            <div class="label">Montant détecté</div>
            <div class="value">{total:.2f} {currency}</div>
          </div>

          <div class="kpi">
            <div class="label">Économie estimée (baseline)</div>
            <div class="value green">{savings:.2f} {currency}</div>
          </div>

          <div class="kpi">
            <div class="label">Fournisseur + catégorie</div>
            <div class="value">{vendor_final}</div>
            <div class="muted" style="margin-top:6px;">Catégorie: <b>{category}</b></div>
          </div>

          <div class="kpi">
            <div class="label">Analyse IA</div>
            <div class="value" style="font-size:16px;">{"✅ IA active" if ai_used else "⚠️ IA fallback"} — Confiance: {confidence:.2f}</div>
            <ul style="margin-top:10px;line-height:1.5;">{insights_html}</ul>
          </div>

          <a class="btn" href="/pay/{doc_id}?t={t}">Débloquer le rapport complet ({PRICE_CENTS/100:.0f}€)</a>
          <a class="btn btn-secondary" href="/example">Voir un exemple</a>

          <p class="muted" style="margin-top:10px;">ID : <strong>{doc_id}</strong></p>
        </div>

        <div>
          <div class="kpi">
            <div class="label">Opportunités détectées (aperçu)</div>
            <ul style="margin-top:10px;line-height:1.5;">{opps_html}</ul>
          </div>

          <div class="kpi">
            <div class="label">Ce que tu obtiens</div>
            <pre>✅ Analyse IA complète + score confiance
✅ Opportunités + questions à poser
✅ Email ultra adapté
✅ Export PDF pro
✅ Bouton “Copier”</pre>
          </div>
        </div>
      </div>

      <p style="margin-top:18px;"><a class="link" href="/pricing">← Nouvelle analyse</a></p>
    """
    return shell("Aperçu", inner)


# ================= STRIPE PAYMENT PAGE =================
def render_payment_element(doc_id: str, t: str) -> str:
    return f"""
      <div class="white-panel">
        <h3>Paiement sécurisé</h3>
        <div id="payment-element"></div>

        <button id="submit" class="btn" style="margin-top:14px;">
          Payer et débloquer
        </button>

        <p class="muted" id="payMsg" style="margin-top:10px;"></p>
        <p class="muted" style="margin-top:8px;font-size:12px;">
          Carte test : <b>4242 4242 4242 4242</b> (date future, CVC 123).
        </p>
      </div>

      <script src="https://js.stripe.com/v3/"></script>
      <script>
        (async () => {{
          const msg = document.getElementById("payMsg");
          const btn = document.getElementById("submit");
          const stripe = Stripe("{STRIPE_PUBLISHABLE_KEY}");

          const res = await fetch("/create-payment-intent", {{
            method: "POST",
            headers: {{ "Content-Type": "application/json" }},
            body: JSON.stringify({{ doc_id: "{doc_id}", t: "{t}" }})
          }});

          if (!res.ok) {{
            msg.textContent = "⚠️ Erreur serveur (create-payment-intent).";
            return;
          }}

          const data = await res.json();
          if (!data.client_secret) {{
            msg.textContent = "⚠️ client_secret manquant.";
            return;
          }}

          const elements = stripe.elements({{ clientSecret: data.client_secret }});
          const paymentElement = elements.create("payment");
          paymentElement.mount("#payment-element");

          btn.addEventListener("click", async (e) => {{
            e.preventDefault();
            btn.disabled = true;
            msg.textContent = "⏳ Paiement en cours…";

            const {{ error }} = await stripe.confirmPayment({{
              elements,
              confirmParams: {{
                return_url: window.location.origin + "/success/{doc_id}?t={t}"
              }}
            }});

            if (error) {{
              msg.textContent = "⚠️ " + (error.message || "Paiement refusé");
              btn.disabled = false;
            }}
          }});
        }})().catch(err => {{
          const msg = document.getElementById("payMsg");
          if (msg) msg.textContent = "⚠️ Erreur : " + err;
        }});
      </script>
    """

@app.get("/pay/{doc_id}", response_class=HTMLResponse)
def pay(request: Request, doc_id: str):
    t = request.query_params.get("t")
    if not check_sig(doc_id, t):
        return shell("Lien invalide", "<h1>Lien invalide</h1><p class='muted'>Reviens depuis l’aperçu.</p><a class='btn' href='/pricing'>Retour</a>")

    data = get_report(doc_id)
    if not data:
        return shell("Erreur", "<h1>Rapport introuvable</h1><p class='muted'>Refais l’aperçu.</p><a class='btn' href='/pricing'>Retour</a>")

    if is_paid(doc_id):
        return RedirectResponse(f"/full/{doc_id}?t={t}")

    vendor = normalize_vendor(data.get("vendor"))
    currency = data.get("currency", "EUR")
    total = float(data.get("total") or 0)
    savings = float(data.get("savings") or 0)
    annual = round(savings * 12, 2)

    inner = f"""
      <h1>Paiement</h1>
      <p class="subtitle">Débloque le rapport complet. Montant : <strong>{PRICE_CENTS/100:.0f}€</strong>.</p>

      <div class="grid">
        <div>
          <div class="kpi">
            <div class="label">Résumé</div>
            <div class="value">{vendor}</div>
            <div class="muted" style="margin-top:8px;">Montant détecté : <b>{total:.2f} {currency}</b></div>
            <div class="muted">Économie baseline : <b class="green">{savings:.2f} {currency}</b></div>
          </div>

          <div class="kpi" style="background:rgba(34,197,94,0.10);border:1px solid rgba(34,197,94,0.25);">
            <div class="label">Projection annuelle</div>
            <div class="value green">{annual:.2f} {currency}</div>
            <div class="muted" style="margin-top:6px;">(si cette dépense est mensuelle)</div>
          </div>

          <div class="kpi">
            <div class="label">Ce que tu débloques</div>
            <pre>✅ Audit IA complet (insights + opportunités)
✅ Questions de négociation prêtes
✅ Email ultra adapté (copiable)
✅ Rapport PDF “pro”</pre>
          </div>

          <p style="margin-top:18px;"><a class="link" href="/pricing">← Retour</a></p>
        </div>

        <div>
          {render_payment_element(doc_id, t)}
        </div>
      </div>
    """
    return shell("Paiement", inner)


class PayReq(BaseModel):
    doc_id: str
    t: str

@app.post("/create-payment-intent")
def create_payment_intent(req: PayReq):
    if not check_sig(req.doc_id, req.t):
        raise HTTPException(status_code=403, detail="token invalide")
    if not get_report(req.doc_id):
        raise HTTPException(status_code=404, detail="doc_id introuvable")

    intent = stripe.PaymentIntent.create(
        amount=PRICE_CENTS,
        currency=CURRENCY,
        automatic_payment_methods={"enabled": True},
        metadata={"doc_id": req.doc_id},
    )
    return JSONResponse({"client_secret": intent.client_secret})


@app.get("/success/{doc_id}", response_class=HTMLResponse)
def success(request: Request, doc_id: str):
    t = request.query_params.get("t")
    if not check_sig(doc_id, t):
        return shell("Lien invalide", "<h1>Lien invalide</h1><p class='muted'>Token manquant.</p><a class='btn' href='/pricing'>Retour</a>")

    pi_id = request.query_params.get("payment_intent")
    if pi_id:
        try:
            pi = stripe.PaymentIntent.retrieve(pi_id)
            if pi.status == "succeeded":
                mark_paid(doc_id, payment_intent=pi.id)
        except Exception:
            pass

    if not is_paid(doc_id):
        inner = f"""
          <h1>Paiement en cours de confirmation</h1>
          <p class="subtitle">Attends 2–5 secondes puis clique sur le bouton.</p>
          <a class="btn" href="/full/{doc_id}?t={t}">Accéder au rapport</a>
          <a class="btn btn-secondary" href="/pay/{doc_id}?t={t}">Retour paiement</a>
        """
        return shell("Confirmation", inner)

    inner = f"""
      <h1>Paiement confirmé ✅</h1>
      <p class="subtitle">Ton rapport complet est débloqué.</p>
      <a class="btn" href="/full/{doc_id}?t={t}">Voir le rapport complet</a>
    """
    return shell("Succès", inner)


@app.post("/stripe/webhook")
async def stripe_webhook(request: Request):
    payload = await request.body()
    sig_header = request.headers.get("stripe-signature")
    if not sig_header:
        raise HTTPException(status_code=400, detail="Missing Stripe-Signature header")

    try:
        event = stripe.Webhook.construct_event(
            payload=payload,
            sig_header=sig_header,
            secret=STRIPE_WEBHOOK_SECRET,
        )
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid payload")
    except stripe.error.SignatureVerificationError:
        raise HTTPException(status_code=400, detail="Invalid signature")

    if event.get("type") == "payment_intent.succeeded":
        obj = event["data"]["object"]
        doc_id = (obj.get("metadata") or {}).get("doc_id")
        if doc_id:
            mark_paid(doc_id, payment_intent=obj.get("id", ""))

    return {"received": True}


# ================= FULL REPORT =================
@app.get("/full/{doc_id}", response_class=HTMLResponse)
def full(request: Request, doc_id: str):
    t = request.query_params.get("t")
    if not check_sig(doc_id, t):
        return shell("Lien invalide", "<h1>Lien invalide</h1><p class='muted'>Reviens via le lien après paiement.</p><a class='btn' href='/pricing'>Retour</a>")

    data = get_report(doc_id)
    if not data:
        return shell("Erreur", "<h1>Rapport introuvable</h1><p class='muted'>Refais l’aperçu.</p><a class='btn' href='/pricing'>Retour</a>")

    if not is_paid(doc_id):
        return shell("Accès verrouillé", f"<h1>Accès verrouillé</h1><p class='muted'>Paiement requis.</p><a class='btn' href='/pay/{doc_id}?t={t}'>Payer</a>")

    vendor = normalize_vendor(data.get("vendor"))
    currency = data.get("currency", "EUR")
    total = float(data.get("total") or 0)
    savings = float(data.get("savings") or 0)
    annual = round(savings * 12, 2)

    ai_used = bool(data.get("ai_used"))
    confidence = float(data.get("confidence") or 0.3)
    category = data.get("category") or "unknown"
    insights: List[str] = data.get("insights") or []
    opps: List[Dict[str, str]] = data.get("opportunities") or []
    questions: List[str] = data.get("questions") or []

    subject = data.get("email_subject") or f"Demande d’amélioration tarifaire - {data['company']}"
    body = data.get("email_body") or ""

    email_text = f"Sujet: {subject}\n\n{body}"
    email_text_js = json.dumps(email_text)

    insights_html = "".join([f"<li>{i}</li>" for i in insights]) or "<li>—</li>"
    opps_html = "".join([f"<li><b>{o.get('title','')}</b> — {o.get('why','')} <span class='muted'>({o.get('impact_estimate','')})</span></li>" for o in opps]) or "<li>—</li>"
    q_html = "".join([f"<li>{q}</li>" for q in questions]) or "<li>—</li>"

    inner = f"""
      <h1>Rapport complet</h1>
      <p class="subtitle">Audit IA + stratégie + email prêt à envoyer + export PDF.</p>

      <div class="grid">
        <div>
          <div class="kpi">
            <div class="label">Montant</div>
            <div class="value">{total:.2f} {currency}</div>
          </div>

          <div class="kpi">
            <div class="label">Économie baseline</div>
            <div class="value green">{savings:.2f} {currency}</div>
          </div>

          <div class="kpi" style="background:rgba(34,197,94,0.10);border:1px solid rgba(34,197,94,0.25);">
            <div class="label">Projection annuelle</div>
            <div class="value green">{annual:.2f} {currency}</div>
            <div class="muted" style="margin-top:6px;">(si cette dépense est mensuelle)</div>
          </div>

          <div class="kpi">
            <div class="label">Analyse IA</div>
            <div class="value" style="font-size:16px;">{"✅ IA active" if ai_used else "⚠️ IA fallback"} — Confiance: {confidence:.2f}</div>
            <div class="muted" style="margin-top:6px;">Fournisseur: <b>{vendor}</b> • Catégorie: <b>{category}</b></div>
            <ul style="margin-top:10px;line-height:1.5;">{insights_html}</ul>
          </div>

          <div class="kpi">
            <div class="label">Opportunités détectées</div>
            <ul style="margin-top:10px;line-height:1.5;">{opps_html}</ul>
          </div>

          <div class="kpi">
            <div class="label">Questions à poser</div>
            <ul style="margin-top:10px;line-height:1.5;">{q_html}</ul>
          </div>

          <div class="row-actions">
            <button class="btn btn-secondary" id="copyBtn">Copier l’email</button>
            <a class="btn" href="/print/{doc_id}?t={t}" target="_blank">Télécharger PDF</a>
          </div>

          <p class="muted" id="copyMsg" style="margin-top:10px;"></p>
        </div>

        <div>
          <div class="kpi">
            <div class="label">Email prêt (adapté)</div>
            <pre id="emailBlock">Sujet: {subject}

{body}</pre>
          </div>
        </div>
      </div>

      <script>
        const emailText = {email_text_js};
        const btn = document.getElementById("copyBtn");
        const msg = document.getElementById("copyMsg");
        btn.addEventListener("click", async () => {{
          try {{
            await navigator.clipboard.writeText(emailText);
            msg.textContent = "✅ Email copié dans le presse-papier.";
          }} catch (e) {{
            msg.textContent = "⚠️ Copie automatique refusée. Copie manuellement.";
          }}
        }});
      </script>

      <p style="margin-top:18px;"><a class="link" href="/pricing">← Nouvelle analyse</a></p>
    """
    return shell("Rapport complet", inner)


# ================= PRINT VIEW =================
@app.get("/print/{doc_id}", response_class=HTMLResponse)
def print_view(request: Request, doc_id: str):
    t = request.query_params.get("t")
    if not check_sig(doc_id, t):
        return HTMLResponse("Lien invalide (token manquant ou incorrect).", status_code=403)

    data = get_report(doc_id)
    if not data:
        return HTMLResponse("Rapport introuvable", status_code=404)
    if not is_paid(doc_id):
        return HTMLResponse("Paiement requis", status_code=403)

    vendor = normalize_vendor(data.get("vendor"))
    currency = data.get("currency", "EUR")
    total = float(data.get("total") or 0)
    savings = float(data.get("savings") or 0)
    annual = round(savings * 12, 2)

    subject = data.get("email_subject") or f"Demande d’amélioration tarifaire - {data['company']}"
    body = data.get("email_body") or ""

    return f"""
    <html>
    <head>
      <meta charset="utf-8"/>
      <title>SpendGuard – Rapport</title>
      <style>
        body {{
          font-family: Arial, sans-serif;
          margin: 40px;
          color: #111827;
        }}
        h1 {{ margin:0 0 10px 0; }}
        .meta {{ color:#374151; margin-bottom:18px; }}
        .box {{
          border:1px solid #e5e7eb;
          padding:16px;
          border-radius:12px;
          margin-top:14px;
          white-space: pre-wrap;
        }}
        .kpis {{
          display:grid;
          grid-template-columns: 1fr 1fr;
          gap:12px;
          margin-top:18px;
        }}
        .kpi {{
          border:1px solid #e5e7eb;
          border-radius:12px;
          padding:14px;
        }}
        .kpi.greenbox {{
          border:1px solid #86efac;
          background:#f0fdf4;
        }}
        .label {{ color:#6b7280; font-size:12px; }}
        .value {{ font-size:18px; font-weight:700; margin-top:6px; }}
        .green {{ color:#16a34a; }}
        @media print {{
          button {{ display:none; }}
          body {{ margin: 0; }}
        }}
      </style>
    </head>
    <body>
      <button onclick="window.print()" style="padding:10px 14px;border:none;border-radius:10px;background:#111827;color:white;cursor:pointer;">
        Imprimer / Enregistrer en PDF
      </button>

      <h1>Rapport SpendGuard</h1>
      <div class="meta">Entreprise : <strong>{data['company']}</strong> • Fichier : <strong>{data['filename']}</strong></div>

      <div class="kpis">
        <div class="kpi">
          <div class="label">Montant</div>
          <div class="value">{total:.2f} {currency}</div>
        </div>
        <div class="kpi">
          <div class="label">Économie baseline</div>
          <div class="value green">{savings:.2f} {currency}</div>
        </div>
        <div class="kpi greenbox">
          <div class="label">Projection annuelle</div>
          <div class="value green">{annual:.2f} {currency}</div>
          <div class="label" style="margin-top:6px;">(si dépense mensuelle)</div>
        </div>
        <div class="kpi">
          <div class="label">Fournisseur</div>
          <div class="value">{vendor}</div>
        </div>
      </div>

      <h2 style="margin-top:22px;">Email prêt à envoyer</h2>
      <div class="box">Sujet: {subject}

{body}</div>
    </body>
    </html>
    """


# ================= HEALTH =================
@app.get("/health")
def health():
    return {"status": "running", "ai_enabled": AI_ENABLED, "ai_model": AI_MODEL}