from __future__ import annotations

import os, re, json, uuid, time, hmac, hashlib
from typing import Dict, Any, Optional, List

import pdfplumber
import stripe
import httpx

from dotenv import load_dotenv
from fastapi import FastAPI, UploadFile, File, Form, HTTPException, Request
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse
from pydantic import BaseModel

# ================= CONFIG =================
load_dotenv()

STRIPE_SECRET_KEY = os.getenv("STRIPE_SECRET_KEY", "")
STRIPE_PUBLISHABLE_KEY = os.getenv("STRIPE_PUBLISHABLE_KEY", "")
STRIPE_WEBHOOK_SECRET = os.getenv("STRIPE_WEBHOOK_SECRET", "")

APP_SECRET = os.getenv("APP_SECRET", "change-me-please")
OPENAI_API_KEY = os.getenv("OPENAI_API_KEY", "")  # optionnel

PRICE_CENTS = 900
CURRENCY = "eur"
PRODUCT_NAME = "Rapport SpendGuard (audit + email + PDF)"

stripe.api_key = STRIPE_SECRET_KEY

app = FastAPI(title="SpendGuard AI")

DATA_DIR = "./data"
os.makedirs(DATA_DIR, exist_ok=True)
STATE_PATH = os.path.join(DATA_DIR, "state.json")


# ================= SECURITY (signed token) =================
def sign_doc(doc_id: str) -> str:
    msg = doc_id.encode("utf-8")
    key = APP_SECRET.encode("utf-8")
    return hmac.new(key, msg, hashlib.sha256).hexdigest()[:16]

def check_sig(doc_id: str, t: str | None) -> bool:
    if not t:
        return False
    return hmac.compare_digest(sign_doc(doc_id), t)


# ================= PERSISTENCE (disk) =================
def _default_state() -> Dict[str, Any]:
    return {"reports": {}, "paid": {}}

def load_state() -> Dict[str, Any]:
    if not os.path.exists(STATE_PATH):
        s = _default_state()
        save_state(s)
        return s
    try:
        with open(STATE_PATH, "r", encoding="utf-8") as f:
            s = json.load(f)
        if "reports" not in s: s["reports"] = {}
        if "paid" not in s: s["paid"] = {}
        return s
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
    return load_state()["reports"].get(doc_id)

def set_report(doc_id: str, data: Dict[str, Any]) -> None:
    state = load_state()
    state["reports"][doc_id] = data
    save_state(state)

def mark_paid(doc_id: str, payment_intent: str | None = None) -> None:
    state = load_state()
    state["paid"][doc_id] = {
        "paid_at": int(time.time()),
        "payment_intent": payment_intent or state["paid"].get(doc_id, {}).get("payment_intent", ""),
    }
    save_state(state)

def is_paid(doc_id: str) -> bool:
    state = load_state()
    return doc_id in state.get("paid", {})


# ================= TEXT EXTRACT / HEURISTICS =================
def detect_currency(text: str) -> str:
    if "€" in text or "eur" in text.lower():
        return "EUR"
    if "$" in text or "usd" in text.lower():
        return "USD"
    if "£" in text or "gbp" in text.lower():
        return "GBP"
    return "UNKNOWN"

def normalize_vendor(name: str) -> str:
    v = (name or "UNKNOWN").strip()
    v = v.replace("Ia", "IA").replace("Aws", "AWS").replace("Hubspot", "HubSpot")
    v = re.sub(r"\s{2,}", " ", v)
    return v

def detect_vendor(raw_text: str) -> str:
    text = raw_text.strip()
    low = text.lower()

    brands = [
        ("google workspace", "Google Workspace"),
        ("workspace", "Google Workspace"),
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
        m = re.search(p, text, re.IGNORECASE)
        if m:
            cand = m.group(m.lastindex).strip().split("\n")[0].strip()
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
        except:
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

def extract_vat_breakdown(text: str) -> Dict[str, float]:
    """
    Retourne un dict {'vat_rate': 20.0, 'vat_amount': 900.0, 'subtotal': 4500.0} si trouvé.
    Heuristique simple.
    """
    t = text.replace("\u00a0", " ")
    low = t.lower()

    # TVA 20% + montant
    vat_rate = None
    m_rate = re.search(r"(tva|vat)\s*[:\-]?\s*(\d{1,2}(?:[.,]\d)?)\s*%", low)
    if m_rate:
        try:
            vat_rate = float(m_rate.group(2).replace(",", "."))
        except:
            vat_rate = None

    def parse_any_amount(s: str) -> float:
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
        except:
            return 0.0

    vat_amount = 0.0
    m_vat_amt = re.search(r"(tva|vat)\s*(?:\(\s*\d{1,2}.*?%\s*\))?\s*[:\-]?\s*([0-9]{1,3}(?:[ .][0-9]{3})*(?:[.,][0-9]{2}))", low)
    if m_vat_amt:
        vat_amount = parse_any_amount(m_vat_amt.group(2))

    subtotal = 0.0
    m_ht = re.search(r"(ht|hors\s*taxe|subtotal)\s*[:\-]?\s*([0-9]{1,3}(?:[ .][0-9]{3})*(?:[.,][0-9]{2}))", low)
    if m_ht:
        subtotal = parse_any_amount(m_ht.group(2))

    out = {}
    if vat_rate is not None: out["vat_rate"] = vat_rate
    if vat_amount > 0: out["vat_amount"] = vat_amount
    if subtotal > 0: out["subtotal"] = subtotal
    return out

def detect_recurring(text: str) -> str:
    low = text.lower()
    if any(k in low for k in ["mensuel", "monthly", "/mo", "per month", "mois"]):
        return "monthly"
    if any(k in low for k in ["annuel", "annual", "/yr", "per year", "year"]):
        return "annual"
    if any(k in low for k in ["trimestr", "quarter"]):
        return "quarterly"
    return "unknown"

def categorize_vendor(vendor: str) -> str:
    low = vendor.lower()
    if any(k in low for k in ["aws", "azure", "ovh", "cloud", "infrastructure"]):
        return "cloud / infrastructure"
    if any(k in low for k in ["adobe", "canva"]):
        return "design / creative"
    if any(k in low for k in ["slack", "notion", "workspace", "microsoft 365"]):
        return "productivity / collaboration"
    if any(k in low for k in ["stripe", "payment"]):
        return "payments"
    if vendor == "UNKNOWN":
        return "unknown"
    return "saas"


# ================= LLM (optional, real AI if OPENAI_API_KEY) =================
def goal_label(goal: str) -> str:
    m = {
        "reduce": "Négocier une réduction tarifaire",
        "annual": "Passer en annuel (remise)",
        "downgrade": "Downgrade / plan inférieur",
        "cancel": "Résiliation stratégique",
        "audit": "Audit interne (optimisation)",
    }
    return m.get(goal, "Optimisation")

async def llm_analyze_invoice(
    text: str,
    vendor: str,
    currency: str,
    total: float,
    savings: float,
    company: str,
    signer: str,
    goal: str,
) -> Dict[str, Any]:
    # Fallback si pas de clé
    if not OPENAI_API_KEY:
        recurring = detect_recurring(text)
        vat = extract_vat_breakdown(text)
        cat = categorize_vendor(vendor)
        confidence = 0.72 if vendor != "UNKNOWN" else 0.55

        bullets = []
        bullets.append(f"Fournisseur détecté : {vendor} • Catégorie : {cat}.")
        if total > 0:
            bullets.append(f"Montant détecté : {total:.2f} {currency}.")
        if vat:
            parts = []
            if "subtotal" in vat: parts.append(f"{vat['subtotal']:.2f} HT")
            if "vat_amount" in vat: parts.append(f"{vat['vat_amount']:.2f} TVA")
            if "vat_rate" in vat: parts.append(f"taux {vat['vat_rate']:.1f}%")
            bullets.append("TVA : " + " • ".join(parts) + ".")
        if recurring != "unknown":
            bullets.append(f"Indices de périodicité : {recurring}.")
        else:
            bullets.append("Aucune périodicité clairement indiquée sur l’extrait.")

        opps = [
            {
                "title": "Clarification des modalités contractuelles",
                "detail": "Demander la périodicité, la date de renouvellement, les conditions de résiliation, et les clauses d’indexation.",
                "impact": "Réduction du risque et meilleure planification budgétaire.",
            },
            {
                "title": "Négociation du prix / conditions de paiement",
                "detail": "Demander une remise annuelle, une réduction fidélité, ou des conditions de paiement plus flexibles.",
                "impact": f"Potentiel d’économies : ~{(savings*12):.2f} {currency} / an (si mensuel).",
            },
            {
                "title": "Audit licences / usage",
                "detail": "Vérifier utilisateurs, sièges et modules réellement utilisés. Supprimer les options non utilisées.",
                "impact": "Réduction directe de la dépense récurrente.",
            },
        ]

        # Email adapté à l’objectif
        subj = f"Demande d’optimisation tarifaire – {company}"
        if goal == "annual":
            subj = f"Passage en annuel – demande de remise – {company}"
        elif goal == "downgrade":
            subj = f"Changement de plan – optimisation – {company}"
        elif goal == "cancel":
            subj = f"Préavis / conditions de résiliation – {company}"
        elif goal == "audit":
            subj = f"Demande d’informations contractuelles – {company}"

        body = f"""Bonjour,

Nous utilisons {vendor} et souhaitons optimiser notre abonnement ({goal_label(goal)}).

Pouvez-vous nous confirmer :
- la périodicité (mensuelle/annuelle) et la date de renouvellement,
- les conditions de résiliation / préavis,
- les options incluses et les paliers tarifaires.

Nous sommes également ouverts à une remise (annuelle/fidélité) ou à un plan plus adapté.

Cordialement,
{signer}
{company}"""

        return {
            "ai_active": False,
            "confidence": round(confidence, 2),
            "category": cat,
            "bullets": bullets,
            "opportunities": opps,
            "email_subject": subj,
            "email_body": body,
        }

    # --- True AI via OpenAI Responses API (HTTP) ---
    # (Tu mets OPENAI_API_KEY dans Render env vars)
    prompt = f"""
Tu es un expert en optimisation d'abonnements SaaS B2B.
Objectif utilisateur: {goal_label(goal)}.

Analyse le texte de facture ci-dessous et retourne un JSON STRICT avec ce schéma:
{{
  "confidence": number (0..1),
  "category": string,
  "bullets": [string, ...] (5 à 8 points),
  "opportunities": [{{"title":string,"detail":string,"impact":string}}, ...] (3 à 6 items),
  "email_subject": string,
  "email_body": string
}}

Contrainte: réponses en français, factuelles, ne pas inventer ce qui n'est pas dans le texte; si une info manque, le dire.
Contexte détecté: vendor="{vendor}", currency="{currency}", total={total}, savings_estimate={savings}, company="{company}", signer="{signer}".

TEXTE FACTURE:
\"\"\"{text[:18000]}\"\"\"
""".strip()

    headers = {
        "Authorization": f"Bearer {OPENAI_API_KEY}",
        "Content-Type": "application/json",
    }

    payload = {
        "model": "gpt-4.1-mini",
        "input": prompt,
        "text": {"format": "json"},
    }

    try:
        async with httpx.AsyncClient(timeout=25) as client:
            r = await client.post("https://api.openai.com/v1/responses", headers=headers, json=payload)
            r.raise_for_status()
            data = r.json()

        # Responses API returns output text in output[0].content[0].text (most common)
        out_text = ""
        for item in data.get("output", []):
            for c in item.get("content", []):
                if c.get("type") == "output_text":
                    out_text += c.get("text", "")
        out_text = out_text.strip()

        parsed = json.loads(out_text)
        parsed["ai_active"] = True
        return parsed
    except Exception:
        # fallback si API down / quota
        return await llm_analyze_invoice(
            text=text,
            vendor=vendor,
            currency=currency,
            total=total,
            savings=savings,
            company=company,
            signer=signer,
            goal=goal,
        )


# ================= UI (shell + loading) =================
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
  --card:rgba(255,255,255,0.07);
  --border:rgba(255,255,255,0.14);
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
  color: var(--text);
  min-height:100vh;
  display:flex;
  justify-content:center;
  align-items:flex-start;
  padding:44px 14px;
  background:#0b1020;
  overflow-x:hidden;
}}
/* Fond premium fixe (corrige le bug de répétition au scroll) */
body::before{{
  content:"";
  position:fixed;
  inset:0;
  z-index:-1;
  background:
    radial-gradient(1200px 600px at 20% 10%, rgba(99,102,241,0.35), transparent 55%),
    radial-gradient(900px 500px at 85% 30%, rgba(59,130,246,0.30), transparent 55%),
    linear-gradient(135deg, var(--bg1), var(--bg2));
  background-repeat:no-repeat;
  background-size:cover;
  background-attachment:fixed;
  transform:translateZ(0);
}}
.container {{ width:100%; max-width:{maxw}; }}
.topbar {{
  display:flex; align-items:center; justify-content:space-between; margin-bottom:18px;
}}
.brand {{
  display:flex; align-items:center; gap:10px; font-weight:900; letter-spacing:-0.6px; font-size:18px;
}}
.dot {{
  width:10px; height:10px; border-radius:999px;
  background: linear-gradient(90deg, var(--brand1), var(--brand2));
  box-shadow: 0 10px 30px rgba(99,102,241,0.45);
}}
.pill {{
  font-size:12px; color:#0b1020; background: rgba(34,197,94,0.95);
  padding:6px 10px; border-radius:999px; font-weight:900;
}}
.card {{
  background: var(--card);
  border:1px solid var(--border);
  border-radius:22px;
  box-shadow: var(--shadow);
  padding:26px;
  backdrop-filter: blur(10px);
}}
h1 {{
  margin:0 0 8px 0;
  font-size:30px;
  letter-spacing:-0.8px;
}}
.subtitle {{
  margin:0 0 18px 0;
  color: var(--muted);
  font-size:14px;
  line-height:1.45;
}}
.grid {{
  display:grid;
  grid-template-columns: 1.1fr 0.9fr;
  gap:18px;
}}
@media (max-width: 920px) {{
  .grid {{ grid-template-columns:1fr; }}
}}
.kpi {{
  border:1px solid var(--border);
  background: rgba(255,255,255,0.05);
  border-radius:18px;
  padding:16px;
  margin-top:10px;
}}
.kpi .label {{
  color: var(--muted);
  font-size:12px;
  margin-bottom:6px;
}}
.kpi .value {{
  font-size:22px;
  font-weight:900;
  letter-spacing:-0.5px;
}}
.green {{ color: var(--green); }}
.btn {{
  display:inline-block; width:100%;
  padding:14px;
  border-radius:14px;
  border:none;
  background: linear-gradient(90deg, var(--brand1), var(--brand2));
  color:white;
  font-weight:900;
  cursor:pointer;
  text-align:center;
  text-decoration:none;
  transition:all 0.2s ease;
  margin-top:10px;
}}
.btn:hover {{
  transform: translateY(-2px);
  box-shadow: 0 12px 28px rgba(99,102,241,0.35);
}}
.btn-secondary {{
  background: rgba(255,255,255,0.08);
  border:1px solid var(--border);
}}
input, select {{
  width:100%;
  padding:12px;
  margin:10px 0;
  border-radius:12px;
  border:1px solid var(--border);
  background: rgba(255,255,255,0.07);
  color: var(--text);
  outline:none;
  transition:0.2s;
}}
input:focus, select:focus {{
  border-color: var(--brand1);
  box-shadow:0 0 0 2px rgba(59,130,246,0.3);
}}
.muted {{
  color: var(--muted);
  font-size:13px;
}}
.row-actions {{
  display:flex;
  gap:10px;
  flex-wrap:wrap;
  margin-top:12px;
}}
.row-actions .btn {{
  width:auto;
  flex:1;
  min-width:220px;
}}
pre {{
  background: rgba(255,255,255,0.08);
  padding:16px;
  border-radius:14px;
  white-space: pre-wrap;
  border:1px solid var(--border);
  margin:0;
}}
.link {{
  color:#93c5fd;
  text-decoration:none;
  font-weight:900;
}}
.badge {{
  display:inline-flex;
  align-items:center;
  gap:8px;
  padding:8px 10px;
  border:1px solid var(--border);
  border-radius:999px;
  background: rgba(255,255,255,0.05);
  color: var(--muted);
  font-size:12px;
  font-weight:900;
}}
.badge b {{ color: var(--text); }}
/* loading overlay */
#loadingOverlay {{
  position:fixed;
  inset:0;
  display:none;
  align-items:center;
  justify-content:center;
  background: rgba(2,6,23,0.72);
  z-index:9999;
  backdrop-filter: blur(6px);
}}
.loaderCard {{
  width:min(520px, calc(100% - 32px));
  background: rgba(255,255,255,0.08);
  border:1px solid rgba(255,255,255,0.14);
  border-radius: 20px;
  padding: 18px;
  box-shadow: 0 30px 90px rgba(0,0,0,0.55);
}}
.spinner {{
  width:46px;
  height:46px;
  border-radius:999px;
  border: 4px solid rgba(255,255,255,0.18);
  border-top-color: rgba(99,102,241,0.95);
  animation: spin 1s linear infinite;
}}
@keyframes spin {{ to {{ transform: rotate(360deg); }} }}
.progressLine {{
  height:10px;
  border-radius:999px;
  overflow:hidden;
  background: rgba(255,255,255,0.10);
  margin-top:12px;
}}
.progressLine > div {{
  width:40%;
  height:100%;
  background: linear-gradient(90deg, rgba(59,130,246,0.95), rgba(99,102,241,0.95));
  animation: move 1.2s ease-in-out infinite;
}}
@keyframes move {{
  0% {{ transform: translateX(-60%); }}
  50% {{ transform: translateX(140%); }}
  100% {{ transform: translateX(-60%); }}
}}
      </style>
    </head>
    <body>
      <div id="loadingOverlay">
        <div class="loaderCard">
          <div style="display:flex;align-items:center;gap:14px;">
            <div class="spinner"></div>
            <div>
              <div style="font-weight:900;font-size:16px;">Analyse en cours…</div>
              <div class="muted" style="margin-top:4px;">On extrait la facture, on détecte le fournisseur et on génère l’audit IA.</div>
            </div>
          </div>
          <div class="progressLine"><div></div></div>
          <div class="muted" style="margin-top:10px;font-size:12px;">Astuce : les grosses factures peuvent prendre quelques secondes.</div>
        </div>
      </div>

      <div class="container">
        <div class="topbar">
          <div class="brand"><span class="dot"></span> SpendGuard</div>
          <div class="pill">AI SaaS Optimizer</div>
        </div>
        <div class="card">
          {inner}
        </div>
      </div>

      <script>
        // Affiche un overlay "analyse" dès qu'un formulaire est soumis (UX pro)
        function enableLoadingOnForm(formId) {{
          const f = document.getElementById(formId);
          if (!f) return;
          f.addEventListener("submit", () => {{
            const ov = document.getElementById("loadingOverlay");
            if (ov) ov.style.display = "flex";
          }});
        }}
        enableLoadingOnForm("mainForm");
      </script>
    </body>
    </html>
    """


# ================= STRIPE (Payment Element) =================
def render_stripe_checkout(doc_id: str) -> str:
    # return_url va rediriger vers /success/{doc_id}?t=...
    # Stripe ajoute ?payment_intent=... automatiquement à return_url
    return f"""
    <div class="kpi" style="background:rgba(255,255,255,.06);">
      <div class="label">Paiement sécurisé</div>

      <div id="paybox" style="margin-top:10px;">
        <div id="payment-element"></div>

        <button id="submit" class="btn" style="width:100%;margin-top:14px;">
          Payer et débloquer
        </button>

        <p class="muted" id="payMsg" style="margin-top:10px;"></p>
        <p class="muted" style="margin-top:8px;font-size:12px;">
          Carte test : <b>4242 4242 4242 4242</b> (date future, CVC 123).
        </p>
      </div>
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
          body: JSON.stringify({{ doc_id: "{doc_id}" }})
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
              return_url: window.location.origin + "/success/{doc_id}?t={sign_doc(doc_id)}"
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


# ================= ROUTES =================
@app.get("/health")
def health():
    return {"status": "running"}

@app.get("/", response_class=HTMLResponse)
def home():
    inner = f"""
      <h1>Optimise tes abonnements SaaS</h1>
      <p class="subtitle">
        Upload une facture PDF. On détecte le montant, le fournisseur, et on génère un <b>audit IA</b> + un email de négociation prêt à envoyer.
      </p>

      <div class="badge">Rapport complet : <b>9€</b> • Paiement sécurisé</div>

      <form id="mainForm" action="/preview" method="post" enctype="multipart/form-data" style="margin-top:12px;">
        <input type="file" name="file" required />
        <input type="text" name="company_name" placeholder="Nom de l’entreprise" required />
        <input type="text" name="signature_name" placeholder="Votre nom" required />

        <select name="goal" required>
          <option value="reduce">Objectif : Réduire le prix</option>
          <option value="annual">Objectif : Passer en annuel (remise)</option>
          <option value="downgrade">Objectif : Downgrade plan</option>
          <option value="cancel">Objectif : Résilier</option>
          <option value="audit">Objectif : Audit interne</option>
        </select>

        <select name="tone">
          <option value="Pro">Ton : Professionnel</option>
          <option value="Amical">Ton : Amical</option>
          <option value="Direct">Ton : Direct</option>
        </select>

        <button class="btn" type="submit">Générer l’aperçu</button>
      </form>

      <p class="muted" style="margin-top:12px;">
        {("✅ IA activée (OPENAI_API_KEY détectée)" if OPENAI_API_KEY else "ℹ️ IA en mode fallback (ajoute OPENAI_API_KEY sur Render pour l’analyse IA avancée).")}
      </p>
    """
    return shell("SpendGuard", inner)

@app.post("/preview", response_class=HTMLResponse)
async def preview(
    file: UploadFile = File(...),
    company_name: str = Form(...),
    signature_name: str = Form(...),
    goal: str = Form(...),
    tone: str = Form("Pro"),
):
    doc_id = str(uuid.uuid4())
    safe_name = re.sub(r"[^a-zA-Z0-9._-]+", "_", file.filename or "invoice.pdf")
    path = os.path.join(DATA_DIR, f"{doc_id}_{safe_name}")

    content = await file.read()
    with open(path, "wb") as f:
        f.write(content)

    raw_parts: List[str] = []
    try:
        with pdfplumber.open(path) as pdf:
            for page in pdf.pages:
                raw_parts.append(page.extract_text() or "")
    except Exception:
        raise HTTPException(status_code=400, detail="Impossible de lire le PDF.")

    raw_text = "\n".join(raw_parts)

    vendor = normalize_vendor(detect_vendor(raw_text))
    currency = detect_currency(raw_text)
    total = float(extract_total_amount(raw_text))
    rate = 0.10 if total < 1000 else 0.15
    savings = round(min(total * rate, 2500), 2) if total > 0 else 0.0

    ai = await llm_analyze_invoice(
        text=raw_text,
        vendor=vendor,
        currency=currency,
        total=total,
        savings=savings,
        company=company_name,
        signer=signature_name,
        goal=goal,
    )

    # Score + projections (même si IA off)
    score = min(95, max(60, int((savings / (total + 1)) * 200)))
    annual = round(savings * 12, 2)
    three_year = round(savings * 36, 2)

    set_report(doc_id, {
        "company": company_name,
        "name": signature_name,
        "tone": tone,
        "goal": goal,
        "vendor": vendor,
        "currency": currency,
        "total": total,
        "savings": savings,
        "annual": annual,
        "three_year": three_year,
        "score": score,
        "filename": safe_name,
        "ai": ai,
        "created_at": int(time.time()),
    })

    inner = f"""
      <h1>Aperçu</h1>
      <p class="subtitle">Ton audit est prêt. Débloque la version complète (audit détaillé + email + export PDF).</p>

      <div class="grid">
        <div>
          <div class="kpi">
            <div class="label">Fournisseur</div>
            <div class="value">{vendor}</div>
          </div>

          <div class="kpi">
            <div class="label">Montant détecté</div>
            <div class="value">{total:.2f} {currency}</div>
          </div>

          <div class="kpi">
            <div class="label">Économie estimée</div>
            <div class="value green">{savings:.2f} {currency}</div>
          </div>

          <div class="kpi">
            <div class="label">Score d’optimisation</div>
            <div class="value">{score}/100</div>
          </div>

          <a class="btn" href="/pay/{doc_id}">Débloquer le rapport complet (9€)</a>

          <p class="muted" style="margin-top:10px;">doc_id : <strong>{doc_id}</strong></p>
        </div>

        <div>
          <div class="kpi">
            <div class="label">Ce que tu obtiens</div>
            <pre>✅ Audit IA (points clés + opportunités)
✅ Email adapté à ton objectif
✅ Bouton “Copier”
✅ Export PDF propre</pre>
          </div>
        </div>
      </div>

      <p style="margin-top:18px;"><a class="link" href="/">← Nouvelle analyse</a></p>
    """
    return shell("Aperçu", inner)

@app.get("/pay/{doc_id}", response_class=HTMLResponse)
def pay(doc_id: str):
    data = get_report(doc_id)
    if not data:
        return shell("Erreur", "<h1>Rapport introuvable</h1><p class='muted'>Refais l’aperçu.</p>")

    vendor = normalize_vendor(data.get("vendor", "UNKNOWN"))
    currency = data.get("currency", "EUR")
    total = float(data.get("total") or 0)
    savings = float(data.get("savings") or 0)

    inner = f"""
      <h1>Paiement</h1>
      <p class="subtitle">Débloque le rapport complet. Montant : <b>9€</b>.</p>

      <div class="grid">
        <div>
          <div class="kpi">
            <div class="label">Résumé</div>
            <div class="value">{vendor}</div>
            <div class="muted" style="margin-top:6px;">
              Montant détecté : <b>{total:.2f} {currency}</b><br/>
              Économie estimée : <b class="green">{savings:.2f} {currency}</b>
            </div>
          </div>

          <div class="kpi" style="background:rgba(34,197,94,0.10);border:1px solid rgba(34,197,94,0.25);">
            <div class="label">Projection annuelle (si mensuel)</div>
            <div class="value green">{(savings*12):.2f} {currency}</div>
          </div>

          <div class="kpi">
            <div class="label">Conseil</div>
            <pre>🎯 Objectif : {goal_label(data.get("goal","reduce"))}
🧠 Audit + email adapté
⏱️ Temps : 2 minutes</pre>
          </div>

          <p style="margin-top:18px;"><a class="link" href="/">← Retour</a></p>
        </div>

        <div>
          {render_stripe_checkout(doc_id)}
        </div>
      </div>
    """
    return shell("Paiement", inner)

class PayReq(BaseModel):
    doc_id: str

@app.post("/create-payment-intent")
def create_payment_intent(req: PayReq):
    if not get_report(req.doc_id):
        raise HTTPException(status_code=404, detail="doc_id introuvable")

    if not STRIPE_SECRET_KEY or not STRIPE_PUBLISHABLE_KEY:
        raise HTTPException(status_code=500, detail="Stripe non configuré (variables manquantes)")

    intent = stripe.PaymentIntent.create(
        amount=PRICE_CENTS,
        currency=CURRENCY,
        automatic_payment_methods={"enabled": True},
        metadata={"doc_id": req.doc_id},
        description=PRODUCT_NAME,
    )
    return JSONResponse({"client_secret": intent.client_secret})

@app.get("/success/{doc_id}", response_class=HTMLResponse)
def success(request: Request, doc_id: str):
    # Vérif token signé
    t = request.query_params.get("t")
    if not check_sig(doc_id, t):
        return shell("Lien invalide", "<h1>Lien invalide</h1><p class='muted'>Reviens via le lien Stripe après paiement.</p>")

    # Stripe renvoie payment_intent dans l’URL de retour
    pi_id = request.query_params.get("payment_intent")
    if not pi_id:
        return shell("Erreur", "<h1>Paiement non confirmé</h1><p class='muted'>Paramètre payment_intent manquant.</p>")

    try:
        pi = stripe.PaymentIntent.retrieve(pi_id)
        if pi.status == "succeeded":
            mark_paid(doc_id, payment_intent=pi_id)
            return RedirectResponse(f"/full/{doc_id}?t={t}", status_code=303)
        return shell("Paiement", f"<h1>Paiement incomplet</h1><p class='muted'>Statut : {pi.status}</p><a class='btn' href='/pay/{doc_id}'>Réessayer</a>")
    except Exception:
        return shell("Erreur", "<h1>Erreur Stripe</h1><p class='muted'>Impossible de vérifier le paiement.</p>")

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
            secret=STRIPE_WEBHOOK_SECRET
        )
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid payload")
    except stripe.error.SignatureVerificationError:
        raise HTTPException(status_code=400, detail="Invalid signature")

    event_type = event.get("type", "")
    obj = event["data"]["object"]

    if event_type == "payment_intent.succeeded":
        doc_id = (obj.get("metadata") or {}).get("doc_id")
        if doc_id:
            mark_paid(doc_id, payment_intent=obj.get("id"))

    return {"received": True}

@app.get("/full/{doc_id}", response_class=HTMLResponse)
def full(request: Request, doc_id: str):
    data = get_report(doc_id)
    if not data:
        return shell("Erreur", "<h1>Rapport introuvable</h1><p class='muted'>Refais l’aperçu.</p>")

    t = request.query_params.get("t")
    if not check_sig(doc_id, t):
        return shell("Lien invalide", "<h1>Lien invalide</h1><p class='muted'>Accès via paiement requis.</p>")

    if not is_paid(doc_id):
        return shell(
            "Accès verrouillé",
            f"<h1>Accès verrouillé</h1><p class='muted'>Paiement requis.</p><a class='btn' href='/pay/{doc_id}'>Payer 9€</a>",
        )

    vendor = normalize_vendor(data.get("vendor", "UNKNOWN"))
    currency = data.get("currency", "EUR")
    total = float(data.get("total") or 0)
    savings = float(data.get("savings") or 0)
    annual = float(data.get("annual") or round(savings * 12, 2))
    three_year = float(data.get("three_year") or round(savings * 36, 2))
    score = int(data.get("score") or 70)

    ai = data.get("ai") or {}
    ai_active = bool(ai.get("ai_active"))
    confidence = float(ai.get("confidence") or 0.0)
    category = ai.get("category") or "unknown"
    bullets = ai.get("bullets") or []
    opportunities = ai.get("opportunities") or []

    subject = ai.get("email_subject") or f"Demande d’optimisation tarifaire – {data['company']}"
    body = ai.get("email_body") or f"""Bonjour,

Nous utilisons {vendor}. Avant renouvellement, nous souhaitons discuter d’un ajustement tarifaire.

Cordialement,
{data['name']}"""

    email_text = f"Sujet: {subject}\n\n{body}"
    email_text_js = json.dumps(email_text)

    bullets_html = ""
    if bullets:
        bullets_html = "<ul>" + "".join([f"<li>{b}</li>" for b in bullets]) + "</ul>"
    else:
        bullets_html = "<p class='muted'>Aucun point IA disponible.</p>"

    opps_html = ""
    if opportunities:
        opps_html += "<ul>"
        for o in opportunities[:6]:
            title = o.get("title","")
            detail = o.get("detail","")
            impact = o.get("impact","")
            opps_html += f"<li><b>{title}</b><br/><span class='muted'>{detail}</span><br/><span class='muted'>Impact : {impact}</span></li>"
        opps_html += "</ul>"
    else:
        opps_html = "<p class='muted'>Aucune opportunité détectée.</p>"

    inner = f"""
      <h1>Rapport complet</h1>
      <p class="subtitle">Audit IA + email prêt à envoyer + export PDF.</p>

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
            <div class="muted" style="margin-top:6px;">(si cette dépense est mensuelle)</div>
          </div>

          <div class="kpi" style="background:rgba(34,197,94,0.08);border:1px solid rgba(34,197,94,0.18);">
            <div class="label">Projection 3 ans</div>
            <div class="value green">{three_year:.2f} {currency}</div>
          </div>

          <div class="kpi">
            <div class="label">Score d’optimisation</div>
            <div class="value">{score}/100</div>
          </div>

          <div class="kpi">
            <div class="label">Analyse IA</div>
            <div class="badge" style="margin-bottom:10px;">
              <b>{'IA active' if ai_active else 'IA fallback'}</b> — Confiance: <b>{confidence:.2f}</b> — Catégorie: <b>{category}</b>
            </div>
            {bullets_html}
          </div>

          <div class="kpi">
            <div class="label">Opportunités détectées</div>
            {opps_html}
          </div>

          <div class="kpi">
            <div class="label">Checklist</div>
            <pre>✅ Envoyer l’email
✅ Demander remise / annualisation / downgrade
✅ Vérifier licences & options inutilisées
✅ Demander SLA / support / modalités contractuelles</pre>
          </div>

          <div class="row-actions">
            <button class="btn btn-secondary" id="copyBtn">Copier l’email</button>
            <a class="btn" href="/print/{doc_id}?t={t}" target="_blank">Télécharger PDF</a>
          </div>

          <p class="muted" id="copyMsg" style="margin-top:10px;"></p>
          <p style="margin-top:18px;"><a class="link" href="/">← Nouvelle analyse</a></p>
        </div>

        <div>
          <div class="kpi">
            <div class="label">Email prêt</div>
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
            msg.textContent = "⚠️ Copie automatique refusée. Sélectionne le texte et copie manuellement.";
          }}
        }});
      </script>
    """
    return shell("Rapport complet", inner, wide=True)

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

    vendor = normalize_vendor(data.get("vendor", "UNKNOWN"))
    currency = data.get("currency", "EUR")
    total = float(data.get("total") or 0)
    savings = float(data.get("savings") or 0)
    annual = float(data.get("annual") or round(savings * 12, 2))
    three_year = float(data.get("three_year") or round(savings * 36, 2))
    score = int(data.get("score") or 70)

    ai = data.get("ai") or {}
    subject = ai.get("email_subject") or f"Demande d’optimisation tarifaire – {data['company']}"
    body = ai.get("email_body") or f"""Bonjour,

Nous utilisons {vendor}. Avant renouvellement, nous souhaitons discuter d’un ajustement tarifaire.

Cordialement,
{data['name']}"""

    bullets = ai.get("bullets") or []
    opportunities = ai.get("opportunities") or []

    bullets_html = ""
    if bullets:
        bullets_html = "<ul>" + "".join([f"<li>{b}</li>" for b in bullets]) + "</ul>"
    opps_html = ""
    if opportunities:
        opps_html = "<ul>" + "".join([f"<li><b>{o.get('title','')}</b> — {o.get('detail','')}<br/><i>Impact : {o.get('impact','')}</i></li>" for o in opportunities[:6]]) + "</ul>"

    return f"""
    <html>
    <head>
      <meta charset="utf-8"/>
      <title>SpendGuard – Rapport</title>
      <style>
        body {{
          font-family: Arial, sans-serif;
          margin: 36px;
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
        .kpi.good {{
          border:1px solid #86efac;
          background:#f0fdf4;
        }}
        .label {{ color:#6b7280; font-size:12px; }}
        .value {{ font-size:18px; font-weight:700; margin-top:6px; }}
        .green {{ color:#16a34a; }}
        ul {{ margin: 8px 0 0 18px; }}
        li {{ margin: 6px 0; }}
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
          <div class="label">Économie estimée</div>
          <div class="value green">{savings:.2f} {currency}</div>
        </div>
        <div class="kpi good">
          <div class="label">Projection annuelle</div>
          <div class="value green">{annual:.2f} {currency}</div>
          <div class="label" style="margin-top:6px;">(si dépense mensuelle)</div>
        </div>
        <div class="kpi">
          <div class="label">Projection 3 ans</div>
          <div class="value green">{three_year:.2f} {currency}</div>
        </div>
        <div class="kpi">
          <div class="label">Fournisseur</div>
          <div class="value">{vendor}</div>
        </div>
        <div class="kpi">
          <div class="label">Score d’optimisation</div>
          <div class="value">{score}/100</div>
        </div>
      </div>

      <h2 style="margin-top:18px;">Analyse IA</h2>
      {bullets_html if bullets_html else "<p>Aucune analyse disponible.</p>"}

      <h2 style="margin-top:18px;">Opportunités</h2>
      {opps_html if opps_html else "<p>Aucune opportunité disponible.</p>"}

      <h2 style="margin-top:22px;">Email prêt à envoyer</h2>
      <div class="box">Sujet: {subject}

{body}</div>
    </body>
    </html>
    """


# Optional demo pages (if you have templates/)
@app.get("/pricing", response_class=HTMLResponse)
def pricing():
    try:
        with open("templates/pricing.html", "r", encoding="utf-8") as f:
            return f.read()
    except FileNotFoundError:
        return "<h1>pricing.html manquant</h1>"

@app.get("/example", response_class=HTMLResponse)
def example():
    try:
        with open("templates/example.html", "r", encoding="utf-8") as f:
            return f.read()
    except FileNotFoundError:
        return "<h1>example.html manquant</h1>"