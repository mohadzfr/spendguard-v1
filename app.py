from __future__ import annotations

import os
import re
import json
import uuid
import time
import hmac
import hashlib
from typing import Dict, Any, Optional

import stripe
import pdfplumber
from dotenv import load_dotenv
from pydantic import BaseModel

from fastapi import FastAPI, UploadFile, File, Form, HTTPException, Request
from fastapi.responses import HTMLResponse, JSONResponse

# ================= CONFIG =================
load_dotenv()  # lit le fichier .env en local (Render = variables d'env)

STRIPE_SECRET_KEY = os.getenv("STRIPE_SECRET_KEY", "")
STRIPE_PUBLISHABLE_KEY = os.getenv("STRIPE_PUBLISHABLE_KEY", "")
STRIPE_WEBHOOK_SECRET = os.getenv("STRIPE_WEBHOOK_SECRET", "")

APP_SECRET = os.getenv("APP_SECRET", "change-me-please")  # important: change en prod
PRICE_CENTS = int(os.getenv("PRICE_CENTS", "900"))
CURRENCY = os.getenv("CURRENCY", "eur")

DATA_DIR = os.getenv("DATA_DIR", "./data")
os.makedirs(DATA_DIR, exist_ok=True)
STATE_PATH = os.path.join(DATA_DIR, "state.json")

if not STRIPE_SECRET_KEY or not STRIPE_PUBLISHABLE_KEY or not STRIPE_WEBHOOK_SECRET:
    print("⚠️ Variables Stripe manquantes. Vérifie .env (local) ou variables Render (prod).")

stripe.api_key = STRIPE_SECRET_KEY

app = FastAPI(title="SpendGuard AI", version="0.1.0")


# ================= SIGNATURE LIEN (token t) =================
def sign_doc(doc_id: str) -> str:
    msg = doc_id.encode("utf-8")
    key = APP_SECRET.encode("utf-8")
    return hmac.new(key, msg, hashlib.sha256).hexdigest()[:16]


def check_sig(doc_id: str, t: Optional[str]) -> bool:
    if not t:
        return False
    return hmac.compare_digest(sign_doc(doc_id), t)


# ================= PERSISTENCE DISQUE =================
def _default_state() -> Dict[str, Any]:
    return {"reports": {}, "paid": []}  # paid optionnel, on garde pour UX


def load_state() -> Dict[str, Any]:
    if not os.path.exists(STATE_PATH):
        s = _default_state()
        save_state(s)
        return s
    try:
        with open(STATE_PATH, "r", encoding="utf-8") as f:
            return json.load(f)
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
    return state.get("reports", {}).get(doc_id)


def set_report(doc_id: str, data: Dict[str, Any]) -> None:
    state = load_state()
    state.setdefault("reports", {})[doc_id] = data
    save_state(state)


def mark_paid(doc_id: str) -> None:
    state = load_state()
    state.setdefault("paid", [])
    if doc_id not in state["paid"]:
        state["paid"].append(doc_id)
        save_state(state)


# ================= STRIPE: check paiement (source: API Stripe) =================
def is_paid(doc_id: str) -> bool:
    """
    Robust: vérifie sur Stripe dans les 7 derniers jours si un PaymentIntent succeeded
    avec metadata.doc_id == doc_id
    """
    if not STRIPE_SECRET_KEY:
        return False
    try:
        seven_days_ago = int(time.time()) - 7 * 24 * 3600
        starting_after = None

        while True:
            params: Dict[str, Any] = {"limit": 100, "created": {"gte": seven_days_ago}}
            if starting_after:
                params["starting_after"] = starting_after

            intents = stripe.PaymentIntent.list(**params)

            for pi in intents.data:
                md = pi.metadata or {}
                if md.get("doc_id") == doc_id and pi.status == "succeeded":
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
    # parfois écrit
    low = text.lower()
    if " eur" in low or " euro" in low:
        return "EUR"
    if " usd" in low:
        return "USD"
    if " gbp" in low:
        return "GBP"
    return "UNKNOWN"


def normalize_vendor(v: str) -> str:
    v = (v or "UNKNOWN").strip()
    v = v.replace("Ia", "IA").replace("Aws", "AWS").replace("Hubspot", "HubSpot")
    # petits nettoyages
    v = re.sub(r"\s{2,}", " ", v)
    return v


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
        m = re.search(p, text, re.IGNORECASE)
        if m:
            cand = m.group(m.lastindex).strip()
            cand = cand.split("\n")[0].strip()
            if 3 <= len(cand) <= 80:
                return normalize_vendor(cand)

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


# ================= UI SHELL =================
def shell(title: str, inner: str) -> str:
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
          padding:48px 16px;
        }}
        .container {{ width:100%; max-width: 980px; }}
        .topbar {{ display:flex; align-items:center; justify-content:space-between; margin-bottom:18px; }}
        .logo {{ font-weight:900; letter-spacing:-0.6px; font-size:18px; }}
        .pill {{
          font-size:12px; color:#0b1020; background: rgba(34,197,94,0.95);
          padding:6px 10px; border-radius: 999px; font-weight:800;
        }}
        .card {{
          background: var(--card);
          border:1px solid var(--border);
          border-radius: 22px;
          box-shadow: var(--shadow);
          padding: 28px;
        }}
        .grid {{ display:grid; grid-template-columns: 1.1fr 0.9fr; gap:18px; }}
        @media (max-width: 900px) {{ .grid {{ grid-template-columns: 1fr; }} }}
        h1 {{ margin: 0 0 8px 0; font-size: 28px; letter-spacing:-0.7px; }}
        .subtitle {{ margin:0 0 18px 0; color: var(--muted); font-size:14px; line-height:1.4; }}
        .stepper {{ display:flex; gap:10px; margin: 14px 0 18px 0; flex-wrap:wrap; }}
        .step {{
          border:1px solid var(--border);
          background: rgba(255,255,255,0.04);
          padding:10px 12px;
          border-radius: 14px;
          font-size: 13px;
          color: var(--muted);
        }}
        .step strong {{ color: var(--text); }}
        input, select {{
          width:100%;
          padding:12px 12px;
          margin:10px 0;
          border-radius:12px;
          border:1px solid var(--border);
          background: rgba(255,255,255,0.07);
          color: var(--text);
          outline:none;
        }}
        .btn {{
          display:inline-block;
          width:100%;
          padding:14px;
          border-radius: 14px;
          border:none;
          background: linear-gradient(90deg, var(--brand1), var(--brand2));
          color:white;
          font-weight:900;
          cursor:pointer;
          text-align:center;
          text-decoration:none;
          transition:0.2s;
          margin-top:10px;
        }}
        .btn:hover {{ transform: translateY(-2px); box-shadow: 0 12px 28px rgba(99,102,241,0.35); }}
        .btn-secondary {{
          background: rgba(255,255,255,0.08);
          border: 1px solid var(--border);
        }}
        .muted {{ color: var(--muted); font-size: 13px; }}
        .kpi {{
          border:1px solid var(--border);
          background: rgba(255,255,255,0.04);
          border-radius: 18px;
          padding: 16px;
          margin-top: 10px;
        }}
        .kpi .label {{ color: var(--muted); font-size: 12px; margin-bottom: 6px; }}
        .kpi .value {{ font-size: 22px; font-weight: 900; letter-spacing:-0.5px; }}
        .green {{ color: var(--green); }}
        .white-panel {{
          background: #ffffff;
          color: #0b1020;
          border-radius: 18px;
          padding: 16px;
        }}
        pre {{
          background: rgba(255,255,255,0.08);
          padding: 16px;
          border-radius: 14px;
          white-space: pre-wrap;
          border: 1px solid var(--border);
          margin:0;
        }}
        .link {{ color: #93c5fd; text-decoration: none; font-weight: 800; }}
        .row-actions {{
          display:flex;
          gap:10px;
          flex-wrap:wrap;
          margin-top:12px;
        }}
        .row-actions .btn {{
          width:auto;
          flex: 1;
          min-width: 220px;
        }}
      </style>
    </head>
    <body>
      <div class="container">
        <div class="topbar">
          <div class="logo">SpendGuard</div>
          <div class="pill">AI SaaS Optimizer</div>
        </div>
        <div class="card">
          {inner}
        </div>
      </div>
    </body>
    </html>
    """


# ================= STRIPE ELEMENTS (Payment Element) =================
def render_stripe_checkout(doc_id: str) -> str:
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


# ================= LANDING =================
@app.get("/", response_class=HTMLResponse)
def home():
    inner = """
      <h1>Optimise tes abonnements SaaS</h1>
      <p class="subtitle">Upload une facture PDF. On détecte le montant, le fournisseur, et on génère un email de négociation prêt à envoyer.</p>

      <div class="stepper">
        <div class="step"><strong>1.</strong> Aperçu</div>
        <div class="step"><strong>2.</strong> Paiement</div>
        <div class="step"><strong>3.</strong> Rapport complet</div>
      </div>

      <form action="/preview" method="post" enctype="multipart/form-data">
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

      <p class="muted" style="margin-top:12px;">Rapport complet : <strong>9€</strong> (paiement sécurisé).</p>
    """
    return shell("SpendGuard", inner)


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

    vendor = normalize_vendor(detect_vendor(raw_text))
    currency = detect_currency(raw_text)
    total = extract_total_amount(raw_text)

    rate = 0.10 if total < 1000 else 0.15
    savings = round(min(total * rate, 2500), 2) if total > 0 else 0.0

    set_report(
        doc_id,
        {
            "company": company_name,
            "name": signature_name,
            "tone": tone,
            "vendor": vendor,
            "currency": currency,
            "total": total,
            "savings": savings,
            "filename": file.filename,
        },
    )

    inner = f"""
      <h1>Aperçu</h1>
      <p class="subtitle">Ton rapport est prêt. Débloque la version complète (email + check-list + export PDF).</p>

      <div class="grid">
        <div>
          <div class="kpi">
            <div class="label">Montant détecté</div>
            <div class="value">{total:.2f} {currency}</div>
          </div>

          <div class="kpi">
            <div class="label">Économie estimée</div>
            <div class="value green">{savings:.2f} {currency}</div>
          </div>

          <div class="kpi">
            <div class="label">Fournisseur détecté</div>
            <div class="value">{vendor}</div>
          </div>

          <a class="btn" href="/pay/{doc_id}">Débloquer le rapport complet (9€)</a>
          <p class="muted" style="margin-top:10px;">doc_id : <strong>{doc_id}</strong></p>
        </div>

        <div>
          <div class="kpi">
            <div class="label">Ce que tu obtiens</div>
            <pre>✅ Email prêt à envoyer
✅ Bouton “Copier”
✅ Export PDF propre
✅ Checklist d’optimisation</pre>
          </div>
        </div>
      </div>

      <p style="margin-top:18px;"><a class="link" href="/">← Nouvelle analyse</a></p>
    """
    return shell("Aperçu", inner)


# ================= PAY PAGE (IMPORTANT) =================
@app.get("/pay/{doc_id}", response_class=HTMLResponse)
def pay(doc_id: str):
    data = get_report(doc_id)
    if not data:
        return shell("Erreur", "<h1>Rapport introuvable</h1><p class='muted'>Refais l’aperçu.</p>")

    currency = data.get("currency", "EUR")
    total = float(data.get("total") or 0)
    savings = float(data.get("savings") or 0)
    vendor = normalize_vendor(data.get("vendor") or "UNKNOWN")
    annual = round(savings * 12, 2)

    inner = f"""
      <h1>Paiement</h1>
      <p class="subtitle">Débloque le rapport complet. Montant : <strong>9€</strong>.</p>

      <div class="stepper">
        <div class="step"><strong>1.</strong> Aperçu ✅</div>
        <div class="step"><strong>2.</strong> Paiement</div>
        <div class="step"><strong>3.</strong> Rapport complet</div>
      </div>

      <div class="grid">
        <div>
          <div class="kpi">
            <div class="label">Résumé</div>
            <div class="value">{vendor}</div>
            <div class="muted" style="margin-top:8px;">
              Montant détecté : <b>{total:.2f} {currency}</b><br/>
              Économie estimée : <b class="green">{savings:.2f} {currency}</b>
            </div>
          </div>

          <div class="kpi" style="background:rgba(34,197,94,0.10);border:1px solid rgba(34,197,94,0.25);">
            <div class="label">Projection annuelle</div>
            <div class="value green">{annual:.2f} {currency}</div>
            <div class="muted" style="margin-top:6px;">(si dépense mensuelle)</div>
          </div>

          <div class="kpi">
            <div class="label">Conseil</div>
            <pre>🎯 Objectif : obtenir une remise
📌 Demande : annualisation + downgrade + licences inutilisées
⏱ Temps : 2 minutes</pre>
          </div>

          <p style="margin-top:18px;"><a class="link" href="/">← Retour</a></p>
        </div>

        <div>
          <div class="white-panel">
            {render_stripe_checkout(doc_id)}
          </div>
        </div>
      </div>
    """
    return shell("Paiement", inner)


# ================= CREATE PAYMENT INTENT =================
class PayReq(BaseModel):
    doc_id: str


@app.post("/create-payment-intent")
def create_payment_intent(req: PayReq):
    if not get_report(req.doc_id):
        raise HTTPException(status_code=404, detail="doc_id introuvable")

    if not STRIPE_SECRET_KEY:
        raise HTTPException(status_code=500, detail="Stripe non configuré (STRIPE_SECRET_KEY manquant)")

    intent = stripe.PaymentIntent.create(
        amount=PRICE_CENTS,
        currency=CURRENCY,
        automatic_payment_methods={"enabled": True},
        metadata={"doc_id": req.doc_id},
    )
    return JSONResponse({"client_secret": intent.client_secret})


# ================= SUCCESS (return_url Stripe) =================
@app.get("/success/{doc_id}", response_class=HTMLResponse)
def success(request: Request, doc_id: str):
    t = request.query_params.get("t")
    if not check_sig(doc_id, t):
        return shell("Erreur", "<h1>Lien invalide</h1><p class='muted'>Token manquant ou incorrect.</p>")

    # webhook peut prendre 1-2s => on refresh
    if not is_paid(doc_id):
        inner = f"""
          <h1>⏳ Paiement en cours de validation</h1>
          <p class="subtitle">Ne ferme pas la page. Redirection automatique…</p>
          <script>
            setTimeout(()=>{{ window.location.reload(); }}, 1200);
          </script>
        """
        return shell("Validation", inner)

    mark_paid(doc_id)

    inner = f"""
      <h1>✅ Paiement confirmé</h1>
      <p class="subtitle">Ton rapport complet est prêt.</p>
      <a class="btn" href="/full/{doc_id}?t={t}">Ouvrir le rapport</a>
      <p class="muted" style="margin-top:12px;">Redirection automatique…</p>
      <script>
        setTimeout(()=>{{ window.location.href="/full/{doc_id}?t={t}"; }}, 900);
      </script>
    """
    return shell("Succès", inner)


# ================= FULL REPORT =================
@app.get("/full/{doc_id}", response_class=HTMLResponse)
def full(request: Request, doc_id: str):
    data = get_report(doc_id)
    if not data:
        return shell("Erreur", "<h1>Rapport introuvable</h1><p class='muted'>Refais l’aperçu.</p>")

    t = request.query_params.get("t")
    if not check_sig(doc_id, t):
        return shell("Lien invalide", "<h1>Lien invalide</h1><p class='muted'>Reviens via le lien après paiement.</p>")

    if not is_paid(doc_id):
        return shell(
            "Accès verrouillé",
            f"<h1>Accès verrouillé</h1><p class='muted'>Paiement requis.</p><a class='btn' href='/pay/{doc_id}'>Payer 9€</a>",
        )

    vendor = normalize_vendor(data.get("vendor") or "UNKNOWN")
    currency = data.get("currency", "EUR")
    total = float(data.get("total") or 0)
    savings = float(data.get("savings") or 0)
    annual = round(savings * 12, 2)

    subject = f"Demande d’amélioration tarifaire - {data['company']}"
    body = f"""Bonjour,

Nous utilisons {vendor}. Avant renouvellement, nous souhaitons discuter d’un ajustement tarifaire.
Avez-vous une remise annuelle, une offre fidélité, ou un plan plus adapté ?

Cordialement,
{data['name']}"""

    email_text = f"Sujet: {subject}\n\n{body}"
    email_text_js = json.dumps(email_text)

    inner = f"""
      <h1>Rapport complet</h1>
      <p style="opacity:0.7;font-size:14px;">Analyse IA basée sur optimisation SaaS B2B (benchmark 2026)</p>
      <p class="subtitle">Email prêt à envoyer + export PDF.</p>

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

          <div class="kpi">
            <div class="label">Fournisseur</div>
            <div class="value">{vendor}</div>
          </div>

          <div class="kpi">
            <div class="label">Checklist</div>
            <pre>✅ Envoyer l’email
✅ Demander remise annuelle / downgrade
✅ Vérifier licences inutilisées
✅ Revue mensuelle des abonnements</pre>
          </div>

          <div class="row-actions">
            <button class="btn btn-secondary" id="copyBtn">Copier l’email</button>
            <a class="btn" href="/print/{doc_id}?t={t}" target="_blank">Télécharger PDF</a>
          </div>

          <p class="muted" id="copyMsg" style="margin-top:10px;"></p>
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

      <p style="margin-top:18px;"><a class="link" href="/">← Nouvelle analyse</a></p>
    """
    return shell("Rapport complet", inner)


# ================= PRINT VIEW (PDF navigateur) =================
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

    vendor = normalize_vendor(data.get("vendor") or "UNKNOWN")
    currency = data.get("currency", "EUR")
    total = float(data.get("total") or 0)
    savings = float(data.get("savings") or 0)
    annual = round(savings * 12, 2)

    subject = f"Demande d’amélioration tarifaire - {data['company']}"
    body = f"""Bonjour,

Nous utilisons {vendor}. Avant renouvellement, nous souhaitons discuter d’un ajustement tarifaire.
Avez-vous une remise annuelle, une offre fidélité, ou un plan plus adapté ?

Cordialement,
{data['name']}"""

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
          <div class="label">Économie estimée</div>
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


# ================= STRIPE WEBHOOK =================
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

    event_type = event.get("type", "")
    obj = event["data"]["object"]

    if event_type == "payment_intent.succeeded":
        doc_id = (obj.get("metadata") or {}).get("doc_id")
        if doc_id:
            mark_paid(doc_id)

    return {"received": True}


# ================= HEALTH =================
@app.get("/health")
def health():
    return {"status": "running"}


# ================= PAGES OPTIONNELLES (templates) =================
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