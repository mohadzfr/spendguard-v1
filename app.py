from fastapi import FastAPI, UploadFile, File, Form, HTTPException, Request
from fastapi.responses import HTMLResponse, JSONResponse
from pydantic import BaseModel
from typing import Dict, Any, Optional
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


# ================= CONFIG =================
load_dotenv()  # lit .env en local (ne JAMAIS push)

STRIPE_SECRET_KEY = os.getenv("STRIPE_SECRET_KEY", "")
STRIPE_PUBLISHABLE_KEY = os.getenv("STRIPE_PUBLISHABLE_KEY", "")
STRIPE_WEBHOOK_SECRET = os.getenv("STRIPE_WEBHOOK_SECRET", "")
APP_SECRET = os.getenv("APP_SECRET", "change-me-please")

PRICE_CENTS = int(os.getenv("PRICE_CENTS", "900"))  # 9€ par défaut
CURRENCY = os.getenv("CURRENCY", "eur")

if not STRIPE_SECRET_KEY or not STRIPE_PUBLISHABLE_KEY or not STRIPE_WEBHOOK_SECRET:
    print("⚠️ Variables Stripe manquantes. Vérifie .env (local) ou Render env vars (prod).")

stripe.api_key = STRIPE_SECRET_KEY

app = FastAPI(title="SpendGuard AI", version="1.0.0")

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


# ================= PERSISTENCE (STATE.JSON) =================
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
        # migration douce
        if "paid" in data and isinstance(data["paid"], list):
            data["paid"] = {doc_id: {"ts": int(time.time()), "payment_intent": ""} for doc_id in data["paid"]}
        if "paid" not in data or not isinstance(data["paid"], dict):
            data["paid"] = {}
        if "reports" not in data or not isinstance(data["reports"], dict):
            data["reports"] = {}
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


# ================= STRIPE: PAID CHECK (fallback) =================
def is_paid(doc_id: str) -> bool:
    # 1) local state d’abord (rapide)
    if is_paid_local(doc_id):
        return True

    # 2) fallback Stripe (utile si state reset / webhook en retard)
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
        .white-panel {{
          background: #ffffff;
          color: #0b1020;
          border-radius: 18px;
          padding: 18px;
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


# ================= LANDING =================
@app.get("/", response_class=HTMLResponse)
def home():
    inner = f"""
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

      <p class="muted" style="margin-top:12px;">Rapport complet : <strong>{PRICE_CENTS/100:.0f}€</strong> (paiement sécurisé Stripe).</p>
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

    # Estimation “business”
    rate = 0.10 if total < 1000 else 0.15
    savings = round(min(total * rate, 2500), 2) if total > 0 else 0.0

    set_report(doc_id, {
        "company": company_name,
        "name": signature_name,
        "tone": tone,
        "vendor": vendor,
        "currency": currency,
        "total": total,
        "savings": savings,
        "filename": file.filename,
        "created_ts": int(time.time()),
    })

    t = sign_doc(doc_id)

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

          <a class="btn" href="/pay/{doc_id}?t={t}">Débloquer le rapport complet ({PRICE_CENTS/100:.0f}€)</a>
          <p class="muted" style="margin-top:10px;">ID : <strong>{doc_id}</strong></p>
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


# ================= PAIEMENT PAGE =================
def render_payment_element(doc_id: str, t: str) -> str:
    # Payment Element: create-payment-intent -> confirmPayment -> return_url /success/{doc_id}?t=...
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
        return shell("Lien invalide", "<h1>Lien invalide</h1><p class='muted'>Reviens depuis l’aperçu.</p><a class='btn' href='/'>Retour</a>")

    data = get_report(doc_id)
    if not data:
        return shell("Erreur", "<h1>Rapport introuvable</h1><p class='muted'>Refais l’aperçu.</p><a class='btn' href='/'>Retour</a>")

    # déjà payé ?
    if is_paid(doc_id):
        return JSONResponse({"ok": True, "redirect": f"/full/{doc_id}?t={t}"})

    vendor = normalize_vendor(data.get("vendor"))
    currency = data.get("currency", "EUR")
    total = float(data.get("total") or 0)
    savings = float(data.get("savings") or 0)
    annual = round(savings * 12, 2)

    inner = f"""
      <h1>Paiement</h1>
      <p class="subtitle">Débloque le rapport complet. Montant : <strong>{PRICE_CENTS/100:.0f}€</strong>.</p>

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
            <div class="muted" style="margin-top:8px;">Montant détecté : <b>{total:.2f} {currency}</b></div>
            <div class="muted">Économie estimée : <b class="green">{savings:.2f} {currency}</b></div>
          </div>

          <div class="kpi" style="background:rgba(34,197,94,0.10);border:1px solid rgba(34,197,94,0.25);">
            <div class="label">Projection annuelle</div>
            <div class="value green">{annual:.2f} {currency}</div>
            <div class="muted" style="margin-top:6px;">(si cette dépense est mensuelle)</div>
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
          {render_payment_element(doc_id, t)}
        </div>
      </div>
    """
    return shell("Paiement", inner)


# ================= CREATE PAYMENT INTENT =================
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


# ================= SUCCESS (RETURN_URL) =================
@app.get("/success/{doc_id}", response_class=HTMLResponse)
def success(request: Request, doc_id: str):
    t = request.query_params.get("t")
    if not check_sig(doc_id, t):
        return shell("Lien invalide", "<h1>Lien invalide</h1><p class='muted'>Token manquant.</p><a class='btn' href='/'>Retour</a>")

    # Stripe redirige avec payment_intent dans l’URL (souvent), on peut l’utiliser pour marquer paid immédiatement
    pi_id = request.query_params.get("payment_intent")
    if pi_id:
        try:
            pi = stripe.PaymentIntent.retrieve(pi_id)
            if pi.status == "succeeded":
                mark_paid(doc_id, payment_intent=pi.id)
        except Exception:
            pass

    # si webhook a déjà mark_paid, ou fallback Stripe:
    if not is_paid(doc_id):
        inner = f"""
          <h1>Paiement en cours de confirmation</h1>
          <p class="subtitle">Si tu viens de payer, attends 2–5 secondes puis clique sur le bouton.</p>
          <a class="btn" href="/full/{doc_id}?t={t}">Accéder au rapport</a>
          <p class="muted" style="margin-top:10px;">Si ça bloque, reviens sur la page paiement.</p>
          <a class="btn btn-secondary" href="/pay/{doc_id}?t={t}">Retour paiement</a>
        """
        return shell("Confirmation", inner)

    inner = f"""
      <h1>Paiement confirmé ✅</h1>
      <p class="subtitle">Ton rapport complet est débloqué.</p>
      <a class="btn" href="/full/{doc_id}?t={t}">Voir le rapport complet</a>
    """
    return shell("Succès", inner)


# ================= WEBHOOK STRIPE =================
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
            mark_paid(doc_id, payment_intent=obj.get("id", ""))

    return {"received": True}


# ================= RAPPORT COMPLET =================
@app.get("/full/{doc_id}", response_class=HTMLResponse)
def full(request: Request, doc_id: str):
    t = request.query_params.get("t")
    if not check_sig(doc_id, t):
        return shell("Lien invalide", "<h1>Lien invalide</h1><p class='muted'>Reviens via le lien après paiement.</p><a class='btn' href='/'>Retour</a>")

    data = get_report(doc_id)
    if not data:
        return shell("Erreur", "<h1>Rapport introuvable</h1><p class='muted'>Refais l’aperçu.</p><a class='btn' href='/'>Retour</a>")

    if not is_paid(doc_id):
        return shell(
            "Accès verrouillé",
            f"<h1>Accès verrouillé</h1><p class='muted'>Paiement requis.</p><a class='btn' href='/pay/{doc_id}?t={t}'>Payer</a>",
        )

    vendor = normalize_vendor(data.get("vendor"))
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


# ================= PRINT / PDF VIEW =================
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


# ================= HEALTH =================
@app.get("/health")
def health():
    return {"status": "running"}