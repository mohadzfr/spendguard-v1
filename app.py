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
from fastapi.responses import RedirectResponse


# ================= CONFIG =================
load_dotenv()

STRIPE_SECRET_KEY = os.getenv("STRIPE_SECRET_KEY", "")
STRIPE_PUBLISHABLE_KEY = os.getenv("STRIPE_PUBLISHABLE_KEY", "")
STRIPE_WEBHOOK_SECRET = os.getenv("STRIPE_WEBHOOK_SECRET", "")
APP_SECRET = os.getenv("APP_SECRET", "change-me-please")

PRICE_CENTS = int(os.getenv("PRICE_CENTS", "900"))
CURRENCY = os.getenv("CURRENCY", "eur")

if not STRIPE_SECRET_KEY or not STRIPE_PUBLISHABLE_KEY or not STRIPE_WEBHOOK_SECRET:
    print("⚠️ Variables Stripe manquantes. Vérifie .env (local) ou Render env vars (prod).")

stripe.api_key = STRIPE_SECRET_KEY

app = FastAPI(title="SpendGuard AI", version="1.1.0")

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


# ================= STATE.JSON =================
def _default_state() -> Dict[str, Any]:
    return {"reports": {}, "paid": {}}

def load_state() -> Dict[str, Any]:
    if not os.path.exists(STATE_PATH):
        s = _default_state()
        save_state(s)
        return s
    try:
        with open(STATE_PATH, "r", encoding="utf-8") as f:
            data = json.load(f)
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

def is_paid(doc_id: str) -> bool:
    if is_paid_local(doc_id):
        return True
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


# ================= UI SHELL (UX BOOST) =================
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
        .topbar {{
          display:flex; align-items:center; justify-content:space-between;
          margin-bottom:18px;
        }}
        .brand {{
          display:flex; align-items:center; gap:10px;
          font-weight:900; letter-spacing:-0.6px; font-size:18px;
        }}
        .dot {{
          width:10px; height:10px; border-radius:999px;
          background: linear-gradient(90deg, var(--brand1), var(--brand2));
          box-shadow: 0 10px 30px rgba(99,102,241,0.45);
        }}
        .pill {{
          font-size:12px; color:#0b1020; background: rgba(34,197,94,0.95);
          padding:6px 10px; border-radius: 999px; font-weight:900;
        }}

        .card {{
          background: var(--card);
          border:1px solid var(--border);
          border-radius: 22px;
          box-shadow: var(--shadow);
          padding: 26px;
        }}

        h1 {{ margin: 0 0 8px 0; font-size: 30px; letter-spacing:-0.8px; }}
        .subtitle {{ margin:0 0 18px 0; color: var(--muted); font-size:14px; line-height:1.45; }}

        .grid {{ display:grid; grid-template-columns: 1.1fr 0.9fr; gap:18px; }}
        @media (max-width: 920px) {{ .grid {{ grid-template-columns: 1fr; }} }}

        .hero {{
          display:grid;
          grid-template-columns: 1.3fr 0.7fr;
          gap:18px;
          align-items:start;
        }}
        @media (max-width: 920px) {{ .hero {{ grid-template-columns: 1fr; }} }}

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

        .muted {{ color: var(--muted); font-size: 13px; }}
        .row-actions {{
          display:flex; gap:10px; flex-wrap:wrap; margin-top:12px;
        }}
        .row-actions .btn {{
          width:auto; flex:1; min-width:220px;
        }}

        pre {{
          background: rgba(255,255,255,0.08);
          padding: 16px;
          border-radius: 14px;
          white-space: pre-wrap;
          border: 1px solid var(--border);
          margin:0;
        }}

        .link {{ color: #93c5fd; text-decoration: none; font-weight: 900; }}

        .badge {{
          display:inline-flex; align-items:center; gap:8px;
          padding:8px 10px;
          border:1px solid var(--border);
          border-radius:999px;
          background: rgba(255,255,255,0.04);
          color: var(--muted);
          font-size:12px;
          font-weight:900;
        }}
        .badge b {{ color: var(--text); }}

        .feature {{
          border:1px solid var(--border);
          background: rgba(255,255,255,0.03);
          border-radius: 18px;
          padding: 16px;
        }}
        .feature h3 {{ margin:0 0 6px 0; font-size: 15px; }}
        .feature p {{ margin:0; color: var(--muted); font-size: 13px; line-height:1.4; }}

        .faq {{
          border:1px solid var(--border);
          border-radius: 18px;
          padding: 14px 16px;
          background: rgba(255,255,255,0.03);
        }}
        .faq summary {{
          cursor:pointer;
          font-weight: 900;
          color: var(--text);
          list-style:none;
        }}
        .faq summary::-webkit-details-marker {{ display:none; }}
        .faq p {{ margin:10px 0 0 0; color: var(--muted); font-size: 13px; line-height:1.5; }}

        .notice {{
          margin-top:12px;
          padding:12px 14px;
          border:1px solid rgba(251,191,36,0.35);
          background: rgba(251,191,36,0.10);
          border-radius: 16px;
          color: #fde68a;
          font-size: 13px;
          line-height:1.45;
        }}

        .white-panel {{
          background: #ffffff;
          color: #0b1020;
          border-radius: 18px;
          padding: 18px;
        }}
        .white-panel h3 {{ margin: 0 0 10px 0; font-size: 16px; }}
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


# ================= OPTION B: LANDING CONVERSION =================

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
            Upload une facture PDF → on détecte le fournisseur & le montant → on génère un <b>email de négociation</b>
            + checklist + export PDF. Résultat en 30 secondes.
          </p>

          <div style="display:flex;gap:10px;flex-wrap:wrap;margin-top:10px;">
            <span class="badge">⚡ <b>30 sec</b> par audit</span>
            <span class="badge">📉 <b>10–15%</b> d’économies typiques</span>
            <span class="badge">🔒 <b>Paiement</b> Stripe</span>
          </div>

          <div class="notice">
            <b>Astuce conversion :</b> commence par voir un exemple, puis teste avec ta facture.
          </div>

          <div class="row-actions" style="margin-top:16px;">
            <a class="btn" href="#try">Essayer maintenant</a>
            <a class="btn btn-secondary" href="/example">Voir un exemple</a>
          </div>

          <div style="display:grid;grid-template-columns:1fr 1fr;gap:12px;margin-top:18px;">
            <div class="feature">
              <h3>✅ Email prêt à envoyer</h3>
              <p>Texte clair, pro, orienté “remise annuelle / downgrade / licences inutilisées”.</p>
            </div>
            <div class="feature">
              <h3>✅ Export PDF “rapport”</h3>
              <p>Format clean pour ton dossier achats ou ton boss.</p>
            </div>
            <div class="feature">
              <h3>✅ Checklist actionnable</h3>
              <p>Le plan simple pour récupérer de l’argent rapidement.</p>
            </div>
            <div class="feature">
              <h3>✅ Confidentialité</h3>
              <p>On traite juste ton PDF pour extraire montant/fournisseur (MVP).</p>
            </div>
          </div>

          <h2 style="margin-top:22px;font-size:18px;margin-bottom:10px;">FAQ</h2>

          <div style="display:grid;gap:10px;">
            <details class="faq">
              <summary>Ça marche avec toutes les factures ?</summary>
              <p>Ça marche déjà bien sur les PDF “classiques”. Si ton PDF est une image scannée, l’extraction peut être moins fiable (on pourra ajouter OCR ensuite).</p>
            </details>
            <details class="faq">
              <summary>Pourquoi je paie {price} ?</summary>
              <p>L’aperçu est gratuit. Le paiement débloque le rapport complet (email + checklist + PDF). Stripe sécurise le paiement.</p>
            </details>
            <details class="faq">
              <summary>Et si le fournisseur est mal détecté ?</summary>
              <p>Pas grave : le rapport reste utile. On ajoute ensuite une correction manuelle et une meilleure détection.</p>
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


# ================= EXEMPLE RAPPORT (CONVERSION) =================
@app.get("/example", response_class=HTMLResponse)
def example():
    # Exemple statique — rassure et augmente conversion
    vendor = "Microsoft 365"
    company = "Exemple SARL"
    name = "Mohamed"
    currency = "EUR"
    total = 540.00
    savings = 81.00
    annual = round(savings * 12, 2)

    subject = f"Demande d’amélioration tarifaire - {company}"
    body = f"""Bonjour,

Nous utilisons {vendor}. Avant renouvellement, nous souhaitons discuter d’un ajustement tarifaire.
Avez-vous une remise annuelle, une offre fidélité, ou un plan plus adapté ?

Cordialement,
{name}"""

    inner = f"""
      <h1>Exemple de rapport</h1>
      <p class="subtitle">Voici exactement ce que tu obtiens après paiement : KPI + email prêt + PDF.</p>

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
            <div class="label">Checklist</div>
            <pre>✅ Envoyer l’email
✅ Demander remise annuelle / downgrade
✅ Vérifier licences inutilisées
✅ Revue mensuelle des abonnements</pre>
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

    vendor = normalize_vendor(detect_vendor(raw_text))
    currency = detect_currency(raw_text)
    total = extract_total_amount(raw_text)

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
          <a class="btn btn-secondary" href="/example">Voir un exemple</a>

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

      <p style="margin-top:18px;"><a class="link" href="/pricing">← Retour</a></p>
    """
    return shell("Aperçu", inner)


# ================= STRIPE ELEMENTS =================
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
        return JSONResponse({"ok": True, "redirect": f"/full/{doc_id}?t={t}"})

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
            <div class="muted">Économie estimée : <b class="green">{savings:.2f} {currency}</b></div>
          </div>

          <div class="kpi" style="background:rgba(34,197,94,0.10);border:1px solid rgba(34,197,94,0.25);">
            <div class="label">Projection annuelle</div>
            <div class="value green">{annual:.2f} {currency}</div>
            <div class="muted" style="margin-top:6px;">(si cette dépense est mensuelle)</div>
          </div>

          <div class="kpi">
            <div class="label">Pourquoi ça marche</div>
            <pre>✅ Tu demandes une remise annuelle
✅ Tu proposes un downgrade si besoin
✅ Tu coupes les licences inutilisées</pre>
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