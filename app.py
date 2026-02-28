from fastapi import FastAPI, UploadFile, File, Form, HTTPException, Request
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse
from fastapi import HTTPException
from fastapi.responses import HTMLResponse
from pydantic import BaseModel
from typing import Dict, Any
from dotenv import load_dotenv
import pdfplumber
import uuid
import os
import re
import json
import stripe
import json
import time


# ================= CONFIG =================
load_dotenv()  # lit le fichier .env en local

STRIPE_SECRET_KEY = os.getenv("STRIPE_SECRET_KEY", "")
STRIPE_PUBLISHABLE_KEY = os.getenv("STRIPE_PUBLISHABLE_KEY", "")
STRIPE_WEBHOOK_SECRET = os.getenv("STRIPE_WEBHOOK_SECRET", "")

PRICE_CENTS = 900
CURRENCY = "eur"

if not STRIPE_SECRET_KEY or not STRIPE_PUBLISHABLE_KEY or not STRIPE_WEBHOOK_SECRET:
    print("⚠️ Variables Stripe manquantes. Vérifie ton fichier .env (local) ou tes variables Render (prod).")

stripe.api_key = STRIPE_SECRET_KEY

app = FastAPI(title="SpendGuard AI")

DATA_DIR = "./data"
os.makedirs(DATA_DIR, exist_ok=True)

STATE_PATH = os.path.join(DATA_DIR, "state.json")

# ================= PERSISTENCE (DISQUE) =================
def _default_state() -> Dict[str, Any]:
    return {"reports": {}, "paid": []}

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

def get_report(doc_id: str) -> Dict[str, Any] | None:
    state = load_state()
    return state["reports"].get(doc_id)

def set_report(doc_id: str, data: Dict[str, Any]) -> None:
    state = load_state()
    state["reports"][doc_id] = data
    save_state(state)

def mark_paid(doc_id: str) -> None:
    state = load_state()
    if doc_id not in state["paid"]:
        state["paid"].append(doc_id)
        save_state(state)

def is_paid(doc_id: str) -> bool:
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
                    return True

            if intents.has_more and intents.data:
                starting_after = intents.data[-1].id
            else:
                break

        return False
    except Exception:
        return False


# ================= UTILITAIRES =================
def detect_currency(text: str) -> str:
    if "€" in text:
        return "EUR"
    if "$" in text:
        return "USD"
    if "£" in text:
        return "GBP"
    return "UNKNOWN"

def detect_vendor(raw_text: str) -> str:
    text = raw_text.strip()
    low = text.lower()

    # 1) Règles simples (marques fréquentes)
    brands = [
        ("google", "Google"),
        ("workspace", "Google Workspace"),
        ("notion", "Notion"),
        ("microsoft", "Microsoft"),
        ("office 365", "Microsoft 365"),
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

    # 2) Cherche une ligne "Facturé par", "Vendor", "Fournisseur", etc.
    patterns = [
        r"(factur[eé]\s*par|fournisseur|vendor|seller|issued by)\s*[:\-]\s*(.+)",
        r"(soci[eé]t[eé]|company)\s*[:\-]\s*(.+)",
    ]
    for p in patterns:
        m = re.search(p, low, re.IGNORECASE)
        if m:
            cand = m.group(m.lastindex).strip()
            cand = cand.split("\n")[0].strip()
            if 3 <= len(cand) <= 80:
                cand = cand.title()
                cand = cand.replace("Ia", "IA").replace("Aws", "AWS").replace("Hubspot", "HubSpot")
                return cand

    # 3) Heuristique : souvent le nom est dans les 10 premières lignes
    lines = [l.strip() for l in text.splitlines() if l.strip()]
    head = lines[:12]
    # ignore lignes trop "génériques"
    bad = ("facture", "invoice", "date", "total", "tva", "vat", "adresse", "address")
    for l in head:
        ll = l.lower()
        if len(l) < 4 or any(b in ll for b in bad):
            continue
        # Si ligne contient beaucoup de lettres, peu de chiffres → bon candidat
        letters = sum(c.isalpha() for c in l)
        digits = sum(c.isdigit() for c in l)
        if letters >= 6 and digits <= 2 and len(l) <= 60:
            return l
  
    return "UNKNOWN"

def extract_total_amount(raw_text: str) -> float:
    t = raw_text.replace("\u00a0", " ")  # espaces insécables
    low = t.lower()

    # Priorité: lignes "total" / "amount due" etc.
    priority_keys = [
        "total ttc", "montant ttc", "total à payer", "net à payer",
        "amount due", "total due", "total", "grand total"
    ]

    def parse_number(s: str) -> float:
        s = s.strip()
        s = s.replace(" ", "")
        # 1 234,56 -> 1234.56
        if "," in s and "." in s:
            # cas 1.234,56 -> on enlève les points
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

    # Cherche une valeur sur les lignes prioritaires
    lines = [l.strip() for l in t.splitlines() if l.strip()]
    for l in lines:
        ll = l.lower()
        if any(k in ll for k in priority_keys):
            m = re.search(r"([0-9]{1,3}(?:[ .][0-9]{3})*(?:[.,][0-9]{2})?)", l)
            if m:
                val = parse_number(m.group(1))
                if val > 0:
                    return val

    # fallback : dernier montant avec symbole ou code
    matches = re.findall(r"([0-9]{1,3}(?:[ .][0-9]{3})*(?:[.,][0-9]{2})?)\s*(€|eur|usd|\$|gbp|£)", low)
    if matches:
        val = parse_number(matches[-1][0])
        if val > 0:
            return val

    # fallback 2 : dernier nombre formaté
    m2 = re.findall(r"([0-9]{1,3}(?:[ .][0-9]{3})*(?:[.,][0-9]{2}))", low)
    if m2:
        val = parse_number(m2[-1])
        return val if val > 0 else 0.0

    return 0.0

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
        .white-panel h3 {{ margin: 0 0 10px 0; font-size: 16px; }}
        .hint {{ font-size: 12px; color: #334155; margin-top: 8px; }}
        pre {{
          background: rgba(255,255,255,0.08);
          padding: 16px;
          border-radius: 14px;
          white-space: pre-wrap;
          border: 1px solid var(--border);
          margin:0;
        }}
        .link {{ color: #93c5fd; text-decoration: none; font-weight: 800; }}
        .danger {{ color: #fecaca; font-size: 13px; margin-top: 10px; }}
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
    tone: str = Form("Pro")
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
    raw_lower = raw_text.lower()

    vendor = detect_vendor(raw_text)
    currency = detect_currency(raw_text)
    total = extract_total_amount(raw_text)
    # Estimation plus “business” (plafonnée)
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
        "filename": file.filename
    })

    inner = f"""
      <h1>Aperçu</h1>
      <p class="subtitle">Ton rapport est prêt. Débloque la version complète (email + check-list + export PDF).</p>

      <div class="grid">
        <div>
          <div class="kpi">
            <div class="label">Montant détecté</div>
            <div class="value">{total} {currency}</div>
          </div>

          <div class="kpi">
            <div class="label">Économie estimée</div>
            <div class="value green">{savings} {currency}</div>
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
    return shell("Preview", inner)


# ================= PAIEMENT (Stripe Elements) =================
@app.get("/pay/{doc_id}", response_class=HTMLResponse)
def pay(doc_id: str):
    d = get_report(doc_id)
    if not d:
        return shell("Erreur", "<h1>doc_id introuvable</h1><p class='muted'>Refais l’aperçu.</p>")

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
            <div class="value">{d["vendor"]}</div>
            <p class="muted" style="margin:8px 0 0 0;">Montant détecté : {d["total"]} {d["currency"]}</p>
            <p class="muted" style="margin:6px 0 0 0;">Économie estimée : <span class="green"><strong>{d["savings"]} {d["currency"]}</strong></span></p>
            <div style="margin-top:20px;padding:15px;background:rgba(0,255,100,0.08);border-radius:10px;">
              <strong>Projection annuelle :</strong><br>
              Si cette dépense est mensuelle, cela représente
              <span style="color:#22c55e;font-weight:bold;">
                {{ (d["savings"] * 12)|round(2) }} EUR économisables par an
              </span>
            </div>
          </div>

          <div class="kpi">
            <div class="label">Conseil</div>
            <pre>🎯 Objectif : obtenir une remise
📌 Demande : annualisation + downgrade + licences inutilisées
⏱️ Temps : 2 minutes</pre>
          </div>
        </div>

        <div>
          <div class="white-panel">
            <h3>Paiement sécurisé</h3>
            <div id="error" class="danger"></div>
            <div id="payment-element"></div>
            <button class="btn" id="payBtn" style="margin-top:14px;">Payer et débloquer</button>
            <div class="hint">Carte test : <strong>4242 4242 4242 4242</strong> (date future, CVC 123).</div>
          </div>
        </div>
      </div>

      <script src="https://js.stripe.com/v3/"></script>
      <script>
        const docId = "{doc_id}";
        const stripe = Stripe("{STRIPE_PUBLISHABLE_KEY}");

        async function boot() {{
          const res = await fetch("/create-payment-intent", {{
            method: "POST",
            headers: {{ "Content-Type": "application/json" }},
            body: JSON.stringify({{ doc_id: docId }})
          }});
          const data = await res.json();
          if (!data.client_secret) {{
            document.getElementById("error").innerText = "Erreur paiement: " + (data.detail || "client_secret manquant");
            return;
          }}

          const elements = stripe.elements({{ clientSecret: data.client_secret }});
          const paymentElement = elements.create("payment", {{ layout: "tabs" }});
          paymentElement.mount("#payment-element");

          document.getElementById("payBtn").addEventListener("click", async () => {{
            document.getElementById("error").innerText = "";
            const result = await stripe.confirmPayment({{
              elements,
              confirmParams: {{
                return_url: window.location.origin + "/paid/" + docId
              }}
            }});
            if (result.error) {{
              document.getElementById("error").innerText = result.error.message;
            }}
          }});
        }}
        boot();
      </script>

      <p style="margin-top:18px;"><a class="link" href="/">← Retour</a></p>
    """
    return shell("Paiement", inner)


# ================= CREATE PAYMENT INTENT =================
class PayReq(BaseModel):
    doc_id: str

@app.post("/create-payment-intent")
def create_payment_intent(req: PayReq):
    if not get_report(req.doc_id):
        raise HTTPException(status_code=404, detail="doc_id introuvable")

    intent = stripe.PaymentIntent.create(
        amount=PRICE_CENTS,
        currency=CURRENCY,
        automatic_payment_methods={"enabled": True},
        metadata={"doc_id": req.doc_id}
    )
    return JSONResponse({"client_secret": intent.client_secret})


# ================= RETOUR APRÈS PAIEMENT =================
@app.get("/paid/{doc_id}", response_class=HTMLResponse)
def paid(doc_id: str, payment_intent: str = ""):
    # Ici on vérifie en direct + on laisse le webhook faire foi aussi.
    if not payment_intent:
        return shell("Erreur", "<h1>Paiement non confirmé</h1><p class='muted'>Paramètre payment_intent manquant.</p>")

    pi = stripe.PaymentIntent.retrieve(payment_intent)
    if pi.status == "succeeded":
        # Déverrouille immédiatement (UX), même si webhook arrive après.
        mark_paid(doc_id)
        return RedirectResponse(f"/full/{doc_id}")

    return shell("Paiement", f"<h1>Paiement incomplet</h1><p class='muted'>Statut: {pi.status}</p><a class='btn' href='/pay/{doc_id}'>Réessayer</a>")


# ================= WEBHOOK STRIPE (SOURCE DE VÉRITÉ) =================
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

    # Événements importants
    event_type = event.get("type", "")
    obj = event["data"]["object"]

    # PaymentIntent OK → on déverrouille
    if event_type in ("payment_intent.succeeded",):
        doc_id = (obj.get("metadata") or {}).get("doc_id")
        if doc_id:
            mark_paid(doc_id)

    # Optionnel: gérer un paiement échoué
    # if event_type == "payment_intent.payment_failed": ...

    return {"received": True}


# ================= RAPPORT COMPLET (+ COPY + PDF) =================
@app.get("/full/{doc_id}", response_class=HTMLResponse)
def full(doc_id: str):
    data = get_report(doc_id)
    if not data:
        return shell("Erreur", "<h1>Rapport introuvable</h1><p class='muted'>Refais l’aperçu.</p>")

    if not is_paid(doc_id):
        return shell(
            "Accès verrouillé",
            f"<h1>Accès verrouillé</h1><p class='muted'>Paiement requis.</p><a class='btn' href='/pay/{doc_id}'>Payer 9€</a>",
        )

    # Normalisation vendor (petite finition)
    vendor = (data.get("vendor") or "UNKNOWN")
    vendor = vendor.replace("Ia", "IA").replace("Aws", "AWS")

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
    # IMPORTANT: JSON stringify pour éviter les bugs JS (apostrophes, retours ligne, etc.)
    email_text_js = json.dumps(email_text)

    inner = f"""
      <h1>Rapport complet</h1>
      <p style="opacity:0.7;font-size:14px;">
        Analyse IA basée sur optimisation SaaS B2B (benchmark 2026)
      </p>
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
            <a class="btn" href="/print/{doc_id}" target="_blank">Télécharger PDF</a>
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


# ================= PAGE PRINT (PDF) =================
@app.get("/print/{doc_id}", response_class=HTMLResponse)
def print_view(doc_id: str):
    data = get_report(doc_id)
    if not data:
        return HTMLResponse("Rapport introuvable", status_code=404)
    if not is_paid(doc_id):
        return HTMLResponse("Paiement requis", status_code=403)

    vendor = (data.get("vendor") or "UNKNOWN")
    vendor = vendor.replace("Ia", "IA").replace("Aws", "AWS")

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
@app.get("/health")
def health():
    return {"status": "running"}

from fastapi.responses import HTMLResponse

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