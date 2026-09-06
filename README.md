# Multi-Cloud AI Supply Chain Auditor

Scans models and datasets across cloud storage sources for tampering,
dangerous serialization formats, and dependency typosquatting — deployed
entirely on free tiers that require **no credit card** and **never expire**.

## Architecture

```
File uploaded to Supabase Storage bucket
        |
        v
Supabase Database Webhook fires on storage.objects INSERT
        |
        v
Supabase Edge Function (thin dispatcher)
        |
        v
Backend (FastAPI on Render) -- runs the real scans:
    - serialization_check.py   (pickle vs. safetensors)
    - dangerous_code_scan.py   (static opcode inspection, never executes)
    - typosquat_check.py       (dependency name Levenshtein check)
    - cross_cloud_diff.py      (hash compare vs. Hugging Face source)
        |
        v
Result written directly to Supabase Postgres via its REST API
        |
        v
Streamlit dashboard (Render) reads results from the same REST API
```

Why this stack: every service here (Supabase, Render, Hugging Face Hub)
has a genuinely card-free free tier with no expiry cliff — verified
directly against each provider's docs and billing pages, after an
earlier version of this plan mistakenly included Cloudflare R2, which
does require a card even on its free tier.

## Setup — step by step

### 1. Supabase (Storage + Database + Edge Function)

1. Go to https://supabase.com and create a free account (no card).
2. Create a new project (pick any region close to you).
3. **Storage**: Dashboard > Storage > New bucket > name it
   `supply-chain-artifacts`.
4. **Database**: Dashboard > SQL Editor > paste and run
   `supabase/sql/schema.sql` from this repo.
5. **Get your S3-compatible Storage credentials**: Dashboard > Project
   Settings > Storage > "S3 Connection" — note the endpoint URL, access
   key, and secret key. These map to `SUPABASE_S3_ENDPOINT`,
   `SUPABASE_S3_ACCESS_KEY_ID`, `SUPABASE_S3_SECRET_ACCESS_KEY`.
6. **Get your API keys**: Dashboard > Project Settings > API — copy the
   `URL`, the `anon` public key, and the `service_role` secret key.
7. **Deploy the Edge Function**:
   ```bash
   npm install -g supabase
   supabase login
   supabase link --project-ref <your-project-ref>
   supabase functions deploy storage-trigger
   supabase secrets set BACKEND_URL=https://your-app.onrender.com
   ```
8. **Wire up the trigger**: Dashboard > Database > Webhooks > Create a
   new webhook on table `storage.objects`, event `INSERT`, pointing to
   your deployed Edge Function's URL (shown after step 7 deploys).

### 2. Backend (Render)

Push the `backend/` folder to a GitHub repo, then on Render:
- New Web Service → connect the repo → root directory `backend/`
- Build command: `pip install -r requirements.txt`
- Start command: `uvicorn main:app --host 0.0.0.0 --port $PORT`
- Environment variables to set:
  - `SUPABASE_S3_ENDPOINT`, `SUPABASE_S3_ACCESS_KEY_ID`,
    `SUPABASE_S3_SECRET_ACCESS_KEY` — from step 1.5
  - `SUPABASE_STORAGE_BUCKET` — `supply-chain-artifacts`
  - `SUPABASE_URL` — from step 1.6
  - `SUPABASE_SERVICE_ROLE_KEY` — from step 1.6 (server-side only,
    never put this in the dashboard's env vars)

Free tier note: Render spins down after inactivity (~30-60s wake time).
Supabase free projects auto-pause after 7 days of no database activity —
a manual click in the dashboard wakes them back up.

### 3. Dashboard (Render, separate service)

Same repo, root directory `dashboard/`:
- Build command: `pip install -r requirements.txt`
- Start command: `streamlit run app.py --server.port $PORT --server.address 0.0.0.0`
- Environment variables:
  - `SUPABASE_URL` — from step 1.6
  - `SUPABASE_ANON_KEY` — from step 1.6 (safe to expose, read-only via RLS)

### 4. Configure cross-cloud comparisons

Edit `backend/scanners/cross_cloud_diff.py` and fill in `R2_TO_HF_MAP`
(name kept for now — rename if you like) with the object keys you want
checked against their Hugging Face source, e.g.:

```python
R2_TO_HF_MAP = {
    "models/bert-base.safetensors": ("bert-base-uncased", "model.safetensors"),
}
```

## Testing it

Upload a file to your Supabase Storage bucket (via the dashboard UI or
the S3-compatible API) and watch it flow through: webhook → Edge
Function → backend scan → result in Postgres → visible on the
dashboard.

Good test cases:
- A `.safetensors` file → should come back low-risk
- A `.pkl` file containing an `os.system` call → should flag high-risk
  in `dangerous_code_scan`
- A `requirements.txt` with `"tensrflow"` instead of `"tensorflow"` →
  should flag in `typosquat_check`

## What to say about this in an interview

This project demonstrates: event-driven cloud architecture across a
BaaS platform, the trade-off between edge/serverless compute (fast,
capped) and traditional compute (slower cold start, uncapped) and how
to design around that trade-off, static analysis of untrusted
serialized data without executing it, and a real supply-chain security
threat model that maps to actual incidents (malicious Hugging
Face/PyPI uploads, tampered model mirrors).
