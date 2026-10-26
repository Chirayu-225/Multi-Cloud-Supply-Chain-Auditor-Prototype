// Supabase Edge Function — wakes the backend when a scan job is queued.
//
// Invoked by a Database Webhook on `public.scan_jobs` INSERT (the job row
// itself is created by a trigger on storage.objects — see schema.sql).
// It forwards only the job id, signed with HMAC-SHA256 so the backend can
// reject anyone else calling it. The backend never trusts this payload
// for *what* to scan; it reads jobs from the database.
//
// Deploy with JWT verification ON (the default) and configure the webhook
// to send the service-role Authorization header.

const BACKEND_URL = Deno.env.get("BACKEND_URL") ?? "";
const WEBHOOK_SECRET = Deno.env.get("SCAN_WEBHOOK_SECRET") ?? "";

async function hmacHex(secret: string, message: string): Promise<string> {
  const key = await crypto.subtle.importKey(
    "raw",
    new TextEncoder().encode(secret),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"],
  );
  const sig = await crypto.subtle.sign("HMAC", key, new TextEncoder().encode(message));
  return Array.from(new Uint8Array(sig)).map((b) => b.toString(16).padStart(2, "0")).join("");
}

Deno.serve(async (req) => {
  if (req.method !== "POST") {
    return new Response("Method not allowed", { status: 405 });
  }
  if (!BACKEND_URL || !WEBHOOK_SECRET) {
    return new Response("Function not configured", { status: 500 });
  }

  const payload = await req.json().catch(() => null);
  const jobId = payload?.record?.id;
  if (payload?.table !== "scan_jobs" || typeof jobId !== "number") {
    return new Response("Unexpected payload", { status: 400 });
  }

  const body = JSON.stringify({ job_id: jobId });
  const timestamp = Math.floor(Date.now() / 1000).toString();
  const signature = await hmacHex(WEBHOOK_SECRET, `${timestamp}.${body}`);

  // Fire the wake-up but don't make the webhook wait on a cold start:
  // the job is already safe in the database and the backend drains the
  // queue on startup, so a slow or failed ping loses nothing.
  const ping = fetch(`${BACKEND_URL}/jobs/notify`, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      "X-Auditor-Timestamp": timestamp,
      "X-Auditor-Signature": signature,
    },
    body,
  }).catch((err) => console.error("Backend ping failed:", err));

  // Keep the function alive until the ping settles, without blocking the response.
  // deno-lint-ignore no-explicit-any
  (globalThis as any).EdgeRuntime?.waitUntil?.(ping);

  return new Response("Job notification sent", { status: 202 });
});
