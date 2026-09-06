// Multi-Cloud AI Supply Chain Auditor — Supabase Edge Function (dispatcher)
//
// Deno-based, deployed via `supabase functions deploy storage-trigger`.
// Supabase Edge Functions have a far more generous execution budget than
// Cloudflare Workers' free-tier 10ms CPU cap, but we still keep this thin:
// it only forwards the job to the Render backend, which does the actual
// hashing / deserialization / scanning work.
//
// This function is invoked by a Supabase Database Webhook configured on
// the `storage.objects` table (fires on INSERT — i.e. a new file uploaded).

import { serve } from "https://deno.land/std@0.224.0/http/server.ts";

const BACKEND_URL = Deno.env.get("BACKEND_URL") ?? ""; // e.g. https://your-app.onrender.com

serve(async (req) => {
  if (req.method !== "POST") {
    return new Response("Method not allowed", { status: 405 });
  }

  const payload = await req.json();

  // Supabase Storage webhook payload shape (record = the new storage.objects row)
  const record = payload.record;
  if (!record) {
    return new Response("No record in payload", { status: 400 });
  }

  const backendResponse = await fetch(`${BACKEND_URL}/scan`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      bucket: record.bucket_id,
      object_key: record.name,
      size: record.metadata?.size ?? 0,
      source: "supabase",
    }),
  });

  if (!backendResponse.ok) {
    return new Response("Backend dispatch failed", { status: 502 });
  }

  return new Response("Scan job dispatched", { status: 202 });
});
