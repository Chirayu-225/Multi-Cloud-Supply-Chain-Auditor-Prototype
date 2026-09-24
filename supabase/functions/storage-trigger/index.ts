import { serve } from "https://deno.land/std@0.224.0/http/server.ts";

const BACKEND_URL = Deno.env.get("BACKEND_URL") ?? "";

serve(async (req) => {
  if (req.method !== "POST") {
    return new Response("Method not allowed", { status: 405 });
  }

  const payload = await req.json();
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