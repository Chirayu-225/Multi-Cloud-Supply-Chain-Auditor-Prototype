/**
 * Multi-Cloud AI Supply Chain Auditor — Cloudflare Worker (dispatcher only)
 *
 * This Worker does ZERO heavy compute. Its entire job is:
 *   1. Receive an R2 event notification (a file landed in the bucket)
 *   2. Forward the job details to the backend (Render/Fly.io) which does
 *      the actual hashing / deserialization / scanning
 *   3. Optionally serve scan results back to the dashboard from D1
 *
 * Keeping this Worker "thin" is deliberate — Cloudflare's free tier caps
 * CPU time per invocation at 10ms. Forwarding a JSON payload takes
 * microseconds; hashing a multi-MB model file would not fit.
 */

export default {
  async fetch(request, env) {
    const url = new URL(request.url);

    // --- 1. R2 event notification lands here ---
    if (url.pathname === "/r2-event" && request.method === "POST") {
      const event = await request.json();

      // Forward straight to the backend scanning service. We don't touch
      // the file contents here at all — just relay metadata about where it is.
      const backendResponse = await fetch(`${env.BACKEND_URL}/scan`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          bucket: event.bucket,
          object_key: event.object.key,
          size: event.object.size,
          source: "r2",
        }),
      });

      if (!backendResponse.ok) {
        return new Response("Backend dispatch failed", { status: 502 });
      }

      return new Response("Scan job dispatched", { status: 202 });
    }

    // --- 2. Dashboard asks for latest scan results (reads from D1) ---
    if (url.pathname === "/results" && request.method === "GET") {
      const { results } = await env.DB.prepare(
        "SELECT object_key, risk_score, findings, scanned_at FROM scan_results ORDER BY scanned_at DESC LIMIT 50"
      ).all();
      return Response.json(results);
    }

    // --- 3. Backend posts a completed result back, we store it in D1 ---
    if (url.pathname === "/results" && request.method === "POST") {
      const body = await request.json();
      await env.DB.prepare(
        `INSERT INTO scan_results (object_key, risk_score, findings, scanned_at)
         VALUES (?, ?, ?, ?)`
      )
        .bind(
          body.object_key,
          body.risk_score,
          JSON.stringify(body.findings),
          new Date().toISOString()
        )
        .run();
      return new Response("Stored", { status: 201 });
    }

    return new Response("Not found", { status: 404 });
  },
};
