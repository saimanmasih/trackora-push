export default {
  async fetch(request, env) {
    const url = new URL(request.url);

    // ---------------------------------------------------------
    // CORS / basic response headers
    // ---------------------------------------------------------
    const corsHeaders = {
      "Access-Control-Allow-Origin": "*",
      "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
      "Access-Control-Allow-Headers": "Content-Type, Authorization"
    };

    // Handle browser preflight requests
    if (request.method === "OPTIONS") {
      return new Response(null, {
        status: 204,
        headers: corsHeaders
      });
    }

    // ---------------------------------------------------------
    // Health check
    // GET /health
    // ---------------------------------------------------------
    if (request.method === "GET" && url.pathname === "/health") {
      return json(
        {
          service: "trackora-push",
          status: "online",
          version: "1.0.0"
        },
        200,
        corsHeaders
      );
    }

    // ---------------------------------------------------------
    // Push gateway
    // POST /push
    // ---------------------------------------------------------
    if (request.method === "POST" && url.pathname === "/push") {
      return handlePush(request, env, corsHeaders);
    }

    // ---------------------------------------------------------
    // Unknown route
    // ---------------------------------------------------------
    return json(
      {
        error: "Not Found",
        service: "trackora-push"
      },
      404,
      corsHeaders
    );
  }
};


// =============================================================
// PUSH HANDLER
// =============================================================

async function handlePush(request, env, corsHeaders) {
  // Server-side secret.
  // Configure this later as a Cloudflare Worker Secret.
  const expectedSecret = env.TRACKORA_PUSH_SECRET;

  if (!expectedSecret) {
    return json(
      {
        error: "Push gateway is not configured"
      },
      503,
      corsHeaders
    );
  }

  // -----------------------------------------------------------
  // Authorization
  // -----------------------------------------------------------

  const authorization = request.headers.get("Authorization");

  if (authorization !== `Bearer ${expectedSecret}`) {
    return json(
      {
        error: "Unauthorized"
      },
      401,
      corsHeaders
    );
  }

  // -----------------------------------------------------------
  // Content-Type validation
  // -----------------------------------------------------------

  const contentType = request.headers.get("Content-Type") || "";

  if (!contentType.toLowerCase().includes("application/json")) {
    return json(
      {
        error: "Content-Type must be application/json"
      },
      415,
      corsHeaders
    );
  }

  // -----------------------------------------------------------
  // Parse JSON
  // -----------------------------------------------------------

  let body;

  try {
    body = await request.json();
  } catch {
    return json(
      {
        error: "Invalid JSON"
      },
      400,
      corsHeaders
    );
  }

  // -----------------------------------------------------------
  // Extract payload
  // -----------------------------------------------------------

  const {
    token,
    title,
    message,
    data
  } = body || {};

  // -----------------------------------------------------------
  // Validate FCM token
  // -----------------------------------------------------------

  if (
    typeof token !== "string" ||
    token.trim().length < 20
  ) {
    return json(
      {
        error: "Invalid push token"
      },
      400,
      corsHeaders
    );
  }

  // -----------------------------------------------------------
  // Validate title
  // -----------------------------------------------------------

  if (
    typeof title !== "string" ||
    title.trim().length < 1 ||
    title.length > 120
  ) {
    return json(
      {
        error: "Invalid push title"
      },
      400,
      corsHeaders
    );
  }

  // -----------------------------------------------------------
  // Validate message
  // -----------------------------------------------------------

  if (
    typeof message !== "string" ||
    message.trim().length < 1 ||
    message.length > 500
  ) {
    return json(
      {
        error: "Invalid push message"
      },
      400,
      corsHeaders
    );
  }

  // -----------------------------------------------------------
  // Validate optional data
  // -----------------------------------------------------------

  if (
    data !== undefined &&
    data !== null &&
    (typeof data !== "object" || Array.isArray(data))
  ) {
    return json(
      {
        error: "Invalid push data"
      },
      400,
      corsHeaders
    );
  }

  // -----------------------------------------------------------
  // Firebase sender is intentionally NOT implemented yet.
  //
  // Firebase Admin credentials must never be placed inside
  // frontend code or GitHub. They will be configured later
  // as protected Cloudflare Worker Secrets.
  // -----------------------------------------------------------

  const firebaseConfigured =
    Boolean(env.FIREBASE_PROJECT_ID) &&
    Boolean(env.FIREBASE_CLIENT_EMAIL) &&
    Boolean(env.FIREBASE_PRIVATE_KEY);

  return json(
    {
      accepted: true,
      service: "trackora-push",
      message: "Push request validated successfully",
      fcmConfigured: firebaseConfigured
    },
    200,
    corsHeaders
  );
}


// =============================================================
// JSON RESPONSE HELPER
// =============================================================

function json(data, status = 200, extraHeaders = {}) {
  return new Response(
    JSON.stringify(data),
    {
      status,
      headers: {
        "Content-Type": "application/json; charset=utf-8",
        "Cache-Control": "no-store",
        ...extraHeaders
      }
    }
  );
}
