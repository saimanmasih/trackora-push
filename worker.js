export default {
  async fetch(request, env) {
    const url = new URL(request.url);

    // Health check
    if (request.method === "GET" && url.pathname === "/health") {
      return json({
        service: "trackora-push",
        status: "online"
      });
    }

    // Push endpoint
    if (request.method === "POST" && url.pathname === "/push") {
      return handlePush(request, env);
    }

    return json(
      {
        error: "Not Found"
      },
      404
    );
  }
};

async function handlePush(request, env) {
  // Backend authorization secret.
  // This value must be configured later as a Cloudflare Worker Secret.
  const expectedSecret = env.TRACKORA_PUSH_SECRET;

  if (!expectedSecret) {
    return json(
      {
        error: "Push gateway is not configured"
      },
      503
    );
  }

  const authorization = request.headers.get("Authorization");

  if (authorization !== `Bearer ${expectedSecret}`) {
    return json(
      {
        error: "Unauthorized"
      },
      401
    );
  }

  if (request.headers.get("Content-Type")?.includes("application/json") !== true) {
    return json(
      {
        error: "Content-Type must be application/json"
      },
      415
    );
  }

  let body;

  try {
    body = await request.json();
  } catch {
    return json(
      {
        error: "Invalid JSON"
      },
      400
    );
  }

  const { token, title, message, data } = body;

  if (
    typeof token !== "string" ||
    token.length < 20 ||
    typeof title !== "string" ||
    title.length < 1 ||
    title.length > 120 ||
    typeof message !== "string" ||
    message.length < 1 ||
    message.length > 500
  ) {
    return json(
      {
        error: "Invalid push payload"
      },
      400
    );
  }

  // Firebase sending will be connected after
  // the required server-side Firebase credentials
  // are safely configured as Worker Secrets.

  return json({
    accepted: true,
    service: "trackora-push",
    message: "Push request validated successfully",
    fcmConfigured: Boolean(env.FIREBASE_PROJECT_ID)
  });
}

function json(data, status = 200) {
  return new Response(JSON.stringify(data), {
    status,
    headers: {
      "Content-Type": "application/json; charset=utf-8",
      "Cache-Control": "no-store"
    }
  });
}
// TrackOra Cloudflare deployment verification
