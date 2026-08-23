export default {
  async fetch(request, env) {
    const url = new URL(request.url);

    const corsHeaders = {
      "Access-Control-Allow-Origin": "*",
      "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
      "Access-Control-Allow-Headers": "Content-Type, Authorization"
    };

    if (request.method === "OPTIONS") {
      return new Response(null, {
        status: 204,
        headers: corsHeaders
      });
    }

    if (request.method === "GET" && url.pathname === "/health") {
      return json(
        {
          service: "trackora-push",
          status: "online",
          version: "2.0.0"
        },
        200,
        corsHeaders
      );
    }

    if (request.method === "POST" && url.pathname === "/push") {
      return handlePush(request, env, corsHeaders);
    }

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


// ============================================================
// PUSH HANDLER
// ============================================================

async function handlePush(request, env, corsHeaders) {
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

  const {
    token,
    title,
    message,
    data
  } = body || {};

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

  const projectId = env.FIREBASE_PROJECT_ID;
  const clientEmail = env.FIREBASE_CLIENT_EMAIL;
  const privateKey = env.FIREBASE_PRIVATE_KEY;

  if (!projectId || !clientEmail || !privateKey) {
    return json(
      {
        error: "Firebase server credentials are not configured"
      },
      503,
      corsHeaders
    );
  }

  try {
    const accessToken = await createGoogleAccessToken(
      clientEmail,
      privateKey
    );

    const fcmUrl =
      `https://fcm.googleapis.com/v1/projects/${encodeURIComponent(projectId)}/messages:send`;

    const fcmPayload = {
      message: {
        token: token.trim(),

        notification: {
          title: title.trim(),
          body: message.trim()
        },

        data: normalizeData(data),

        webpush: {
          notification: {
            title: title.trim(),
            body: message.trim(),
            icon: "/favicon.ico"
          }
        }
      }
    };

    const response = await fetch(fcmUrl, {
      method: "POST",

      headers: {
        "Authorization": `Bearer ${accessToken}`,
        "Content-Type": "application/json"
      },

      body: JSON.stringify(fcmPayload)
    });

    const responseText = await response.text();

    let responseData;

    try {
      responseData = JSON.parse(responseText);
    } catch {
      responseData = {
        raw: responseText
      };
    }

    if (!response.ok) {
      return json(
        {
          error: "FCM request failed",
          status: response.status,
          details: responseData
        },
        502,
        corsHeaders
      );
    }

    return json(
      {
        accepted: true,
        sent: true,
        service: "trackora-push",
        fcmMessageId:
          responseData?.name || null
      },
      200,
      corsHeaders
    );

  } catch (error) {
    return json(
      {
        error: "FCM delivery failed",
        details: error instanceof Error
          ? error.message
          : "Unknown error"
      },
      502,
      corsHeaders
    );
  }
}


// ============================================================
// GOOGLE OAUTH 2.0
// ============================================================

async function createGoogleAccessToken(
  clientEmail,
  privateKey
) {
  const now = Math.floor(Date.now() / 1000);

  const header = {
    alg: "RS256",
    typ: "JWT"
  };

  const payload = {
    iss: clientEmail,
    scope: "https://www.googleapis.com/auth/firebase.messaging",
    aud: "https://oauth2.googleapis.com/token",
    iat: now,
    exp: now + 3600
  };

  const encodedHeader = base64UrlEncode(
    JSON.stringify(header)
  );

  const encodedPayload = base64UrlEncode(
    JSON.stringify(payload)
  );

  const unsignedToken =
    `${encodedHeader}.${encodedPayload}`;

  const normalizedKey = privateKey
    .replace(/\\n/g, "\n")
    .trim();

  const keyData = pemToArrayBuffer(normalizedKey);

  const cryptoKey = await crypto.subtle.importKey(
    "pkcs8",
    keyData,
    {
      name: "RSASSA-PKCS1-v1_5",
      hash: "SHA-256"
    },
    false,
    ["sign"]
  );

  const signature = await crypto.subtle.sign(
    "RSASSA-PKCS1-v1_5",
    cryptoKey,
    new TextEncoder().encode(unsignedToken)
  );

  const signedJwt =
    `${unsignedToken}.${base64UrlEncodeBytes(signature)}`;

  const tokenResponse = await fetch(
    "https://oauth2.googleapis.com/token",
    {
      method: "POST",

      headers: {
        "Content-Type":
          "application/x-www-form-urlencoded"
      },

      body:
        `grant_type=${encodeURIComponent(
          "urn:ietf:params:oauth:grant-type:jwt-bearer"
        )}` +
        `&assertion=${encodeURIComponent(signedJwt)}`
    }
  );

  const tokenText = await tokenResponse.text();

  let tokenData;

  try {
    tokenData = JSON.parse(tokenText);
  } catch {
    throw new Error(
      "Google OAuth returned an invalid response"
    );
  }

  if (
    !tokenResponse.ok ||
    typeof tokenData.access_token !== "string"
  ) {
    throw new Error(
      tokenData.error_description ||
      tokenData.error ||
      "Unable to obtain Google access token"
    );
  }

  return tokenData.access_token;
}


// ============================================================
// DATA NORMALIZATION
// ============================================================

function normalizeData(data) {
  if (!data || typeof data !== "object") {
    return {};
  }

  const result = {};

  for (const [key, value] of Object.entries(data)) {
    if (value === undefined || value === null) {
      continue;
    }

    result[String(key)] = String(value);
  }

  return result;
}


// ============================================================
// BASE64URL HELPERS
// ============================================================

function base64UrlEncode(value) {
  return base64UrlEncodeBytes(
    new TextEncoder().encode(value)
  );
}

function base64UrlEncodeBytes(bytes) {
  let binary = "";

  const chunkSize = 0x8000;

  for (
    let i = 0;
    i < bytes.length;
    i += chunkSize
  ) {
    binary += String.fromCharCode(
      ...bytes.subarray(
        i,
        Math.min(i + chunkSize, bytes.length)
      )
    );
  }

  return btoa(binary)
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/g, "");
}


// ============================================================
// PEM → ARRAY BUFFER
// ============================================================

function pemToArrayBuffer(pem) {
  const base64 = pem
    .replace("-----BEGIN PRIVATE KEY-----", "")
    .replace("-----END PRIVATE KEY-----", "")
    .replace(/\s+/g, "");

  const binary = atob(base64);

  const bytes = new Uint8Array(binary.length);

  for (let i = 0; i < binary.length; i++) {
    bytes[i] = binary.charCodeAt(i);
  }

  return bytes.buffer;
}


// ============================================================
// JSON RESPONSE
// ============================================================

function json(data, status = 200, extraHeaders = {}) {
  return new Response(
    JSON.stringify(data),
    {
      status,
      headers: {
        "Content-Type":
          "application/json; charset=utf-8",

        "Cache-Control":
          "no-store",

        ...extraHeaders
      }
    }
  );
}
