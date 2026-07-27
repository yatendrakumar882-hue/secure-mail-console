export default {
  async fetch(request, env, ctx) {
    // 1. Basic Routing / Health Check
    const url = new URL(request.url);

    if (url.pathname === "/health") {
      return new Response(JSON.stringify({ status: "OK", timestamp: Date.now() }), {
        status: 200,
        headers: getSecurityHeaders("application/json"),
      });
    }

    try {
      // Direct response or your main application logic here
      const responseBody = JSON.stringify({
        message: "Worker running securely!",
      });

      return new Response(responseBody, {
        status: 200,
        headers: getSecurityHeaders("application/json"),
      });
    } catch (err) {
      // Generic error response so internal details don't leak
      return new Response(
        JSON.stringify({ error: "Internal Server Error" }),
        { status: 500, headers: getSecurityHeaders("application/json") }
      );
    }
  },
};

// Helper function to append Security Headers
function getSecurityHeaders(contentType = "text/plain") {
  return {
    "Content-Type": contentType,
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "strict-origin-when-cross-origin",
    "Content-Security-Policy": "default-src 'none'; frame-ancestors 'none';",
    "Strict-Transport-Security": "max-age=31536000; includeSubDomains; preload",
    // Modern CORS setting (In production, replace '*' with your specific origin domain)
    "Access-Control-Allow-Origin": "*",
    "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
    "Access-Control-Allow-Headers": "Content-Type, Authorization",
  };
}
