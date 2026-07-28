export default {
  async fetch(request, env, ctx) {
    return new Response(JSON.stringify({ status: "OK", service: "Secure Mail Worker" }), {
      status: 200,
      headers: { "Content-Type": "application/json" }
    });
  }
};
