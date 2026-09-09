export default {
  async fetch(request, env, ctx) {
    if (env.ASSETS) {
      return env.ASSETS.fetch(request);
    }
    return new Response(
      JSON.stringify({ status: "active", engine: "secure-mail-console" }),
      { status: 200, headers: { "Content-Type": "application/json" } }
    );
  }
};
