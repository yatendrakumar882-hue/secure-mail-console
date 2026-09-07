export default {
  async fetch(request, env, ctx) {
    return new Response(
      JSON.stringify({ 
        status: "active", 
        engine: "secure-mail-console", 
        relay: "vercel-node-production" 
      }),
      { 
        status: 200, 
        headers: { "content-type": "application/json" } 
      }
    );
  }
};
