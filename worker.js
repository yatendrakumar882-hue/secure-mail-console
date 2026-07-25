import { connect } from 'cloudflare:sockets';

const TURNSTILE_SECRET = process.env.TURNSTILE_SECRET || '1x0000000000000000000000000000000AA';
const SMTP_PORT = 465;
const SMTP_HOST = 'smtp.gmail.com';

const corsHeaders = {
    'Access-Control-Allow-Origin': '*',
    'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
    'Access-Control-Allow-Headers': 'Content-Type',
};

export default {
    async fetch(request) {
        if (request.method === 'OPTIONS') {
            return new Response(null, { headers: corsHeaders });
        }

        const url = new URL(request.url);

        try {
            if (url.pathname === '/api/verify' && request.method === 'POST') {
                return await handleVerify(request);
            }
            return new Response('API Running', { headers: corsHeaders });
        } catch (err) {
            return new Response(JSON.stringify({ success: false, message: err.message }), {
                status: 500,
                headers: { 'Content-Type': 'application/json', ...corsHeaders }
            });
        }
    }
};

async function handleVerify(request) {
    const { email, appPassword } = await request.json();
    if (!email || !appPassword) {
        return new Response(JSON.stringify({ success: false, message: "Missing credentials" }), {
            status: 400,
            headers: { 'Content-Type': 'application/json', ...corsHeaders }
        });
    }
    return new Response(JSON.stringify({ success: true }), {
        headers: { 'Content-Type': 'application/json', ...corsHeaders }
    });
}
