// src/pages/api/register.ts
export const prerender = false;
import type { APIRoute } from 'astro';

export const POST: APIRoute = async ({ request, env }) => {
  const formData = await request.formData();
  const email = formData.get('email')?.toString();
  const provider = formData.get('provider')?.toString();
  const tenantId = formData.get('tenantId')?.toString();

  if (!email || !provider) {
    return new Response('Missing fields', { status: 400 });
  }

  const domain = email.split('@')[1].toLowerCase();
  
  // Save to KV for Admin Review
  // Ensure you have a KV Namespace bound as 'SSII_KV' in Cloudflare Dashboard
  if (env.SSII_KV) {
    await env.SSII_KV.put(`pending:${domain}`, JSON.stringify({
      email, provider, tenantId, status: 'pending', date: new Date().toISOString()
    }));
  }

  return new Response(null, { 
    status: 302, 
    headers: { Location: '/register?status=success' } 
  });
};   
