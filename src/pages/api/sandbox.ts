// src/pages/api/sandbox.ts
export const prerender = false;
import type { APIRoute } from 'astro';
import { runScoringEngine, type PaddedStreamNode } from '../../lib/scoring-engine';

export const POST: APIRoute = async ({ request }) => {
  try {
    const body = await request.json();
    const { paddedStream, threatIntelVector } = body;

    // Validate input
    if (!Array.isArray(paddedStream)) {
      return new Response(JSON.stringify({ error: 'Invalid paddedStream' }), { status: 400 });
    }

    // Execute scoring engine synchronously
    // This uses the exact same logic as ssii-consumer.ts but runs immediately
    const result = runScoringEngine(paddedStream as PaddedStreamNode[], threatIntelVector || [0, 0, 0]);

    return new Response(JSON.stringify(result), { 
      status: 200,
      headers: { 'Content-Type': 'application/json' } 
    });
  } catch (err) {
    console.error('[Sandbox API] Error:', err);
    return new Response(JSON.stringify({ error: (err as Error).message }), { status: 500 });
  }
};   