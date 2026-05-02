import { createClient } from '@supabase/supabase-js';
import { z } from 'zod';

const supabase = createClient(
  process.env.SUPABASE_URL,
  process.env.SUPABASE_SERVICE_KEY,
  { auth: { persistSession: false } }
);

// validação
const BodySchema = z.object({
  discord_id: z.string().min(10).max(32),
  hwid: z.string().min(16).max(256),
  app: z.string().max(64).optional(),
  version: z.string().max(32).optional(),
});

function json(res, code, obj) {
  res.statusCode = code;
  res.setHeader('Content-Type', 'application/json; charset=utf-8');
  res.end(JSON.stringify(obj));
}

export default async function handler(req, res) {
  if (req.method !== 'POST') {
    res.setHeader('Allow', 'POST');
    return json(res, 405, { allowed: false, reason: 'method_not_allowed' });
  }

  let body;
  try {
    body = typeof req.body === 'string' ? JSON.parse(req.body) : req.body;
  } catch {
    return json(res, 400, { allowed: false, reason: 'bad_json' });
  }

  const parsed = BodySchema.safeParse(body);
  if (!parsed.success) return json(res, 400, { allowed: false, reason: 'bad_request' });

  const ip = (req.headers['x-forwarded-for'] || '').toString().split(',')[0].trim();
  const { discord_id, hwid } = parsed.data;

  const { data: lic, error } = await supabase
    .from('licenses')
    .select('discord_id,status,expires_at,hwid,product')
    .eq('discord_id', discord_id)
    .maybeSingle();

  if (error) return json(res, 500, { allowed: false, reason: 'server_error' });
  if (!lic) return json(res, 403, { allowed: false, reason: 'not_found' });

  if (lic.status !== 'active') return json(res, 403, { allowed: false, reason: 'not_active' });

  if (lic.expires_at && new Date(lic.expires_at).getTime() < Date.now()) {
    return json(res, 403, { allowed: false, reason: 'expired' });
  }

  // HWID lock: primeiro bind
  if (!lic.hwid) {
    const { error: upErr } = await supabase
      .from('licenses')
      .update({ hwid, hwid_set_at: new Date().toISOString(), last_ip: ip, last_seen_at: new Date().toISOString() })
      .eq('discord_id', discord_id)
      .is('hwid', null);

    if (upErr) return json(res, 500, { allowed: false, reason: 'server_error' });

    return json(res, 200, { allowed: true, first_bind: true, product: lic.product ?? null, expires_at: lic.expires_at ?? null });
  }

  // já bindado: precisa bater
  if (lic.hwid !== hwid) {
    await supabase.from('licenses').update({ last_ip: ip, last_seen_at: new Date().toISOString() }).eq('discord_id', discord_id);
    return json(res, 403, { allowed: false, reason: 'hwid_mismatch' });
  }

  await supabase.from('licenses').update({ last_ip: ip, last_seen_at: new Date().toISOString() }).eq('discord_id', discord_id);
  return json(res, 200, { allowed: true, first_bind: false, product: lic.product ?? null, expires_at: lic.expires_at ?? null });
}
