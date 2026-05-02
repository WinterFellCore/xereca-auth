import { createClient } from '@supabase/supabase-js';

const supabase = createClient(
  process.env.SUPABASE_URL,
  process.env.SUPABASE_SERVICE_KEY,
  { auth: { persistSession: false } }
);

function json(res, code, obj) {
  res.statusCode = code;
  res.setHeader('Content-Type', 'application/json; charset=utf-8');
  res.end(JSON.stringify(obj));
}

export default async function handler(req, res) {
  if (req.method !== 'POST') {
    res.setHeader('Allow', 'POST');
    return json(res, 405, { ok: false });
  }

  const adminKey = req.headers['x-admin-key'];
  if (!adminKey || adminKey !== process.env.ADMIN_KEY) return json(res, 401, { ok: false });

  let body;
  try {
    body = typeof req.body === 'string' ? JSON.parse(req.body) : req.body;
  } catch {
    return json(res, 400, { ok: false });
  }

  const discord_id = body?.discord_id;
  if (!discord_id) return json(res, 400, { ok: false });

  const { error } = await supabase
    .from('licenses')
    .update({ hwid: null, hwid_set_at: null })
    .eq('discord_id', discord_id);

  if (error) return json(res, 500, { ok: false });

  return json(res, 200, { ok: true });
}
