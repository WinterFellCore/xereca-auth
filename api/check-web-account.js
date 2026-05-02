import { createClient } from '@supabase/supabase-js';
import { z } from 'zod';

const supabase = createClient(
  process.env.SUPABASE_URL,
  process.env.SUPABASE_SERVICE_KEY,
  { auth: { persistSession: false } }
);

const BodySchema = z.object({
  discord_id: z.string().min(10).max(32),
});

function json(res, code, obj) {
  res.statusCode = code;
  res.setHeader('Content-Type', 'application/json; charset=utf-8');
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'POST, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type');
  res.end(JSON.stringify(obj));
}

export default async function handler(req, res) {
  // CORS preflight
  if (req.method === 'OPTIONS') {
    res.statusCode = 200;
    res.setHeader('Access-Control-Allow-Origin', '*');
    res.setHeader('Access-Control-Allow-Methods', 'POST, OPTIONS');
    res.setHeader('Access-Control-Allow-Headers', 'Content-Type');
    return res.end();
  }

  if (req.method !== 'POST') {
    res.setHeader('Allow', 'POST');
    return json(res, 405, { success: false, message: 'method_not_allowed' });
  }

  let body;
  try {
    body = typeof req.body === 'string' ? JSON.parse(req.body) : req.body;
  } catch {
    return json(res, 400, { success: false, message: 'bad_json' });
  }

  const parsed = BodySchema.safeParse(body);
  if (!parsed.success) {
    return json(res, 400, { success: false, message: 'bad_request' });
  }

  const { discord_id } = parsed.data;

  try {
    // Buscar usuário no banco
    const { data: user, error } = await supabase
      .from('licenses')
      .select('discord_id, status, expires_at, has_web_account, username')
      .eq('discord_id', discord_id)
      .maybeSingle();

    if (error) {
      console.error('Database error:', error);
      return json(res, 500, { success: false, message: 'server_error' });
    }

    // Discord ID não existe no banco
    if (!user) {
      return json(res, 404, { 
        success: false, 
        message: 'Discord ID não encontrado. Entre em contato com o suporte.',
        can_register: false,
      });
    }

    // Licença não está ativa
    if (user.status !== 'active') {
      return json(res, 403, { 
        success: false, 
        message: 'Sua licença não está ativa. Entre em contato com o suporte.',
        can_register: false,
      });
    }

    // Licença expirada
    if (user.expires_at && new Date(user.expires_at).getTime() < Date.now()) {
      return json(res, 403, { 
        success: false, 
        message: 'Sua licença expirou. Renove para continuar.',
        can_register: false,
      });
    }

    // Já tem conta web
    if (user.has_web_account) {
      return json(res, 200, { 
        success: true, 
        can_register: false,
        has_account: true,
        message: 'Este Discord ID já possui uma conta. Faça login.',
      });
    }

    // Pode criar conta
    return json(res, 200, { 
      success: true, 
      can_register: true,
      has_account: false,
      message: 'Discord ID válido! Você pode criar sua conta.',
      expires_at: user.expires_at,
    });

  } catch (error) {
    console.error('Check web account error:', error);
    return json(res, 500, { success: false, message: 'server_error' });
  }
}
