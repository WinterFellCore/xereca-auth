import { createClient } from '@supabase/supabase-js';
import { z } from 'zod';
import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';

const supabase = createClient(
  process.env.SUPABASE_URL,
  process.env.SUPABASE_SERVICE_KEY,
  { auth: { persistSession: false } }
);

const BodySchema = z.object({
  discord_id: z.string().min(10).max(32),
  password: z.string().min(1).max(100),
});

function json(res, code, obj) {
  res.statusCode = code;
  res.setHeader('Content-Type', 'application/json; charset=utf-8');
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'POST, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type');
  res.setHeader('Access-Control-Max-Age', '86400');
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
    return json(res, 400, { 
      success: false, 
      message: 'Dados inválidos',
    });
  }

  const { discord_id, password } = parsed.data;
  const ip = (req.headers['x-forwarded-for'] || '').toString().split(',')[0].trim();

  try {
    // 1. Buscar usuário
    const { data: user, error: fetchError } = await supabase
      .from('licenses')
      .select('*')
      .eq('discord_id', discord_id)
      .maybeSingle();

    if (fetchError) {
      console.error('Database fetch error:', fetchError);
      return json(res, 500, { success: false, message: 'server_error' });
    }

    if (!user) {
      return json(res, 401, { 
        success: false, 
        message: 'Discord ID ou senha incorretos',
      });
    }

    // 2. Verificar se tem conta web
    if (!user.has_web_account || !user.password_hash) {
      return json(res, 401, { 
        success: false, 
        message: 'Você ainda não criou uma conta. Registre-se primeiro.',
      });
    }

    // 3. Verificar senha
    const passwordMatch = await bcrypt.compare(password, user.password_hash);
    if (!passwordMatch) {
      return json(res, 401, { 
        success: false, 
        message: 'Discord ID ou senha incorretos',
      });
    }

    // 4. Verificar status da licença
    if (user.status !== 'active') {
      return json(res, 403, { 
        success: false, 
        message: 'Sua licença não está ativa',
      });
    }

    if (user.expires_at && new Date(user.expires_at).getTime() < Date.now()) {
      return json(res, 403, { 
        success: false, 
        message: 'Sua licença expirou',
      });
    }

    // 5. Atualizar último login
    await supabase
      .from('licenses')
      .update({
        last_login_at: new Date().toISOString(),
        last_ip: ip,
        login_count: (user.login_count || 0) + 1,
      })
      .eq('discord_id', discord_id);

    // 6. Gerar token JWT
    const token = jwt.sign(
      { 
        discord_id: user.discord_id,
        username: user.username,
      },
      process.env.JWT_SECRET || 'your-secret-key-change-this',
      { expiresIn: '7d' }
    );

    // 7. Retornar sucesso
    return json(res, 200, {
      success: true,
      message: 'Login realizado com sucesso!',
      token: token,
      user: {
        discord_id: user.discord_id,
        username: user.username,
        global_name: user.global_name || user.username,
        avatar_url: user.avatar_url || '',
        expires_at: user.expires_at,
        is_active: user.status === 'active',
      },
    });

  } catch (error) {
    console.error('Login web error:', error);
    return json(res, 500, { success: false, message: 'server_error' });
  }
}
