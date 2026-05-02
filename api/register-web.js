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
  username: z.string().min(3).max(20),
  password: z.string().min(6).max(100),
  hwid: z.string().max(256).optional().nullable(),
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
    return json(res, 400, { 
      success: false, 
      message: 'Dados inválidos',
      errors: parsed.error.errors,
    });
  }

  const { discord_id, username, password, hwid } = parsed.data;

  try {
    // 1. Verificar se Discord ID existe e pode criar conta
    const { data: user, error: fetchError } = await supabase
      .from('licenses')
      .select('discord_id, status, expires_at, has_web_account, username')
      .eq('discord_id', discord_id)
      .maybeSingle();

    if (fetchError) {
      console.error('Database fetch error:', fetchError);
      return json(res, 500, { success: false, message: 'server_error' });
    }

    if (!user) {
      return json(res, 404, { 
        success: false, 
        message: 'Discord ID não encontrado no sistema',
      });
    }

    if (user.status !== 'active') {
      return json(res, 403, { 
        success: false, 
        message: 'Licença não está ativa',
      });
    }

    if (user.expires_at && new Date(user.expires_at).getTime() < Date.now()) {
      return json(res, 403, { 
        success: false, 
        message: 'Licença expirada',
      });
    }

    if (user.has_web_account) {
      return json(res, 409, { 
        success: false, 
        message: 'Este Discord ID já possui uma conta web',
      });
    }

    // 2. Verificar se username já existe
    const { data: existingUsername } = await supabase
      .from('licenses')
      .select('username')
      .eq('username', username)
      .neq('discord_id', discord_id)
      .maybeSingle();

    if (existingUsername) {
      return json(res, 409, { 
        success: false, 
        message: 'Username já está em uso',
      });
    }

    // 3. Hash da senha
    const password_hash = await bcrypt.hash(password, 10);

    // 4. Atualizar usuário no banco
    const { data: updatedUser, error: updateError } = await supabase
      .from('licenses')
      .update({
        has_web_account: true,
        username: username,
        password_hash: password_hash,
        hwid: hwid || null,
        web_account_created_at: new Date().toISOString(),
        updated_at: new Date().toISOString(),
      })
      .eq('discord_id', discord_id)
      .eq('has_web_account', false) // Double-check para evitar race condition
      .select()
      .single();

    if (updateError) {
      console.error('Database update error:', updateError);
      
      // Se falhou porque já tem conta (race condition)
      if (updateError.code === 'PGRST116') {
        return json(res, 409, { 
          success: false, 
          message: 'Este Discord ID já possui uma conta web',
        });
      }
      
      return json(res, 500, { success: false, message: 'Erro ao criar conta' });
    }

    // 5. Gerar token JWT
    const token = jwt.sign(
      { 
        discord_id: updatedUser.discord_id,
        username: updatedUser.username,
      },
      process.env.JWT_SECRET || 'your-secret-key-change-this',
      { expiresIn: '7d' }
    );

    // 6. Retornar sucesso
    return json(res, 201, {
      success: true,
      message: 'Conta criada com sucesso!',
      token: token,
      user: {
        discord_id: updatedUser.discord_id,
        username: updatedUser.username,
        expires_at: updatedUser.expires_at,
        is_active: updatedUser.status === 'active',
      },
    });

  } catch (error) {
    console.error('Register web error:', error);
    return json(res, 500, { success: false, message: 'server_error' });
  }
}
