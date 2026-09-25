import { Hono } from 'hono';
import { GmailAdapter } from './adapters/gmail';
import { GraphAdapter } from './adapters/graph';
import { ImapAdapter } from './adapters/imap';
import { encrypt, decrypt } from './crypto';
import { getCookie, setCookie } from 'hono/cookie';

type Env = {
  DB: D1Database;
  TOKEN_KV: KVNamespace;
  ADMIN_PASSWORD: string;
  COOKIE_SECRET: string;
  GOOGLE_CLIENT_ID: string;
  GOOGLE_CLIENT_SECRET: string;
  MS_CLIENT_ID: string;
  MS_CLIENT_SECRET: string;
};

const app = new Hono<{ Bindings: Env }>();

app.get('/', async (c) => {
  return c.env.ASSETS.fetch(c.req.raw);
});

app.get('/api/config', (c) => {
  return c.json({
    googleClientId: c.env.GOOGLE_CLIENT_ID,
    msClientId: c.env.MS_CLIENT_ID
  });
});

app.post('/api/login', async (c) => {
  const body = await c.req.json();
  if (body.password === c.env.ADMIN_PASSWORD) {
    const sessionId = crypto.randomUUID();
    await c.env.TOKEN_KV.put('session:' + sessionId, 'admin', { expirationTtl: 604800 });
    setCookie(c, 'session_id', sessionId, { path: '/', httpOnly: true, secure: true, maxAge: 604800, sameSite: 'Strict' });
    return c.json({ success: true });
  }
  return c.json({ success: false, error: '密码错误' }, 401);
});

app.post('/api/logout', async (c) => {
  const sessionId = getCookie(c, 'session_id');
  if (sessionId) await c.env.TOKEN_KV.delete('session:' + sessionId);
  setCookie(c, 'session_id', '', { path: '/', maxAge: 0 });
  return c.json({ success: true });
});

app.use('/api/*', async (c, next) => {
  if (c.req.path === '/api/login' || c.req.path === '/api/logout') return await next();
  const sessionId = getCookie(c, 'session_id');
  if (!sessionId) return c.json({ error: '未登录' }, 401);
  const isValid = await c.env.TOKEN_KV.get('session:' + sessionId);
  if (isValid !== 'admin') return c.json({ error: '登录已过期，请重新登录' }, 401);
  await next();
});

app.delete('/api/accounts/:id', async (c) => {
  const id = c.req.param('id');
  await c.env.DB.prepare('DELETE FROM accounts WHERE id = ?').bind(id).run();
  return c.json({ success: true });
});

app.get('/api/accounts', async (c) => {
  const { results } = await c.env.DB.prepare(
    'SELECT id, email, display_name, provider, enabled FROM accounts ORDER BY created_at DESC'
  ).all();
  return c.json(results);
});

app.post('/api/accounts/imap', async (c) => {
  const body = await c.req.json();
  
  // 1. 真实验证连接（核心修复！）
  try {
    const adapter = new ImapAdapter(body.imap_host, body.imap_port, body.smtp_host, body.smtp_port, body.email, body.password);
    await adapter.fetchInbox(1); // 尝试拉取1封邮件
  } catch (err: any) {
    return c.json({ error: '连接邮箱失败，请检查服务器地址、端口或授权码。原因: ' + err.message }, 400);
  }

  // 2. 验证通过才存库
  const id = crypto.randomUUID();
  const encrypted = await encrypt(body.password, c.env.COOKIE_SECRET);
  await c.env.DB.prepare(
    `INSERT INTO accounts (id, email, provider, imap_host, imap_port, smtp_host, smtp_port, auth_type, encrypted_password, created_at)
     VALUES (?, ?, 'imap', ?, ?, ?, ?, 'password', ?, ?)`
  ).bind(id, body.email, body.imap_host, body.imap_port, body.smtp_host, body.smtp_port, encrypted, Date.now()).run();
  return c.json({ id, email: body.email });
});

app.get('/api/accounts/:id/messages', async (c) => {
  const account = await c.env.DB.prepare('SELECT * FROM accounts WHERE id = ?')
    .bind(c.req.param('id')).first() as any;
  if (!account) return c.json({ error: 'Account not found' }, 404);

  let messages: any[] = [];

  if (account.provider === 'gmail') {
    const adapter = new GmailAdapter(
      account.oauth_refresh_token, c.env.GOOGLE_CLIENT_ID, c.env.GOOGLE_CLIENT_SECRET
    );
    const ids = await adapter.listMessages(20);
    for (const m of ids.slice(0, 10)) {
      messages.push(await adapter.getMessage(m.id));
    }
  } else if (account.provider === 'outlook') {
    const adapter = new GraphAdapter(
      account.oauth_refresh_token, c.env.MS_CLIENT_ID, c.env.MS_CLIENT_SECRET
    );
    messages = await adapter.listMessages(20);
  } else {
    const adapter = new ImapAdapter(
      account.imap_host, account.imap_port,
      account.smtp_host, account.smtp_port,
      account.email,
      await decrypt(account.encrypted_password, c.env.COOKIE_SECRET)
    );
    messages = await adapter.fetchInbox(10);
  }

  return c.json(messages);
});

app.post('/api/accounts/:id/send', async (c) => {
  const account = await c.env.DB.prepare('SELECT * FROM accounts WHERE id = ?')
    .bind(c.req.param('id')).first() as any;
  const { to, subject, body } = await c.req.json();

  if (account.provider === 'gmail') {
    const adapter = new GmailAdapter(
      account.oauth_refresh_token, c.env.GOOGLE_CLIENT_ID, c.env.GOOGLE_CLIENT_SECRET
    );
    await adapter.sendMessage(to, subject, body);
  } else if (account.provider === 'outlook') {
    const adapter = new GraphAdapter(
      account.oauth_refresh_token, c.env.MS_CLIENT_ID, c.env.MS_CLIENT_SECRET
    );
    await adapter.sendMessage(to, subject, body);
  } else {
    const adapter = new ImapAdapter(
      account.imap_host, account.imap_port,
      account.smtp_host, account.smtp_port,
      account.email,
      await decrypt(account.encrypted_password, c.env.COOKIE_SECRET)
    );
    await adapter.sendMail(to, subject, body);
  }

  return c.json({ success: true });
});

app.get('/oauth/gmail/callback', async (c) => {
  try {
    const code = c.req.query('code');
    if (!code) return c.text('错误: 没有收到 code 参数', 400);

    const redirectUri = new URL(c.req.url).origin + '/oauth/gmail/callback';

    const res = await fetch('https://oauth2.googleapis.com/token', {
      method: 'POST',
      body: new URLSearchParams({
        code: code,
        client_id: c.env.GOOGLE_CLIENT_ID,
        client_secret: c.env.GOOGLE_CLIENT_SECRET,
        redirect_uri: redirectUri,
        grant_type: 'authorization_code',
      }),
    });

    const data: any = await res.json();
    if (!res.ok) {
      return c.text('Google 换 Token 失败: ' + JSON.stringify(data), 400);
    }

    // 🚨 关键安全检查：如果 Google 没给 refresh_token，直接拦截！
    if (!data.refresh_token) {
      return c.text('授权失败：未能获取到 Refresh Token。这通常是因为你之前授权过。请前往 Google 账号设置 -> 安全性 -> 第三方应用，删除本应用的授权，然后再重新试一次！', 400);
    }

    const profile = await fetch('https://www.googleapis.com/oauth2/v2/userinfo', {
      headers: { Authorization: 'Bearer ' + data.access_token },
    });
    const profileData: any = await profile.json();
    // 新版接口返回的是 email
    const email = profileData.email;

    if (!email) {
      return c.text('授权失败：无法获取 Gmail 邮箱地址，请重试。', 400);
    }

    const id = crypto.randomUUID();
    await c.env.DB.prepare(
      "INSERT INTO accounts (id, email, provider, auth_type, oauth_refresh_token, created_at) VALUES (?, ?, 'gmail', 'oauth', ?, ?)"
    ).bind(id, email, data.refresh_token, Date.now()).run();

    return c.redirect('/');
  } catch (err: any) {
    return c.text('Worker 严重崩溃: ' + err.message, 500);
  }
});

app.get('/oauth/ms/callback', async (c) => {
  const code = c.req.query('code');
  const res = await fetch('https://login.microsoftonline.com/common/oauth2/v2.0/token', {
    method: 'POST',
    body: new URLSearchParams({
      code: code!, client_id: c.env.MS_CLIENT_ID, client_secret: c.env.MS_CLIENT_SECRET,
      redirect_uri: `${new URL(c.req.url).origin}/oauth/ms/callback`,
      grant_type: 'authorization_code',
      scope: 'https://graph.microsoft.com/Mail.ReadWrite https://graph.microsoft.com/Mail.Send offline_access User.Read'
    }),
  });
  const data = await res.json() as any;
  const profile = await fetch('https://graph.microsoft.com/v1.0/me', { headers: { Authorization: `Bearer ${data.access_token}` } });
  const profileData = await profile.json() as any;
  const email = profileData.mail || profileData.userPrincipalName;

  const id = crypto.randomUUID();
  await c.env.DB.prepare(
    `INSERT INTO accounts (id, email, provider, auth_type, oauth_refresh_token, created_at) VALUES (?, ?, 'outlook', 'oauth', ?, ?)`
  ).bind(id, email, data.refresh_token, Date.now()).run();
  return c.redirect('/');
});

export default app;
