const SESSION_DAYS = 14;
const PBKDF2_ITERATIONS = 310000;
const encoder = new TextEncoder();

function json(data, status = 200, extraHeaders = {}) {
  return new Response(JSON.stringify(data), {
    status,
    headers: {
      "content-type": "application/json; charset=utf-8",
      "cache-control": "no-store",
      "x-content-type-options": "nosniff",
      ...extraHeaders,
    },
  });
}

function corsHeaders(request) {
  const origin = request.headers.get("Origin");
  const url = new URL(request.url);
  const allowed = origin && new URL(origin).host === url.host ? origin : url.origin;
  return {
    "access-control-allow-origin": allowed,
    "access-control-allow-credentials": "true",
    "access-control-allow-methods": "GET, POST, PUT, DELETE, OPTIONS",
    "access-control-allow-headers": "Content-Type",
    "vary": "Origin",
  };
}

function withCors(response, request) {
  const headers = new Headers(response.headers);
  for (const [key, value] of Object.entries(corsHeaders(request))) headers.set(key, value);
  return new Response(response.body, { status: response.status, headers });
}

async function readJson(request) {
  try {
    const body = await request.json();
    return body && typeof body === "object" && !Array.isArray(body) ? body : null;
  } catch {
    return null;
  }
}

function randomToken(bytes = 32) {
  const raw = crypto.getRandomValues(new Uint8Array(bytes));
  return btoa(String.fromCharCode(...raw)).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
}

async function sha256(text) {
  const digest = await crypto.subtle.digest("SHA-256", encoder.encode(text));
  return [...new Uint8Array(digest)].map(b => b.toString(16).padStart(2, "0")).join("");
}

async function passwordHash(password, salt = randomToken(16)) {
  const material = await crypto.subtle.importKey("raw", encoder.encode(password), "PBKDF2", false, ["deriveBits"]);
  const bits = await crypto.subtle.deriveBits(
    { name: "PBKDF2", salt: encoder.encode(salt), iterations: PBKDF2_ITERATIONS, hash: "SHA-256" },
    material,
    256
  );
  return { salt, hash: [...new Uint8Array(bits)].map(b => b.toString(16).padStart(2, "0")).join("") };
}

function cookieValue(request, name) {
  const cookie = request.headers.get("Cookie") || "";
  const part = cookie.split(";").map(v => v.trim()).find(v => v.startsWith(name + "="));
  return part ? decodeURIComponent(part.slice(name.length + 1)) : null;
}

function sessionCookie(token, maxAge = SESSION_DAYS * 86400) {
  return `dhark_session=${encodeURIComponent(token)}; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=${maxAge}`;
}

async function currentUser(request, env) {
  const token = cookieValue(request, "dhark_session");
  if (!token) return null;
  const tokenHash = await sha256(token);
  return env.DB.prepare(
    "SELECT u.id, u.username, u.display_name, u.area FROM sessions s JOIN users u ON u.id=s.user_id WHERE s.token_hash=? AND s.expires_at > unixepoch()"
  ).bind(tokenHash).first();
}

async function requireUser(request, env) {
  const user = await currentUser(request, env);
  return user ? { user } : { response: json({ error: "Não autenticado." }, 401) };
}

async function handleApi(request, env) {
  if (!env.DB) return json({ error: "Banco D1 não conectado. Configure o binding DB no Worker." }, 503);
  const url = new URL(request.url);
  const path = url.pathname;
  if (request.method === "OPTIONS") return new Response(null, { status: 204, headers: corsHeaders(request) });

  if (path === "/api/health" && request.method === "GET") {
    try {
      await env.DB.prepare("SELECT 1 AS ok").first();
      return json({ ok: true, service: "dhark-library-api" });
    } catch {
      return json({ ok: false, error: "Banco ainda não inicializado. Execute migrations/0001_schema.sql." }, 503);
    }
  }

  if (path === "/api/setup" && request.method === "POST") {
    if (!env.BOOTSTRAP_KEY) return json({ error: "Configure o segredo BOOTSTRAP_KEY antes da inicialização." }, 503);
    const provided = request.headers.get("X-Setup-Key") || "";
    if (provided.length < 20 || provided !== env.BOOTSTRAP_KEY) return json({ error: "Chave de inicialização inválida." }, 403);
    const body = await readJson(request);
    if (!body || !Array.isArray(body.users) || body.users.length !== 2) {
      return json({ error: "Envie exatamente os dois perfis iniciais." }, 400);
    }
    const existing = await env.DB.prepare("SELECT COUNT(*) AS total FROM users").first();
    if ((existing?.total || 0) > 0) return json({ error: "A inicialização já foi feita; endpoint bloqueado." }, 409);
    const normalized = body.users.map(u => ({
      username: String(u.username || "").trim().toLowerCase(),
      display_name: String(u.display_name || "").trim(),
      area: String(u.area || "").trim(),
      password: typeof u.password === "string" ? u.password : "",
    }));
    const allowed = new Set(["programacao", "vestibular"]);
    if (normalized.some(u => !/^[a-z0-9_-]{3,32}$/.test(u.username) || u.display_name.length < 1 || !allowed.has(u.area) || u.password.length < 8 || u.password.length > 128)) {
      return json({ error: "Dados inválidos. Usuários: 3–32 caracteres; senhas: 8–128 caracteres." }, 400);
    }
    if (new Set(normalized.map(u => u.username)).size !== 2 || new Set(normalized.map(u => u.area)).size !== 2) {
      return json({ error: "Os usuários e as áreas devem ser diferentes." }, 400);
    }
    const created = [];
    try {
      for (const u of normalized) {
        const { salt, hash } = await passwordHash(u.password);
        const id = crypto.randomUUID();
        await env.DB.prepare("INSERT INTO users (id, username, display_name, area, password_salt, password_hash, created_at) VALUES (?, ?, ?, ?, ?, ?, unixepoch())")
          .bind(id, u.username, u.display_name, u.area, salt, hash).run();
        created.push(id);
      }
      return json({ ok: true, message: "Perfis iniciais criados. Remova o segredo BOOTSTRAP_KEY após confirmar." }, 201);
    } catch {
      await env.DB.prepare("DELETE FROM users WHERE id IN (?, ?)").bind(created[0] || "", created[1] || "").run();
      return json({ error: "Não foi possível concluir a inicialização. Verifique a migration e tente novamente." }, 500);
    }
  }

  if (path === "/api/login" && request.method === "POST") {
    const body = await readJson(request);
    const username = String(body?.username || "").trim().toLowerCase();
    const password = typeof body?.password === "string" ? body.password : "";
    if (!/^[a-z0-9_-]{3,32}$/.test(username) || password.length < 1 || password.length > 128) {
      return json({ error: "Usuário ou senha inválidos." }, 400);
    }
    const user = await env.DB.prepare("SELECT id, username, display_name, area, password_salt, password_hash FROM users WHERE username=?").bind(username).first();
    if (!user) {
      await passwordHash(password, "constant-time-placeholder-salt");
      return json({ error: "Usuário ou senha inválidos." }, 401);
    }
    const computed = await passwordHash(password, user.password_salt);
    if (computed.hash !== user.password_hash) return json({ error: "Usuário ou senha inválidos." }, 401);
    const token = randomToken();
    const tokenHash = await sha256(token);
    await env.DB.prepare("INSERT INTO sessions (id, user_id, token_hash, expires_at, created_at) VALUES (?, ?, ?, unixepoch()+?, unixepoch())")
      .bind(crypto.randomUUID(), user.id, tokenHash, SESSION_DAYS * 86400).run();
    return json({ ok: true, user: { username: user.username, displayName: user.display_name, area: user.area } }, 200, {
      "set-cookie": sessionCookie(token),
    });
  }

  if (path === "/api/logout" && request.method === "POST") {
    const token = cookieValue(request, "dhark_session");
    if (token) await env.DB.prepare("DELETE FROM sessions WHERE token_hash=?").bind(await sha256(token)).run();
    return json({ ok: true }, 200, { "set-cookie": sessionCookie("", 0) });
  }

  if (path === "/api/me" && request.method === "GET") {
    const auth = await requireUser(request, env);
    if (auth.response) return auth.response;
    return json({ user: { username: auth.user.username, displayName: auth.user.display_name, area: auth.user.area } });
  }

  if (path === "/api/progress" && request.method === "GET") {
    const auth = await requireUser(request, env);
    if (auth.response) return auth.response;
    const rows = await env.DB.prepare("SELECT record_key, record_json, updated_at FROM progress WHERE user_id=? ORDER BY updated_at DESC")
      .bind(auth.user.id).all();
    return json({ progress: (rows.results || []).map(row => ({ key: row.record_key, value: JSON.parse(row.record_json), updatedAt: row.updated_at })) });
  }

  if (path === "/api/progress" && request.method === "PUT") {
    const auth = await requireUser(request, env);
    if (auth.response) return auth.response;
    const body = await readJson(request);
    const key = String(body?.key || "");
    if (!/^[a-zA-Z0-9_.:-]{1,100}$/.test(key) || body?.value === undefined) return json({ error: "Registro de progresso inválido." }, 400);
    const serialized = JSON.stringify(body.value);
    if (serialized.length > 50000) return json({ error: "Registro muito grande (máximo de 50 KB)." }, 413);
    await env.DB.prepare("INSERT INTO progress (user_id, record_key, record_json, updated_at) VALUES (?, ?, ?, unixepoch()) ON CONFLICT(user_id, record_key) DO UPDATE SET record_json=excluded.record_json, updated_at=excluded.updated_at")
      .bind(auth.user.id, key, serialized).run();
    return json({ ok: true });
  }

  if (path === "/api/progress" && request.method === "DELETE") {
    const auth = await requireUser(request, env);
    if (auth.response) return auth.response;
    const body = await readJson(request);
    const key = String(body?.key || "");
    if (!/^[a-zA-Z0-9_.:-]{1,100}$/.test(key)) return json({ error: "Chave inválida." }, 400);
    await env.DB.prepare("DELETE FROM progress WHERE user_id=? AND record_key=?").bind(auth.user.id, key).run();
    return json({ ok: true });
  }

  return json({ error: "Rota não encontrada." }, 404);
}

export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    if (url.pathname.startsWith("/api/")) {
      try {
        return withCors(await handleApi(request, env), request);
      } catch (error) {
        console.error("API error", error?.message || error);
        return withCors(json({ error: "Erro interno da API." }, 500), request);
      }
    }
    if (!env.ASSETS) return new Response("Configure o binding ASSETS para servir a aplicação.", { status: 503 });
    return env.ASSETS.fetch(request);
  },
};
