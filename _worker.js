const SESSION_DAYS = 14;
const PBKDF2_ITERATIONS = 100000;
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
    "SELECT u.id, u.username, u.display_name, u.area, u.role FROM sessions s JOIN users u ON u.id=s.user_id WHERE s.token_hash=? AND s.expires_at > unixepoch() AND u.status='active'"
  ).bind(tokenHash).first();
}

async function requireUser(request, env) {
  const user = await currentUser(request, env);
  return user ? { user } : { response: json({ error: "Não autenticado." }, 401) };
}


async function adminUser(request, env) {
 const auth=await requireUser(request,env); if(auth.response)return auth;
 const row=await env.DB.prepare("SELECT role,status FROM users WHERE id=?").bind(auth.user.id).first();
 if(!row||row.role!=="admin"||row.status!=="active")return {response:json({error:"Acesso restrito à conta administradora."},403)};
 return {user:auth.user};
}
function inviteCode(){return "DHL-"+randomToken(9).replace(/[-_]/g,"").toUpperCase();}

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


  if (path === "/api/admin/setup-status" && request.method === "GET") {
    try {
      const row = await env.DB.prepare("SELECT COUNT(*) AS total FROM users").first();
      return json({ initialized: (row?.total || 0) > 0 });
    } catch {
      return json({ error: "Não foi possível verificar a configuração." }, 503);
    }
  }

  if (path === "/api/admin/setup" && request.method === "POST") {
    if (!env.BOOTSTRAP_KEY) return json({error:"Configure BOOTSTRAP_KEY no Worker."},503);
    const provided=request.headers.get("X-Setup-Key")||"";
    if(provided.length<20||provided!==env.BOOTSTRAP_KEY)return json({error:"Chave de inicialização inválida."},403);
    try {
      const count=await env.DB.prepare("SELECT COUNT(*) AS total FROM users").first();
      if((count?.total||0)>0)return json({error:"A inicialização já foi feita."},409);
      const body=await readJson(request), username=String(body?.username||"").trim().toLowerCase(), displayName=String(body?.displayName||"").trim(), password=typeof body?.password==="string"?body.password:"";
      if(!/^[a-z0-9_-]{3,32}$/.test(username)||!displayName||password.length<8||password.length>128)return json({error:"Informe usuário válido, nome e senha de 8 a 128 caracteres."},400);
      const {salt,hash}=await passwordHash(password);
      await env.DB.prepare("INSERT INTO users (id,username,display_name,area,password_salt,password_hash,created_at,role,status) VALUES (?,?,?,'programacao',?,?,unixepoch(),'admin','active')").bind(crypto.randomUUID(),username,displayName,salt,hash).run();
      return json({ok:true,message:"Conta administradora criada. Remova BOOTSTRAP_KEY após confirmar."},201);
    } catch (error) {
      console.error("Admin setup failed", error?.stack || error?.message || error);
      return json({error:"Falha ao criar a conta administradora. Consulte os logs do Worker pelo evento Admin setup failed."},500);
    }
  }
  if (path === "/api/signup" && request.method === "POST") {
    const body=await readJson(request), code=String(body?.inviteCode||"").trim().toUpperCase(), username=String(body?.username||"").trim().toLowerCase(), displayName=String(body?.displayName||username).trim(), password=typeof body?.password==="string"?body.password:"", goal=String(body?.learningGoal||"").trim().slice(0,500), level=String(body?.level||""), area=String(body?.area||"programacao");
    if(!code||!/^[a-z0-9_-]{3,32}$/.test(username)||!displayName||password.length<8||password.length>128||!goal||!["basico","intermediario","curso_completo"].includes(level)||!["programacao","vestibular","outro"].includes(area))return json({error:"Confira o convite e preencha todos os campos. Senha: 8 a 128 caracteres."},400);
    const invite=await env.DB.prepare("SELECT id,max_uses,used_count FROM invites WHERE code_hash=? AND revoked_at IS NULL AND (expires_at IS NULL OR expires_at>unixepoch()) AND used_count<max_uses").bind(await sha256(code)).first();
    if(!invite)return json({error:"Convite inválido, expirado, revogado ou sem utilizações restantes."},403);
    const {salt,hash}=await passwordHash(password), id=crypto.randomUUID();
    try {
      await env.DB.prepare("INSERT INTO users (id,username,display_name,area,password_salt,password_hash,created_at,role,status) VALUES (?,?,?,?,?,?,unixepoch(),'user','active')").bind(id,username,displayName,area,salt,hash).run();
      await env.DB.prepare("INSERT INTO user_profiles (user_id,learning_goal,level) VALUES (?,?,?)").bind(id,goal,level).run();
      const use=await env.DB.prepare("UPDATE invites SET used_count=used_count+1 WHERE id=? AND revoked_at IS NULL AND used_count<max_uses").bind(invite.id).run();
      if(!use.meta?.changes){await env.DB.prepare("DELETE FROM users WHERE id=?").bind(id).run();return json({error:"Convite atingiu o limite. Peça outro código."},409);}
      return json({ok:true,message:"Conta criada. Você já pode entrar."},201);
    } catch(error) {
      await env.DB.prepare("DELETE FROM users WHERE id=?").bind(id).run();
      if(String(error?.message||"").includes("UNIQUE"))return json({error:"Nome de usuário já utilizado."},409);
      throw error;
    }
  }

  if (path === "/api/login" && request.method === "POST") {
    const body = await readJson(request);
    const username = String(body?.username || "").trim().toLowerCase();
    const password = typeof body?.password === "string" ? body.password : "";
    if (!/^[a-z0-9_-]{3,32}$/.test(username) || password.length < 1 || password.length > 128) {
      return json({ error: "Usuário ou senha inválidos." }, 400);
    }
    const user = await env.DB.prepare("SELECT id, username, display_name, area, password_salt, password_hash, status FROM users WHERE username=?").bind(username).first();
    if (!user) {
      await passwordHash(password, "constant-time-placeholder-salt");
      return json({ error: "Usuário ou senha inválidos." }, 401);
    }
    if(user.status!=="active")return json({error:"Esta conta está suspensa ou revogada."},403);
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

  if (path === "/api/account" && request.method === "DELETE") {
    const auth = await requireUser(request, env);
    if (auth.response) return auth.response;
    const body = await readJson(request);
    if (body?.confirm !== "DELETE MY ACCOUNT") return json({ error: "Confirmação inválida." }, 400);
    const userId = auth.user.id;
    // Explicitly remove user-owned records first, then invalidate every session and delete the account.
    await env.DB.batch([
      env.DB.prepare("DELETE FROM progress WHERE user_id=?").bind(userId),
      env.DB.prepare("DELETE FROM user_profiles WHERE user_id=?").bind(userId),
      env.DB.prepare("DELETE FROM sessions WHERE user_id=?").bind(userId),
      env.DB.prepare("DELETE FROM invites WHERE created_by=?").bind(userId),
      env.DB.prepare("DELETE FROM users WHERE id=?").bind(userId)
    ]);
    return json({ ok: true, deleted: true }, 200, { "set-cookie": sessionCookie("", 0) });
  }

  if (path === "/api/logout" && request.method === "POST") {
    const token = cookieValue(request, "dhark_session");
    if (token) await env.DB.prepare("DELETE FROM sessions WHERE token_hash=?").bind(await sha256(token)).run();
    return json({ ok: true }, 200, { "set-cookie": sessionCookie("", 0) });
  }


  if(path==="/api/admin/invites"&&request.method==="GET"){const a=await adminUser(request,env);if(a.response)return a.response;const r=await env.DB.prepare("SELECT id,code_hint,max_uses,used_count,created_at,expires_at,revoked_at FROM invites ORDER BY created_at DESC LIMIT 200").all();return json({invites:r.results||[]});}
  if(path==="/api/admin/invites"&&request.method==="POST"){const a=await adminUser(request,env);if(a.response)return a.response;const b=await readJson(request),type=b?.type==="single"?"single":b?.type==="multiple"?"multiple":"",max=type==="single"?1:Number(b?.maxUses);if(!type||!Number.isInteger(max)||max<1||max>10000)return json({error:"Escolha uso único ou limite entre 1 e 10000."},400);const code=inviteCode(),id=crypto.randomUUID();await env.DB.prepare("INSERT INTO invites (id,code_hash,code_hint,max_uses,used_count,created_by,created_at) VALUES (?,?,?,?,0,?,unixepoch())").bind(id,await sha256(code),code.slice(-4),max,a.user.id).run();return json({ok:true,invite:{id,code,maxUses:max,usedCount:0}},201);}
  if(path.startsWith("/api/admin/invites/")&&request.method==="DELETE"){const a=await adminUser(request,env);if(a.response)return a.response;const id=path.slice("/api/admin/invites/".length).replace(/\/+$/,"");if(!id)return json({error:"ID do convite ausente."},400);const before=await env.DB.prepare("SELECT id FROM invites WHERE id=?").bind(id).first();if(!before)return json({error:"Convite não encontrado ou já apagado."},404);await env.DB.prepare("DELETE FROM invites WHERE id=?").bind(id).run();const still=await env.DB.prepare("SELECT id FROM invites WHERE id=?").bind(id).first();if(still)return json({error:"O banco não confirmou a exclusão do convite."},500);return json({ok:true,deleted:true});}
  if(path==="/api/admin/users"&&request.method==="GET"){const a=await adminUser(request,env);if(a.response)return a.response;const r=await env.DB.prepare("SELECT u.id,u.username,u.display_name,u.area,u.status,u.created_at,p.learning_goal,p.level FROM users u LEFT JOIN user_profiles p ON p.user_id=u.id WHERE u.role='user' ORDER BY u.created_at DESC LIMIT 500").all();return json({users:r.results||[]});}
  if(path.startsWith("/api/admin/users/")&&["PUT","POST","DELETE"].includes(request.method)){
    const a=await adminUser(request,env);if(a.response)return a.response;
    const id=path.slice("/api/admin/users/".length).replace(/\/+$/,""),b=await readJson(request),status=request.method==="DELETE"?"revoked":b?.status;
    if(!id)return json({error:"ID da conta ausente."},400);
    if(!["active","suspended","revoked"].includes(status))return json({error:"Status inválido."},400);
    const user=await env.DB.prepare("SELECT id,status FROM users WHERE id=? AND role='user'").bind(id).first();
    if(!user)return json({error:"Conta não encontrada ou não é uma conta de usuário."},404);
    if(status==="revoked"){
      await env.DB.batch([
        env.DB.prepare("DELETE FROM progress WHERE user_id=?").bind(id),
        env.DB.prepare("DELETE FROM user_profiles WHERE user_id=?").bind(id),
        env.DB.prepare("DELETE FROM sessions WHERE user_id=?").bind(id),
        env.DB.prepare("DELETE FROM invites WHERE created_by=?").bind(id),
        env.DB.prepare("DELETE FROM users WHERE id=? AND role='user'").bind(id)
      ]);
      const still=await env.DB.prepare("SELECT id FROM users WHERE id=?").bind(id).first();
      if(still)return json({error:"O banco não confirmou a exclusão da conta."},500);
      return json({ok:true,status:"revoked",deleted:true,previousStatus:user.status});
    }
    await env.DB.prepare("UPDATE users SET status=? WHERE id=? AND role='user'").bind(status,id).run();
    if(status!=="active")await env.DB.prepare("DELETE FROM sessions WHERE user_id=?").bind(id).run();
    const after=await env.DB.prepare("SELECT status FROM users WHERE id=?").bind(id).first();
    if(after?.status!==status)return json({error:"O banco não confirmou a alteração de status."},500);
    return json({ok:true,status,previousStatus:user.status});
  }

  // Gemini: chave apenas no Worker; chamadas autenticadas e quota por usuário/dia.
  if (path === "/api/ai" && request.method === "POST") {
    const auth = await requireUser(request, env);
    if (auth.response) return auth.response;
    if (!env.GEMINI_API_KEY) return json({ error: "IA ainda não configurada. Configure o segredo GEMINI_API_KEY no Cloudflare." }, 503);
    const size = Number(request.headers.get("content-length") || 0);
    if (size > 18000) return json({ error: "Mensagem muito grande." }, 413);
    const b = await readJson(request);
    const mode = String(b?.mode || "");
    if (!["tutor", "lesson", "grade", "track"].includes(mode)) return json({ error: "Operação inválida." }, 400);
    const question = String(b?.question || "").trim().slice(0, 5000);
    const topic = String(b?.topic || "").trim().slice(0, 180);
    const level = String(b?.level || "iniciante").trim().slice(0, 40);
    const context = String(b?.context || "").trim().slice(0, 3500);
    const answer = String(b?.answer || "").trim().slice(0, 3500);
    if (!question || (mode === "grade" && !answer)) return json({ error: "Preencha os campos obrigatórios." }, 400);
    if (JSON.stringify(b).length > 18000) return json({ error: "Solicitação muito grande." }, 413);
    const day = new Date().toISOString().slice(0, 10);
    const quotaKey = "ai.daily." + day;
    // Incremento atômico evita ultrapassar o limite mesmo com várias abas.
    const quota = await env.DB.prepare(
      "INSERT INTO progress (user_id,record_key,record_json,updated_at) VALUES (?,?, '1',unixepoch()) ON CONFLICT(user_id,record_key) DO UPDATE SET record_json=CAST(CAST(progress.record_json AS INTEGER)+1 AS TEXT),updated_at=unixepoch() WHERE CAST(progress.record_json AS INTEGER)<30 RETURNING record_json"
    ).bind(auth.user.id, quotaKey).first();
    if (!quota) return json({ error: "Limite diário de 30 solicitações atingido. Tente novamente amanhã." }, 429);
    const instructions = {
      tutor: "Você é o tutor da Dhark Library. Responda em português brasileiro com didática, exemplos concretos e uma sugestão de exercício. Ajude a pessoa a pensar; não invente fatos. Se não tiver certeza, diga.",
      lesson: "Você é designer instrucional da Dhark Library. Crie uma aula original em português brasileiro sobre o tema solicitado, para o nível indicado. Use os títulos: Objetivo, Pré-requisitos, Explicação passo a passo, Exemplos, Atividade prática, Questões de revisão (3 perguntas), Próximos passos. O tema pode ser qualquer assunto educacional apropriado. Não afirme que a aula foi verificada por especialista.",
      track: 'Você cria trilhas educacionais personalizadas para qualquer área de estudo. Responda SOMENTE com JSON válido, sem markdown, no formato {"title":"...","modules":[{"title":"...","description":"...","lessons":[{"title":"...","content":"...","exercise":"..."}]}]}. Crie 4 módulos em ordem pedagógica, cada um com 2 aulas completas e originais, explicações em português brasileiro de 2 a 4 parágrafos por aula e um exercício. Personalize especificamente para o objetivo e dificuldades descritos, sem inserir programação se não for solicitada. Não use HTML. Não invente fontes.',
      grade: "Você é avaliador formativo da Dhark Library. Compare a pergunta e o contexto com a resposta do estudante. Retorne: Veredito (correta/parcial/incorreta/incerta), Justificativa, Pontos fortes, O que melhorar, Resposta-modelo. Considere respostas alternativas válidas e não afirme certeza quando a questão for ambígua. Não altere notas ou progresso."
    };
    const prompt = "Tema: " + topic + "\\nNível: " + level + "\\nPergunta ou objetivo: " + question + "\\nContexto fornecido: " + context + (mode === "grade" ? "\\nResposta do estudante: " + answer : "");
    // Descobrir modelos realmente habilitados para esta chave quando o padrão
    // retorna 404. Nunca enviar a chave ao navegador nem expor lista de modelos.
    const configuredModel = String(env.GEMINI_MODEL || "").replace("models/", "").trim();
    const preferred = !configuredModel || ["gemini-2.5-flash", "gemini-2.5-flash-lite", "gemini-2.0-flash", "gemini-1.5-flash"].includes(configuredModel) ? "gemini-3.5-flash-lite" : configuredModel;
    const payload = JSON.stringify({ systemInstruction: { parts: [{ text: instructions[mode] }] }, contents: [{ role: "user", parts: [{ text: prompt }] }], generationConfig: { temperature: mode === "grade" ? 0.2 : 0.6, maxOutputTokens: mode === "track" ? 8000 : mode === "lesson" ? 2500 : 1400 } });
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), 25000);
    let response;
    try {
      const invoke = model => fetch("https://generativelanguage.googleapis.com/v1beta/models/" + encodeURIComponent(model) + ":generateContent", {
        method: "POST",
        headers: { "content-type": "application/json", "x-goog-api-key": env.GEMINI_API_KEY },
        body: payload,
        signal: controller.signal
      });
      response = await invoke(preferred);
      if ([404, 429, 503].includes(response.status)) {
        // Em caso de modelo indisponível, cota ou sobrecarga, consultar
        // alternativas habilitadas para esta chave e tentar no máximo duas.
        const listing = await fetch("https://generativelanguage.googleapis.com/v1beta/models?pageSize=100", {
          headers: { "x-goog-api-key": env.GEMINI_API_KEY }, signal: controller.signal
        });
        if (listing.ok) {
          const available = await listing.json();
          const models = (available.models || []).filter(m => m.supportedGenerationMethods?.includes("generateContent")).map(m => String(m.name || "").replace("models/", ""));
          const priority = ["gemini-3.5-flash-lite", "gemini-3.5-flash", "gemini-3-flash"];
          const candidates = [...priority.filter(m => models.includes(m)), ...models.filter(m => /^gemini-3(?:\\.|-|$)/.test(m) && /flash/.test(m))].filter((m, i, all) => m !== preferred && all.indexOf(m) === i).slice(0, 2);
          for (const candidate of candidates) {
            console.log("Gemini model fallback", candidate);
            response = await invoke(candidate);
            if (response.ok || ![404, 429, 503].includes(response.status)) break;
          }
        } else {
          console.error("Gemini model discovery status", listing.status);
        }
      }
    } catch (error) {
      return json({ error: "Não foi possível conectar ao Gemini. Tente novamente." }, 502);
    } finally { clearTimeout(timeout); }
    if (!response.ok) {
      // Diagnóstico limitado a campos não sensíveis. Nunca retornar headers, chave ou corpo bruto.
      let providerCode = "", providerMessage = "";
      try {
        const failure = await response.json();
        providerCode = String(failure?.error?.status || "").slice(0, 60);
        providerMessage = String(failure?.error?.message || "").slice(0, 500);
      } catch (_) {}
      console.error("Gemini upstream", response.status, providerCode, providerMessage);
      const hints = {
        400: "O Gemini rejeitou a solicitação.",
        401: "A chave Gemini não foi aceita. Confira o segredo GEMINI_API_KEY no Cloudflare.",
        403: "A chave Gemini não tem permissão para usar esta API. Confira o Google AI Studio.",
        404: "O modelo Gemini não foi encontrado para esta versão da API.",
        429: "O Gemini atingiu o limite de uso ou de cota.",
        500: "O Gemini apresentou um erro temporário.",
        503: "O Gemini está temporariamente indisponível."
      };
      // Retornar só informações de diagnóstico específicas e sanitizadas.
      const safeDetail = providerMessage.replace(/AIza[0-9A-Za-z_-]+/g, "[chave oculta]").replace(/https?:[^ ]+/g, "[URL oculta]");
      return json({ error: (hints[response.status] || "Falha na comunicação com o Gemini.") + " HTTP " + response.status + (providerCode ? " (" + providerCode + ")" : "") + (safeDetail ? " — " + safeDetail : ""), providerStatus: response.status, providerCode }, response.status === 429 ? 429 : 502);
    }
    const data = await response.json();
    const text = (data.candidates?.[0]?.content?.parts || []).map(part => part.text || "").join("\\n").trim();
    if (!text) return json({ error: "O Gemini não retornou conteúdo para esta solicitação." }, 502);
    return json({ text: text.slice(0, mode === "track" ? 60000 : 22000), mode, remainingToday: Math.max(0, 30 - Number(quota.record_json)) });
  }

  if (path === "/api/study-profile" && request.method === "GET") {
    const auth = await requireUser(request, env);
    if (auth.response) return auth.response;
    const profile = await env.DB.prepare("SELECT learning_goal, level FROM user_profiles WHERE user_id=?").bind(auth.user.id).first();
    return json({ role: auth.user.role, area: auth.user.area, goal: profile?.learning_goal || "", level: profile?.level || "basico" });
  }

  if (path === "/api/me" && request.method === "GET") {
    const auth = await requireUser(request, env);
    if (auth.response) return auth.response;
    return json({ user: { id: auth.user.id, username: auth.user.username, displayName: auth.user.display_name, area: auth.user.area, role: auth.user.role } });
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
