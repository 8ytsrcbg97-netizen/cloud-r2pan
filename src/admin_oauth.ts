/**
 * 管理员 GitHub OAuth2 登录 —— 与访客下载鉴权（oauth_handlers.ts）完全独立。
 *
 * 功能:
 *   - 管理员在「安全中心」绑定自己的 GitHub 账号
 *   - 绑定后，登录后台可直接用 GitHub 登录，无需输入 admin 密钥
 *
 * 路由:
 *   GET  /admin/oauth/github/start     未登录时发起 GitHub 登录
 *   GET  /admin/oauth/callback         GitHub 回调（登录 / 绑定共用）
 *
 * 绑定入口走已鉴权的 POST /api/admin/oauth/github/bind-start（见 admin.ts），
 * 由它调用 buildAdminGitHubAuthorizeUrl 生成授权 URL —— 这样 state 本身即代表
 * 一次已登录管理员的授权发起，回调时无需依赖 cd_admin Cookie
 * （cd_admin 是 SameSite=Strict，跨站顶层跳转回来时不会携带）。
 *
 * 复用 oauth_states 表存 state（5 分钟 TTL、一次性消费防 CSRF），
 * 其 provider_id 字段存本次意图（admin_login / admin_bind）。
 */

import type { Env } from "./types";
import { getSettings, updateSettings } from "./settings";
import { decryptSecret } from "./crypto";
import { createSession, clientIp } from "./auth";
import { createOAuthState, verifyOAuthState } from "./oauth";
import { parseUA } from "./ua";

const GITHUB_AUTHORIZE_URL = "https://github.com/login/oauth/authorize";
const GITHUB_TOKEN_URL = "https://github.com/login/oauth/access_token";
const GITHUB_USER_URL = "https://api.github.com/user";
const GITHUB_SCOPE = "read:user";

/** state 意图 —— 存进 oauth_states.provider_id */
export const ADMIN_OAUTH_INTENT_LOGIN = "admin_login";
export const ADMIN_OAUTH_INTENT_BIND = "admin_bind";

/** 管理员 GitHub 回调地址（必须在 GitHub OAuth App 里登记为 Redirect URI） */
export function adminGitHubCallbackUrl(req: Request): string {
  return `${new URL(req.url).origin}/admin/oauth/callback`;
}

/** 生成 state 并构造 GitHub 授权 URL；未配置 Client ID 时返回 null */
export async function buildAdminGitHubAuthorizeUrl(
  env: Env,
  req: Request,
  intent: string
): Promise<string | null> {
  const s = await getSettings(env);
  if (!s.adminGhClientId) return null;
  const redirectUri = adminGitHubCallbackUrl(req);
  const state = await createOAuthState(env, intent, redirectUri);
  const params = new URLSearchParams({
    client_id: s.adminGhClientId,
    redirect_uri: redirectUri,
    scope: GITHUB_SCOPE,
    state,
    response_type: "code",
  });
  return `${GITHUB_AUTHORIZE_URL}?${params.toString()}`;
}

/** GET /admin/oauth/github/start —— 未登录时发起 GitHub 登录 */
export async function handleAdminGitHubStart(req: Request, env: Env): Promise<Response> {
  const s = await getSettings(env);
  if (!s.adminGhLoginEnabled || !s.adminGhUid || !s.adminGhClientId || !s.adminGhClientSecretCipher) {
    return redirectToAdmin(req, { github_error: "not_available" });
  }
  const authorizeUrl = await buildAdminGitHubAuthorizeUrl(env, req, ADMIN_OAUTH_INTENT_LOGIN);
  if (!authorizeUrl) return redirectToAdmin(req, { github_error: "not_available" });
  return new Response(null, { status: 302, headers: { location: authorizeUrl, "cache-control": "no-store" } });
}

/** GET /admin/oauth/callback —— GitHub 回调（登录 / 绑定共用） */
export async function handleAdminGitHubCallback(req: Request, env: Env): Promise<Response> {
  const url = new URL(req.url);
  const error = url.searchParams.get("error");
  const code = url.searchParams.get("code") || "";
  const state = url.searchParams.get("state") || "";
  if (error) return redirectToAdmin(req, { github_error: error });
  if (!code || !state) return redirectToAdmin(req, { github_error: "missing_code" });

  const verify = await verifyOAuthState(env, state);
  if (!verify.ok || !verify.provider_id) return redirectToAdmin(req, { github_error: "state_invalid" });
  const intent = verify.provider_id;
  const redirectUri = verify.redirect_uri || adminGitHubCallbackUrl(req);

  const s = await getSettings(env);
  if (!s.adminGhClientId || !s.adminGhClientSecretCipher) {
    return redirectToAdmin(req, { github_error: "not_configured" });
  }
  const clientSecret = await decryptSecret(s.adminGhClientSecretCipher, env.admin);
  if (!clientSecret) return redirectToAdmin(req, { github_error: "secret_decrypt_failed" });

  // code → access_token
  const token = await exchangeGithubCode(s.adminGhClientId, clientSecret, code, redirectUri);
  if (!token) return redirectToAdmin(req, { github_error: "exchange_failed" });

  // 拉取 GitHub 用户信息
  const user = await fetchGithubUser(token);
  if (!user) return redirectToAdmin(req, { github_error: "userinfo_failed" });

  // ── 绑定流程 ──
  if (intent === ADMIN_OAUTH_INTENT_BIND) {
    await updateSettings(env, {
      admin_gh_uid: user.id,
      admin_gh_login: user.login,
      admin_gh_name: user.name ?? "",
      admin_gh_avatar: user.avatar ?? "",
      admin_gh_bound_at: String(Date.now()),
    });
    return redirectToAdmin(req, { github: "bound" });
  }

  // ── 登录流程 ──
  if (intent !== ADMIN_OAUTH_INTENT_LOGIN) {
    return redirectToAdmin(req, { github_error: "bad_intent" });
  }
  if (!s.adminGhLoginEnabled) {
    return redirectToAdmin(req, { github_error: "disabled" });
  }
  if (!s.adminGhUid || s.adminGhUid !== user.id) {
    await writeLoginLog(env, req, "fail", "github_not_bound");
    return redirectToAdmin(req, { github_error: "not_bound" });
  }

  // 签发管理员会话 Cookie
  const cookie = await createSession(env, url.protocol === "https:");
  await writeLoginLog(env, req, "success", "github_oauth");
  return new Response(null, {
    status: 302,
    headers: { location: "/admin", "set-cookie": cookie, "cache-control": "no-store" },
  });
}

/* ═══════════ 辅助 ═══════════ */

interface GithubUser {
  id: string;
  login: string;
  name: string | null;
  avatar: string | null;
}

async function exchangeGithubCode(
  clientId: string,
  clientSecret: string,
  code: string,
  redirectUri: string
): Promise<string | null> {
  try {
    const resp = await fetch(GITHUB_TOKEN_URL, {
      method: "POST",
      headers: { "content-type": "application/x-www-form-urlencoded", accept: "application/json" },
      body: new URLSearchParams({ client_id: clientId, client_secret: clientSecret, code, redirect_uri: redirectUri }).toString(),
    });
    if (!resp.ok) return null;
    const j = (await resp.json()) as Record<string, unknown>;
    return j.access_token ? String(j.access_token) : null;
  } catch {
    return null;
  }
}

async function fetchGithubUser(accessToken: string): Promise<GithubUser | null> {
  try {
    const resp = await fetch(GITHUB_USER_URL, {
      headers: {
        authorization: `Bearer ${accessToken}`,
        accept: "application/vnd.github+json",
        // GitHub API 强制要求 User-Agent
        "user-agent": "cloud-r2pan",
      },
    });
    if (!resp.ok) return null;
    const j = (await resp.json()) as Record<string, unknown>;
    const id = String(j.id ?? "");
    if (!id) return null;
    return {
      id,
      login: String(j.login ?? id),
      name: j.name ? String(j.name) : null,
      avatar: j.avatar_url ? String(j.avatar_url) : null,
    };
  } catch {
    return null;
  }
}

function redirectToAdmin(req: Request, params: Record<string, string>): Response {
  const qs = new URLSearchParams(params).toString();
  return new Response(null, {
    status: 302,
    headers: { location: `/admin${qs ? "?" + qs : ""}`, "cache-control": "no-store" },
  });
}

/** 写登录安全日志（失败不影响主流程） */
async function writeLoginLog(env: Env, req: Request, result: string, reason: string): Promise<void> {
  try {
    const ua = req.headers.get("user-agent") ?? "";
    const { browser, os } = parseUA(ua);
    const country = req.headers.get("cf-ipcountry") ?? null;
    await env.db
      .prepare(
        "INSERT INTO login_logs(action, ip, ua, browser, os, country, result, reason, created_at) VALUES(?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)"
      )
      .bind("login", clientIp(req), ua || null, browser, os, country, result, reason, Date.now())
      .run();
  } catch {
    /* ignore */
  }
}
