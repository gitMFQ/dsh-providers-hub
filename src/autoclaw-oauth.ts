/**
 * AutoClaw 凭据获取、本地探测、短信验证码快速登录与 Token 刷新。
 */

import fs from 'node:fs'
import path from 'node:path'
import crypto from 'node:crypto'
import http from 'node:http'
import { execFileSync } from 'node:child_process'
import {
  AUTOCLAW,
  AUTOCLAW_SOURCE_ID,
  type AutoclawProduct,
} from './autoclaw-product.js'
import {
  AUTOCLAW_REFRESH_PATH,
  AUTOCLAW_REFRESH_FALLBACK_PATH,
  AUTOCLAW_MODEL_CONFIG_PATH,
  AUTOCLAW_REQUEST_TIMEOUT_MS,
  calculateAutoclawSign,
  cleanBearerToken,
  autoclawExpiresAtMs,
  autoclawAccessTokenExpiresAtMs,
  type AutoclawCredential,
} from './autoclaw.js'

export const AUTOCLAW_SEND_CODE_PATH = '/userapi/v1/agent-send-code'
export const AUTOCLAW_LOGIN_PATH = '/userapi/v1/agent-login'

/** 手机号格式正则（中国大陆11位手机号）。 */
export const PHONE_NUMBER_RE = /^1[3-9]\d{9}$/

/**
 * 从本地 Windows DPAPI 及 AES-256-GCM 探测 AutoClaw 桌面端保存的有效凭据（一键导入模式）。
 *
 * ## ⚠️⚠️ 凭据来源是**用户真实凭据**，故必须可隔离（2026-10-17 审计 P0 修复）
 *
 * 本函数会真读 `%APPDATA%\AutoClaw-official\` 并**真跑 powershell 解 DPAPI**
 * （约 1s）⇒ 单测里若不隔离，用户装了 AutoClaw 桌面端时就会读到**他的真实
 * access/refresh token**（本仓库 `.office-claw` 未隔离事故的同型，见
 * `tests/setup-isolation.ts` 的长注释）。
 *
 * ⇒ 新增 `DSH_AUTOCLAW_APPDATA` 覆盖：**优先级高于 `APPDATA`**，
 *   `tests/setup-isolation.ts` 在**进程级**把它指向临时目录
 *   （与 `DSH_OFFICEACE_HOME` / `DSH_JET_HUB_STATE_DIR` 同型）。
 * ⚠️ 为什么不用「在用例里改 `APPDATA`」：`apply()` 内部有 fire-and-forget 的
 *   后台链，用例的 `afterEach` 恢复环境变量**之后**那条链才跑到本分支 ⇒
 *   与 officeace 那次事故同型，唯一可靠做法是进程级。
 */
export async function probeAutoclawLocalCredential(options?: {
  customAppData?: string
}): Promise<AutoclawCredential | undefined> {
  try {
    const appData =
      options?.customAppData
      // ⚠️ 测试隔离口必须**排在 `APPDATA` 之前**，否则隔离形同虚设。
      ?? process.env.DSH_AUTOCLAW_APPDATA
      ?? process.env.APPDATA
      ?? (process.env.USERPROFILE ? path.join(process.env.USERPROFILE, 'AppData', 'Roaming') : undefined)

    if (!appData) return undefined

    const localStatePath = path.join(appData, 'AutoClaw-official', 'Local State')
    if (!fs.existsSync(localStatePath)) return undefined

    const localState = JSON.parse(fs.readFileSync(localStatePath, 'utf8')) as {
      os_crypt?: { encrypted_key?: string }
    }
    const encKeyB64 = localState?.os_crypt?.encrypted_key
    if (!encKeyB64) return undefined

    const encKeyBuf = Buffer.from(encKeyB64, 'base64')
    if (!encKeyBuf.subarray(0, 5).equals(Buffer.from('DPAPI'))) {
      return undefined
    }

    const rawEncKey = encKeyBuf.subarray(5)
    const hex = rawEncKey.toString('hex')
    const psScript = `
      Add-Type -AssemblyName System.Security
      $hex = "${hex}"
      $bytes = for ($i=0; $i -lt $hex.Length; $i+=2) { [Convert]::ToByte($hex.Substring($i, 2), 16) }
      $unprotected = [Security.Cryptography.ProtectedData]::Unprotect($bytes, $null, [Security.Cryptography.DataProtectionScope]::CurrentUser)
      [Convert]::ToBase64String($unprotected)
    `
    const clearB64 = execFileSync('powershell.exe', ['-NoProfile', '-NonInteractive', '-Command', psScript], {
      encoding: 'utf8',
      timeout: 10_000,
    }).trim()
    const masterKey = Buffer.from(clearB64, 'base64')

    const accountsDir = path.join(appData, 'AutoClaw-official', 'accounts')
    if (!fs.existsSync(accountsDir)) return undefined

    const entries = fs.readdirSync(accountsDir, { withFileTypes: true })
    for (const ent of entries) {
      if (!ent.isDirectory()) continue
      const credFile = path.join(accountsDir, ent.name, 'account-credentials.enc')
      if (!fs.existsSync(credFile)) continue

      const encData = fs.readFileSync(credFile)
      if (encData.length < 31) continue // 3 prefix + 12 nonce + at least 16 tag

      const nonce = encData.subarray(3, 15)
      const ciphertextAndTag = encData.subarray(15)
      const ciphertext = ciphertextAndTag.subarray(0, ciphertextAndTag.length - 16)
      const tag = ciphertextAndTag.subarray(ciphertextAndTag.length - 16)

      const decipher = crypto.createDecipheriv('aes-256-gcm', masterKey, nonce)
      decipher.setAuthTag(tag)
      const decrypted = Buffer.concat([decipher.update(ciphertext), decipher.final()])
      const parsed = JSON.parse(decrypted.toString('utf8')) as Record<string, unknown>

      const rawAccess = (parsed.accessToken ?? parsed.access_token) as string | undefined
      const rawRefresh = (parsed.refreshToken ?? parsed.refresh_token) as string | undefined

      if (rawAccess && rawRefresh) {
        const cleanAccess = cleanBearerToken(rawAccess)
        const cleanRefresh = cleanBearerToken(rawRefresh)

        let jwtPayload: Record<string, unknown> | undefined
        try {
          const parts = cleanAccess.split('.')
          if (parts.length >= 2) {
            const b64 = parts[1].replace(/-/g, '+').replace(/_/g, '/')
            jwtPayload = JSON.parse(Buffer.from(b64, 'base64').toString('utf8'))
          }
        } catch {
          // ignore
        }

        const profilePath = path.join(accountsDir, ent.name, 'account-profile.json')
        let profilePhone: string | undefined
        let profileName: string | undefined
        if (fs.existsSync(profilePath)) {
          try {
            const prof = JSON.parse(fs.readFileSync(profilePath, 'utf8')) as {
              profile?: { phone?: string; displayName?: string }
            }
            profilePhone = prof?.profile?.phone
            profileName = prof?.profile?.displayName
          } catch {
            // ignore
          }
        }

        const jwtPhone =
          typeof jwtPayload?.jti === 'string' && /^1[3-9]\d{9}$/.test(jwtPayload.jti.trim())
            ? jwtPayload.jti.trim()
            : undefined

        const resolvedPhone =
          profilePhone ??
          jwtPhone ??
          (typeof parsed.userPhone === 'string' ? parsed.userPhone : undefined) ??
          (typeof parsed.phone === 'string' ? parsed.phone : undefined)

        const resolvedName =
          profileName ??
          (typeof parsed.userName === 'string' ? parsed.userName : undefined)

        const resolvedUserId =
          (typeof parsed.userId === 'string' || typeof parsed.userId === 'number' ? parsed.userId : undefined) ??
          (typeof jwtPayload?.user_id === 'string' || typeof jwtPayload?.user_id === 'number' ? jwtPayload.user_id : undefined)

        const resolvedDeviceId =
          (typeof parsed.deviceId === 'string' ? parsed.deviceId : undefined) ??
          (typeof jwtPayload?.device_id === 'string' ? jwtPayload.device_id : undefined)

        // ⚠️⚠️ **JWT 的 `exp` 优先**（2026-10-19 P0）：桌面端凭据里那份
        //   `expiresAt` 是**它自己写的**，与 token 的真实死线不一定同源；
        //   而 JWT 的 `exp` 正是网关判定 `410000` 的依据。读不到才回退它。
        const resolvedExpiresAt = autoclawAccessTokenExpiresAtMs(
          cleanAccess,
          typeof parsed.expiresAt === 'number' ? autoclawExpiresAtMs(parsed.expiresAt) : undefined,
        )

        return {
          access_token: cleanAccess,
          refresh_token: cleanRefresh,
          expires_at: resolvedExpiresAt,
          user_id: resolvedUserId,
          user_name: resolvedName,
          user_phone: resolvedPhone,
          device_id: resolvedDeviceId,
        }
      }
    }

    return undefined
  } catch {
    return undefined
  }
}

/**
 * 刷新 AutoClaw Token。
 */
export async function refreshAutoclawToken(
  refreshToken: string,
  options?: {
    product?: AutoclawProduct
    fetchImpl?: typeof fetch
    deviceId?: string
  },
): Promise<AutoclawCredential> {
  const product = options?.product ?? AUTOCLAW
  const fetcher = options?.fetchImpl ?? fetch
  const cleanRefresh = cleanBearerToken(refreshToken)
  const deviceId = options?.deviceId ?? 'dsh-autoclaw-device-001'

  const endpoints = [AUTOCLAW_REFRESH_PATH, AUTOCLAW_REFRESH_FALLBACK_PATH]
  let lastError: Error | undefined

  for (const ep of endpoints) {
    const ts = Math.floor(Date.now() / 1000).toString()
    const sign = calculateAutoclawSign(product.appId, ts, product.appKey)
    const url = `${product.apiBase}${ep}`

    try {
      const resp = await fetcher(url, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'X-Auth-Appid': product.appId,
          'X-Auth-TimeStamp': ts,
          'X-Auth-Sign': sign,
        },
        body: JSON.stringify({
          refresh_token: cleanRefresh,
          source_id: AUTOCLAW_SOURCE_ID,
          device_id: deviceId,
        }),
        signal: AbortSignal.timeout(AUTOCLAW_REQUEST_TIMEOUT_MS),
      })

      if (!resp.ok) {
        const text = await resp.text().catch(() => '')
        throw new Error(`AutoClaw token refresh failed with status ${resp.status}: ${text}`)
      }

      const json = (await resp.json()) as {
        code?: number
        msg?: string
        data?: {
          access_token?: string
          refresh_token?: string
          expires_in?: number
          expires_at?: number
          user_id?: string | number
        }
      }

      if (json.code !== 0 || !json.data?.access_token) {
        throw new Error(`AutoClaw token refresh returned code ${json.code}: ${json.msg ?? 'unknown'}`)
      }

      const newAccess = cleanBearerToken(json.data.access_token)
      const newRefresh = json.data.refresh_token ? cleanBearerToken(json.data.refresh_token) : cleanRefresh
      // ⚠️⚠️ **续期响应同样可能不带 `expires_at` / `expires_in`**
      //   （2026-10-19 P0）：旧写法在这种情形下产出 `undefined` ⇒
      //   `syncAccountExpiry` 保留池内旧值（可能就是那份错的），而凭据里也
      //   读不到真死线。⇒ 一律以 JWT 的 `exp` 为准，声明值只作兜底。
      const declaredExpiresAt = autoclawExpiresAtMs(json.data.expires_at ?? json.data.expires_in)
      const expiresAt = autoclawAccessTokenExpiresAtMs(newAccess, declaredExpiresAt)

      return {
        access_token: newAccess,
        refresh_token: newRefresh,
        expires_at: expiresAt,
        user_id: json.data.user_id,
        device_id: deviceId,
      }
    } catch (err) {
      lastError = err instanceof Error ? err : new Error(String(err))
    }
  }

  throw lastError ?? new Error('AutoClaw token refresh failed on all endpoints')
}

/**
 * 校验 AutoClaw 凭据是否连通可用。
 */
export async function testAutoclawConnection(
  accessToken: string,
  options?: {
    product?: AutoclawProduct
    fetchImpl?: typeof fetch
  },
): Promise<boolean> {
  const product = options?.product ?? AUTOCLAW
  const fetcher = options?.fetchImpl ?? fetch
  const ts = Math.floor(Date.now() / 1000).toString()
  const sign = calculateAutoclawSign(product.appId, ts, product.appKey)
  const cleanAccess = cleanBearerToken(accessToken)

  const url = `${product.apiBase}${AUTOCLAW_MODEL_CONFIG_PATH}`
  try {
    const resp = await fetcher(url, {
      method: 'GET',
      headers: {
        'Content-Type': 'application/json',
        'X-Auth-Appid': product.appId,
        'X-Auth-TimeStamp': ts,
        'X-Auth-Sign': sign,
        'X-Authorization': `Bearer ${cleanAccess}`,
      },
      signal: AbortSignal.timeout(15_000),
    })

    return resp.ok
  } catch {
    return false
  }
}

// ── 手机短信验证码快速登录模式 ──

export interface SendAutoclawCodeOptions {
  product?: AutoclawProduct
  fetchImpl?: typeof fetch
  deviceId?: string
}

export interface SendAutoclawCodeResult {
  ok: boolean
  msgid?: string
  error?: string
}

export interface LoginAutoclawWithCodeOptions {
  product?: AutoclawProduct
  fetchImpl?: typeof fetch
  deviceId?: string
}

export interface LoginAutoclawWithCodeResult {
  ok: boolean
  credential?: AutoclawCredential
  error?: string
}

function resolveDeviceId(explicitId?: string): string {
  if (explicitId && explicitId.trim().length > 0) return explicitId.trim()
  try {
    // ⚠️⚠️ 同样必须走隔离口（2026-10-17 审计 P0 修复）：这里读的是用户**真实**
    //   桌面端设备号。测试里读到它会让断言依赖开发机状态（本仓库 `QODER_RUNTIME_INFO`
    //   隔离的正是同款问题），而设备号会进登录/签到请求体 ⇒ 结果不可复现。
    //   ⚠️ 隔离口优先级必须与 `probeAutoclawLocalCredential` **一致**。
    const p = path.join(
      process.env.DSH_AUTOCLAW_APPDATA
        ?? process.env.APPDATA
        ?? path.join(process.env.USERPROFILE ?? '', 'AppData', 'Roaming'),
      'AutoClaw-official',
      'device',
      'device-id.json',
    )
    if (fs.existsSync(p)) {
      const data = JSON.parse(fs.readFileSync(p, 'utf8')) as { deviceId?: string }
      if (typeof data.deviceId === 'string' && data.deviceId.trim()) {
        return data.deviceId.trim()
      }
    }
  } catch {}
  return crypto.randomUUID()
}

/**
 * 向手机号发送 AutoClaw 登录验证码（/userapi/v1/agent-send-code）。
 */
export async function sendAutoclawVerificationCode(
  phone: string,
  options?: SendAutoclawCodeOptions,
): Promise<SendAutoclawCodeResult> {
  const trimmedPhone = phone.trim()
  if (!PHONE_NUMBER_RE.test(trimmedPhone)) {
    return { ok: false, error: '手机号格式不正确' }
  }

  const product = options?.product ?? AUTOCLAW
  const fetcher = options?.fetchImpl ?? fetch
  const deviceId = resolveDeviceId(options?.deviceId)
  const ts = Math.floor(Date.now() / 1000).toString()
  const sign = calculateAutoclawSign(product.appId, ts, product.appKey)
  const url = `${product.apiBase}${AUTOCLAW_SEND_CODE_PATH}`

  try {
    const resp = await fetcher(url, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'X-Auth-Appid': product.appId,
        'X-Auth-TimeStamp': ts,
        'X-Auth-Sign': sign,
        'X-Lang': 'zh-CN',
        'X-Channel': 'official',
      },
      body: JSON.stringify({
        phone: trimmedPhone,
        source_id: AUTOCLAW_SOURCE_ID,
        device_id: deviceId,
      }),
      signal: AbortSignal.timeout(AUTOCLAW_REQUEST_TIMEOUT_MS),
    })

    if (!resp.ok) {
      const text = await resp.text().catch(() => '')
      return { ok: false, error: `验证码发送失败(${resp.status}): ${text}` }
    }

    const json = (await resp.json()) as {
      code?: number
      msg?: string
      data?: Record<string, unknown>
    }

    if (json.code !== 0) {
      return { ok: false, error: json.msg || `验证码发送失败(错误码: ${json.code})` }
    }

    return { ok: true, msgid: 'autoclaw-sms' }
  } catch (err) {
    const msg = err instanceof Error ? err.message : String(err)
    return { ok: false, error: msg }
  }
}

/**
 * 使用手机验证码登录 AutoClaw 并兑换凭据（/userapi/v1/agent-login）。
 */
export async function loginAutoclawWithCode(
  phone: string,
  code: string,
  options?: LoginAutoclawWithCodeOptions,
): Promise<LoginAutoclawWithCodeResult> {
  const trimmedPhone = phone.trim()
  const trimmedCode = code.trim()
  if (!PHONE_NUMBER_RE.test(trimmedPhone)) {
    return { ok: false, error: '手机号格式不正确' }
  }
  if (!trimmedCode) {
    return { ok: false, error: '验证码不能为空' }
  }
  const numCode = Number(trimmedCode)
  if (!Number.isSafeInteger(numCode)) {
    return { ok: false, error: '验证码必须为纯数字' }
  }

  const product = options?.product ?? AUTOCLAW
  const fetcher = options?.fetchImpl ?? fetch
  const deviceId = resolveDeviceId(options?.deviceId)
  const ts = Math.floor(Date.now() / 1000).toString()
  const sign = calculateAutoclawSign(product.appId, ts, product.appKey)
  const url = `${product.apiBase}${AUTOCLAW_LOGIN_PATH}`

  try {
    const resp = await fetcher(url, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'X-Auth-Appid': product.appId,
        'X-Auth-TimeStamp': ts,
        'X-Auth-Sign': sign,
        'X-Lang': 'zh-CN',
        'X-Channel': 'official',
      },
      body: JSON.stringify({
        phone: trimmedPhone,
        code: numCode,
        source_id: AUTOCLAW_SOURCE_ID,
        device_id: deviceId,
      }),
      signal: AbortSignal.timeout(AUTOCLAW_REQUEST_TIMEOUT_MS),
    })

    if (!resp.ok) {
      const text = await resp.text().catch(() => '')
      return { ok: false, error: `AutoClaw 登录请求失败(${resp.status}): ${text}` }
    }

    const json = (await resp.json()) as {
      code?: number
      msg?: string
      data?: {
        user_id?: string | number
        access_token?: string
        refresh_token?: string
        user_name?: string
        user_phone?: string
        expires_in?: number
        expires_at?: number
      }
    }

    if (json.code !== 0 || !json.data) {
      return { ok: false, error: json.msg || `AutoClaw 登录失败(错误码: ${json.code})` }
    }

    const { data } = json
    if (!data.access_token) {
      return { ok: false, error: 'AutoClaw 响应中缺少 access_token' }
    }

    const cleanAccess = cleanBearerToken(data.access_token)
    const cleanRefresh = data.refresh_token ? cleanBearerToken(data.refresh_token) : undefined
    // ⚠️⚠️ **绝不编造过期时间**（2026-10-19 P0，真实报障）。
    //
    // 旧实现在上游既不给 `expires_at` 也不给 `expires_in` 时写下
    // `Date.now() + 7 * 86400_000`（7 天），而真实 access_token 的寿命是
    // **24 小时**（JWT `iat`→`exp` 实测恒 86400s）⇒ 多出的 6 天让
    // `refreshAll` 的 lead-time 判据与 `healExpiredAccountBeforeBalance`
    // 按需自愈**双双跳过**：凭据到期后表现为「刚启动还能看到积分、
    // 过一会儿变成登录凭据失效」，且**日志零字**；点「刷新积分」也不会自愈。
    //
    // ⇒ 权威是 JWT 的 `exp`；退一步用上游声明值；**都读不到就 `undefined`**
    //   （= 不知道 ⇒ 调用方按「该续期」处理），绝不编数字。
    const declaredExpiresAt = typeof data.expires_at === 'number'
      ? autoclawExpiresAtMs(data.expires_at)
      : typeof data.expires_in === 'number'
        ? Date.now() + data.expires_in * 1000
        : undefined
    const expiresAt = autoclawAccessTokenExpiresAtMs(cleanAccess, declaredExpiresAt)

    const credential: AutoclawCredential = {
      access_token: cleanAccess,
      refresh_token: cleanRefresh ?? '',
      expires_at: expiresAt,
      device_id: deviceId,
      account_id: data.user_id !== undefined ? String(data.user_id) : undefined,
      user_id: data.user_id,
      user_name: data.user_name,
      user_phone: data.user_phone ?? trimmedPhone,
    }

    return { ok: true, credential }
  } catch (err) {
    const msg = err instanceof Error ? err.message : String(err)
    return { ok: false, error: msg }
  }
}

export interface StartedAutoclawSmsLoginFlow {
  readonly loginUrl: string
  readonly result: Promise<{ credential: AutoclawCredential; phone: string }>
  readonly close: () => Promise<void>
}

export interface AutoclawSmsLoginFlowOptions {
  product?: AutoclawProduct
  timeoutMs?: number
  fetchImpl?: typeof fetch
  deviceId?: string
}

/**
 * 启动本地独立服务器承载 AutoClaw 登录授权页（支持一键读取本地凭据或手机验证码登录）。
 */
export async function startAutoclawSmsLoginFlow(
  options?: AutoclawSmsLoginFlowOptions,
): Promise<StartedAutoclawSmsLoginFlow> {
  const product = options?.product ?? AUTOCLAW
  const timeoutMs = options?.timeoutMs ?? 180_000

  let settleOk!: (val: { credential: AutoclawCredential; phone: string }) => void
  let settleErr!: (err: unknown) => void

  const result = new Promise<{ credential: AutoclawCredential; phone: string }>((resolve, reject) => {
    settleOk = resolve
    settleErr = reject
  })

  const server = http.createServer((req, res) => {
    const url = new URL(req.url ?? '/', `http://127.0.0.1:${(req.socket as any).localPort ?? 0}`)

    if (req.method === 'GET' && (url.pathname === '/autoclaw/login' || url.pathname === '/')) {
      res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' })
      res.end(`<!DOCTYPE html>
<html lang="zh-CN">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1.0" />
  <title>AutoClaw 登录授权</title>
  <style>
    body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; background: #0f172a; color: #f8fafc; display: flex; justify-content: center; align-items: center; min-height: 100vh; margin: 0; padding: 20px; box-sizing: border-box; }
    .card { background: #1e293b; border: 1px solid #334155; border-radius: 12px; padding: 32px; width: 100%; max-width: 420px; box-shadow: 0 10px 25px -5px rgba(0, 0, 0, 0.5); }
    h2 { margin: 0 0 8px 0; font-size: 20px; font-weight: 600; color: #38bdf8; }
    p.desc { color: #94a3b8; font-size: 13px; margin: 0 0 24px 0; }
    .btn-secondary { width: 100%; background: #334155; color: #f8fafc; border: 1px solid #475569; border-radius: 6px; padding: 10px 16px; font-size: 14px; cursor: pointer; transition: background 0.2s; }
    .btn-secondary:hover { background: #475569; }
    .divider { display: flex; align-items: center; text-align: center; margin: 20px 0; color: #64748b; font-size: 12px; }
    .divider::before, .divider::after { content: ''; flex: 1; border-bottom: 1px solid #334155; }
    .divider::before { margin-right: .5em; }
    .divider::after { margin-left: .5em; }
    .input-group { margin-bottom: 16px; }
    label { display: block; font-size: 12px; color: #cbd5e1; margin-bottom: 6px; }
    input { width: 100%; box-sizing: border-box; background: #0f172a; border: 1px solid #475569; border-radius: 6px; padding: 10px 12px; color: #f8fafc; font-size: 14px; outline: none; }
    input:focus { border-color: #38bdf8; }
    .row { display: flex; gap: 8px; }
    .row input { flex: 1; }
    .btn-code { background: #0284c7; color: white; border: none; border-radius: 6px; padding: 0 16px; font-size: 13px; cursor: pointer; white-space: nowrap; }
    .btn-code:disabled { background: #475569; cursor: not-allowed; }
    .btn-primary { width: 100%; background: #0284c7; color: white; border: none; border-radius: 6px; padding: 11px 16px; font-size: 15px; font-weight: 500; cursor: pointer; margin-top: 8px; }
    .btn-primary:hover { background: #0369a1; }
    .btn-primary:disabled { background: #475569; cursor: not-allowed; }
    .msg { margin-top: 16px; padding: 10px 12px; border-radius: 6px; font-size: 13px; display: none; }
    .msg.error { display: block; background: rgba(239, 68, 68, 0.15); border: 1px solid #ef4444; color: #fca5a5; }
    .msg.success { display: block; background: rgba(34, 197, 94, 0.15); border: 1px solid #22c55e; color: #86efac; }
  </style>
</head>
<body>
  <div class="card">
    <h2>AutoClaw 账号登录</h2>
    <p class="desc">支持一键读取本机桌面端凭据，或通过手机验证码快速登录。</p>
    <button type="button" class="btn-secondary" id="btnLocal">⚡ 一键读取本机 AutoClaw 桌面端凭据</button>
    <div class="divider">或者使用手机验证码登录</div>
    <div class="input-group">
      <label for="phone">手机号</label>
      <input type="tel" id="phone" placeholder="请输入 11 位手机号" maxlength="11" />
    </div>
    <div class="input-group">
      <label for="code">短信验证码</label>
      <div class="row">
        <input type="text" id="code" placeholder="请输入 6 位验证码" maxlength="6" />
        <button type="button" class="btn-code" id="btnSend">获取验证码</button>
      </div>
    </div>
    <button type="button" class="btn-primary" id="btnLogin">登录并绑定账号</button>
    <div class="msg" id="msgBox"></div>
  </div>
  <script>
    const btnLocal = document.getElementById('btnLocal');
    const phoneInput = document.getElementById('phone');
    const codeInput = document.getElementById('code');
    const btnSend = document.getElementById('btnSend');
    const btnLogin = document.getElementById('btnLogin');
    const msgBox = document.getElementById('msgBox');
    function showMsg(type, text) { msgBox.className = 'msg ' + type; msgBox.textContent = text; msgBox.style.display = 'block'; }
    btnLocal.addEventListener('click', async () => {
      btnLocal.disabled = true;
      btnLocal.textContent = '正在检测本地凭据...';
      try {
        const resp = await fetch('/autoclaw/import-local', { method: 'POST' });
        const data = await resp.json();
        if (data.ok) {
          showMsg('success', '✅ 成功读取本机已登录凭据（' + (data.phone || 'AutoClaw账号') + '）！已自动绑定，请关闭本窗口返回 IDE。');
          btnLocal.style.display = 'none';
        } else {
          showMsg('error', data.error || '未检测到本地 AutoClaw 桌面端有效登录凭据，请使用下方手机验证码登录。');
          btnLocal.disabled = false;
          btnLocal.textContent = '⚡ 一键读取本机 AutoClaw 桌面端凭据';
        }
      } catch (err) {
        showMsg('error', '请求失败：' + (err.message || String(err)));
        btnLocal.disabled = false;
        btnLocal.textContent = '⚡ 一键读取本机 AutoClaw 桌面端凭据';
      }
    });
    let countdown = 0;
    btnSend.addEventListener('click', async () => {
      const phone = phoneInput.value.trim();
      if (!/^1[3-9]\\d{9}$/.test(phone)) { showMsg('error', '请输入正确的 11 位手机号码'); return; }
      btnSend.disabled = true;
      btnSend.textContent = '发送中...';
      try {
        const resp = await fetch('/autoclaw/send-code', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ phone }) });
        const data = await resp.json();
        if (data.ok) {
          showMsg('success', '验证码已发送至手机，请查收');
          countdown = 60;
          btnSend.textContent = countdown + 's 后重新获取';
          const timer = setInterval(() => {
            countdown--;
            if (countdown <= 0) { clearInterval(timer); btnSend.disabled = false; btnSend.textContent = '获取验证码'; }
            else { btnSend.textContent = countdown + 's 后重新获取'; }
          }, 1000);
        } else {
          showMsg('error', data.error || '发送验证码失败');
          btnSend.disabled = false;
          btnSend.textContent = '获取验证码';
        }
      } catch (err) {
        showMsg('error', '发送验证码网络异常：' + (err.message || String(err)));
        btnSend.disabled = false;
        btnSend.textContent = '获取验证码';
      }
    });
    btnLogin.addEventListener('click', async () => {
      const phone = phoneInput.value.trim();
      const code = codeInput.value.trim();
      if (!/^1[3-9]\\d{9}$/.test(phone)) { showMsg('error', '请输入正确的 11 位手机号码'); return; }
      if (!code) { showMsg('error', '请输入收到的短信验证码'); return; }
      btnLogin.disabled = true;
      btnLogin.textContent = '登录中...';
      try {
        const resp = await fetch('/autoclaw/submit-code', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ phone, code }) });
        const data = await resp.json();
        if (data.ok) {
          showMsg('success', '✅ 登录成功！已绑定账号：' + (data.phone || phone) + '，您可以关闭本窗口返回 IDE。');
          btnLogin.style.display = 'none';
        } else {
          showMsg('error', data.error || '验证码登录失败，请重试');
          btnLogin.disabled = false;
          btnLogin.textContent = '登录并绑定账号';
        }
      } catch (err) {
        showMsg('error', '登录网络异常：' + (err.message || String(err)));
        btnLogin.disabled = false;
        btnLogin.textContent = '登录并绑定账号';
      }
    });
  </script>
</body>
</html>`)
      return
    }

    if (req.method === 'POST') {
      let bodyStr = ''
      req.on('data', (chunk) => { bodyStr += chunk })
      req.on('end', async () => {
        let jsonBody: Record<string, any> = {}
        try {
          if (bodyStr.trim()) jsonBody = JSON.parse(bodyStr)
        } catch {}

        if (url.pathname === '/autoclaw/send-code') {
          const resCode = await sendAutoclawVerificationCode(jsonBody.phone ?? '', {
            product,
            fetchImpl: options?.fetchImpl,
            deviceId: options?.deviceId,
          })
          res.writeHead(200, { 'Content-Type': 'application/json; charset=utf-8' })
          res.end(JSON.stringify(resCode))
          return
        }

        if (url.pathname === '/autoclaw/submit-code') {
          const resLogin = await loginAutoclawWithCode(jsonBody.phone ?? '', jsonBody.code ?? '', {
            product,
            fetchImpl: options?.fetchImpl,
            deviceId: options?.deviceId,
          })
          if (resLogin.ok && resLogin.credential) {
            settleOk({ credential: resLogin.credential, phone: jsonBody.phone ?? '' })
            res.writeHead(200, { 'Content-Type': 'application/json; charset=utf-8' })
            res.end(JSON.stringify({ ok: true, phone: jsonBody.phone ?? '' }))
          } else {
            res.writeHead(200, { 'Content-Type': 'application/json; charset=utf-8' })
            res.end(JSON.stringify({ ok: false, error: resLogin.error || '登录失败' }))
          }
          return
        }

        if (url.pathname === '/autoclaw/import-local') {
          const localCred = await probeAutoclawLocalCredential()
          if (localCred) {
            settleOk({ credential: localCred, phone: localCred.user_phone ?? '' })
            res.writeHead(200, { 'Content-Type': 'application/json; charset=utf-8' })
            res.end(JSON.stringify({ ok: true, phone: localCred.user_phone ?? '' }))
          } else {
            res.writeHead(200, { 'Content-Type': 'application/json; charset=utf-8' })
            res.end(JSON.stringify({ ok: false, error: '未检测到本地 AutoClaw 桌面端有效登录凭据' }))
          }
          return
        }

        res.writeHead(404).end('Not Found')
      })
      return
    }

    res.writeHead(404).end('Not Found')
  })

  await new Promise<void>((resolve) => {
    server.listen(0, '127.0.0.1', () => resolve())
  })

  const addr = server.address()
  const port = typeof addr === 'object' && addr !== null ? addr.port : 0
  const loginUrl = `http://127.0.0.1:${port}/autoclaw/login`

  let closed = false
  const close = async (): Promise<void> => {
    if (closed) return
    closed = true
    await new Promise<void>((resolve) => server.close(() => resolve()))
  }

  const timer = setTimeout(() => {
    settleErr(new Error(`AutoClaw 登录超时（${Math.round(timeoutMs / 1000)} 秒内未完成）`))
  }, timeoutMs)
  timer.unref?.()

  result.catch(() => {}).finally(() => {
    clearTimeout(timer)
    void close()
  })

  return { loginUrl, result, close }
}
