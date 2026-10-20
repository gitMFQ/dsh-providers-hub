/**
 * AutoClaw 认证服务。
 */

import { Service, type Context } from '@deepseek-ai/cordis'
import { credentialRef, type CredentialRef } from '@deepseek-ai/dsh-credentials'
import {
  AUTOCLAW,
  type AutoclawProduct,
} from './autoclaw-product.js'
import {
  parseAutoclawCredential,
  isAutoclawRefreshable,
  isAutoclawTokenExpired,
  autoclawDisplayNickname,
  type AutoclawCredential,
} from './autoclaw.js'
import {
  probeAutoclawLocalCredential,
  refreshAutoclawToken,
  testAutoclawConnection,
  sendAutoclawVerificationCode,
  loginAutoclawWithCode,
  startAutoclawSmsLoginFlow,
  type SendAutoclawCodeResult,
  type LoginAutoclawWithCodeResult,
  type StartedAutoclawSmsLoginFlow,
} from './autoclaw-oauth.js'
import { RefreshScheduler } from './refresh.js'
import { claimAutoclawDailyQuota } from './autoclaw-credits.js'
import { AccountPool } from './account-pool.js'
import {
  refreshAccountWithReconcile,
  syncAccountExpiry,
  type ExpiryAccessors,
} from './expiry-sync.js'

/**
 * AutoClaw 凭据 → 账号池有效期所需的提取器。
 *
 * ⚠️ `expiresAtOf` 只读 `credential.expires_at`，而该字段由
 * `parseAutoclawCredential` **以 JWT 的 `exp` 为准**归一（2026-10-19 P0，
 * 见 `src/autoclaw.ts` 的 `autoclawAccessTokenExpiresAtMs`）。
 * 这两个入口必须**同源**：它是 `refreshAll` 的 lead-time 判据与 UI 有效期
 * 的共同数据源 —— 曾因该字段是编造的 7 天而让整条自动续期链**静默跳过**。
 */
const AUTOCLAW_EXPIRY_ACCESSORS: ExpiryAccessors<AutoclawCredential> = {
  expiresAtOf: (credential) => credential.expires_at,
  refreshableOf: isAutoclawRefreshable,
  identityOf: (credential) => credential.access_token ?? '',
}

export class RefreshTokenExpiredError extends Error {
  constructor(message: string) {
    super(message)
    this.name = 'RefreshTokenExpiredError'
  }
}

export interface AutoclawAuthOptions {
  readonly product?: AutoclawProduct
  readonly serviceName?: string
  readonly fetcher?: typeof fetch
}

export interface AutoclawStatusResult {
  readonly loggedIn: boolean
  readonly expiresAt?: number
  readonly refreshable: boolean
  readonly lastError?: string
}

export class AutoclawAuth extends Service {
  readonly product: AutoclawProduct
  readonly credentialRefName: string

  private readonly scheduler = new RefreshScheduler(
    () => this.refresh(),
    (error) => {
      if (error instanceof RefreshTokenExpiredError) {
        this.markRefreshTokenInvalid()
        return
      }
      this.lastRefreshError = error instanceof Error ? error.message : String(error)
    },
  )

  private refreshTokenInvalid = false
  private lastRefreshError: string | undefined
  private active = true

  constructor(ctx: Context, private readonly options: AutoclawAuthOptions = {}) {
    const product = options.product ?? AUTOCLAW
    super(ctx, options.serviceName ?? `${product.id}Auth`)
    this.product = product
    this.credentialRefName = this.product.defaultCredentialRef
  }

  private get fetchImpl(): typeof fetch {
    return this.options.fetcher ?? fetch
  }

  /**
   * 探测本地是否有有效凭据。
   */
  async probeLocal(): Promise<AutoclawCredential | undefined> {
    return probeAutoclawLocalCredential()
  }

  /**
   * 刷新指定的凭据对象。
   */
  async refreshCredential(credential: AutoclawCredential): Promise<AutoclawCredential> {
    if (!isAutoclawRefreshable(credential)) {
      throw new RefreshTokenExpiredError('AutoClaw refresh_token 为空，无法续期')
    }
    try {
      const refreshed = await refreshAutoclawToken(credential.refresh_token, {
        product: this.product,
        fetchImpl: this.fetchImpl,
        deviceId: credential.device_id,
      })
      return refreshed
    } catch (err) {
      const msg = err instanceof Error ? err.message : String(err)
      if (msg.includes('Invalid token') || msg.includes('expired') || msg.includes('401')) {
        throw new RefreshTokenExpiredError(`AutoClaw refresh_token 已失效：${msg}`)
      }
      throw err
    }
  }

  /**
   * 按凭据 ref 续期指定账号的凭据。
   */
  async refreshAccountCredential(
    refName: string,
    pool?: AccountPool,
    accountId?: string,
  ): Promise<void> {
    const ref = credentialRef(refName)
    const resolved = await this.ctx.credentials.resolve(ref)
    if (!resolved) throw new Error('凭据未配置')
    const credential = parseAutoclawCredential(resolved.value)
    if (!credential) throw new Error('凭据解析失败')
    // ⚠️⚠️ **空 `refresh_token` 必须走到这里，而不是上一行**
    // （2026-10-17 审计 P1 修复）。上游不下发 refresh_token 时
    // `loginAutoclawWithCode` 会产出 `refresh_token: ''`，而解析过去把它
    // 判成「解析失败」⇒ 用户点「刷新」看到的是**误导文案**，
    // 真实原因（必须重新登录）就在下一行却永远不可达。
    // ⚠️ 这类「文案本身就是出路」的错误必须给准 —— 它告诉用户**去做什么**
    //   （重新登录），说错会让用户反复点刷新却始终找不到出路
    //   （本仓库 client-ui 笔记记载的复发形态）。
    if (!isAutoclawRefreshable(credential)) {
      throw new RefreshTokenExpiredError('无 refresh_token，请重新登录')
    }

    const refreshed = await this.refreshCredential(credential)
    await this.ctx.credentials.set(ref, JSON.stringify(refreshed))
    await syncAccountExpiry({
      pool,
      provider: this.product.id,
      credential: refreshed,
      accessors: AUTOCLAW_EXPIRY_ACCESSORS,
      accountId,
      tag: '[autoclaw]',
      warn: (message) => this.ctx.logger?.warn?.(message),
    })
  }

  /**
   * 批量续期本产品的所有账号。
   */
  async refreshAll(pool: AccountPool): Promise<void> {
    const accounts = await pool.listAccounts(this.product.id)
    for (const entry of accounts) {
      if (!entry.refreshable) continue
      try {
        const ref = credentialRef(entry.credentialRef)
        const resolved = await this.ctx.credentials.resolve(ref)
        if (!resolved) {
          await pool.updateAccount(entry.id, { refreshable: false })
          continue
        }
        const credential = parseAutoclawCredential(resolved.value)
        if (!credential || !isAutoclawRefreshable(credential)) {
          await pool.updateAccount(entry.id, { refreshable: false })
          continue
        }
        await refreshAccountWithReconcile({
          pool,
          provider: this.product.id,
          tag: '[autoclaw]',
          accountId: entry.id,
          credential,
          accessors: AUTOCLAW_EXPIRY_ACCESSORS,
          current: entry,
          refresh: (c) => this.refreshCredential(c),
          save: (c) => this.ctx.credentials.set(ref, JSON.stringify(c)),
          warn: (message) => this.ctx.logger?.warn?.(message),
        })
      } catch (error) {
        if (error instanceof RefreshTokenExpiredError) {
          try {
            await pool.updateAccount(entry.id, { refreshable: false })
          } catch {
            // 忽略 updateAccount 本身的错误
          }
          this.ctx.logger?.warn?.(
            `[autoclaw] 账号 ${entry.id} 的 refresh_token 已失效，已标记为不可续期（需重新登录）`,
          )
        } else {
          this.ctx.logger?.warn?.(
            `[autoclaw] 账号 ${entry.id} 续期失败: ${error instanceof Error ? error.message : String(error)}`,
          )
        }
      }
    }
  }

  /**
   * 刷新单凭据路径下的当前凭据。
   */
  async refresh(): Promise<void> {
    if (!this.active) return
    const ref = credentialRef(this.credentialRefName)
    const resolved = await this.ctx.credentials.resolve(ref)
    if (!resolved) return

    const credential = parseAutoclawCredential(resolved.value)
    if (!credential || !isAutoclawRefreshable(credential)) return

    try {
      const refreshed = await this.refreshCredential(credential)
      await this.ctx.credentials.set(ref, JSON.stringify(refreshed))
      this.refreshTokenInvalid = false
      this.lastRefreshError = undefined
      if (refreshed.expires_at) {
        this.scheduler.arm(refreshed.expires_at)
      }
    } catch (error) {
      if (error instanceof RefreshTokenExpiredError) {
        this.markRefreshTokenInvalid()
      } else {
        this.lastRefreshError = error instanceof Error ? error.message : String(error)
      }
      throw error
    }
  }

  private markRefreshTokenInvalid(): void {
    this.refreshTokenInvalid = true
    this.scheduler.stop()
  }

  /**
   * 获取当前单凭据状态。
   */
  async status(): Promise<AutoclawStatusResult> {
    const ref = credentialRef(this.credentialRefName)
    const resolved = await this.ctx.credentials.resolve(ref)
    if (!resolved) {
      return { loggedIn: false, refreshable: false }
    }
    const credential = parseAutoclawCredential(resolved.value)
    if (!credential) {
      return { loggedIn: false, refreshable: false, lastError: '凭据格式无效' }
    }

    const expired = isAutoclawTokenExpired(credential, 0)
    return {
      loggedIn: !expired,
      expiresAt: credential.expires_at,
      refreshable: isAutoclawRefreshable(credential) && !this.refreshTokenInvalid,
      lastError: this.lastRefreshError,
    }
  }

  /**
   * 将本地探测到的凭据导入为账号。
   */
  async importLocalAccount(
    pool: AccountPool,
    options?: { accountId?: string; refName?: string },
  ): Promise<{ accountId: string; refName: string; credential: AutoclawCredential }> {
    const cred = await this.probeLocal()
    if (!cred) {
      throw new Error('未检测到本地 AutoClaw 桌面端有效登录凭据，请先在 AutoClaw 中登录')
    }

    const accountId = options?.accountId ?? `autoclaw-${Date.now().toString(36)}`
    const refName = options?.refName ?? `AUTOCLAW_ACCOUNT_${Date.now().toString(16).toUpperCase()}`

    const ref = credentialRef(refName)
    await this.ctx.credentials.set(ref, JSON.stringify(cred))

    const nickname = autoclawDisplayNickname(cred, accountId)

    await pool.addAccount({
      id: accountId,
      provider: this.product.id,
      nickname,
      enabled: true,
      credentialRef: refName,
      createdAt: Date.now(),
      expiresAt: cred.expires_at,
      refreshable: isAutoclawRefreshable(cred),
    })

    return { accountId, refName, credential: cred }
  }

  /**
   * 发送手机验证码（免桌面端快速登录模式）。
   */
  async sendVerificationCode(phone: string): Promise<SendAutoclawCodeResult> {
    return sendAutoclawVerificationCode(phone, {
      product: this.product,
      fetchImpl: this.fetchImpl,
    })
  }

  /**
   * 使用手机验证码登录并保存凭据（免桌面端快速登录模式）。
   */
  async loginWithCode(
    phone: string,
    code: string,
    refName?: string,
  ): Promise<LoginAutoclawWithCodeResult> {
    const res = await loginAutoclawWithCode(phone, code, {
      product: this.product,
      fetchImpl: this.fetchImpl,
    })
    if (res.ok && res.credential && refName) {
      const ref = credentialRef(refName)
      await this.ctx.credentials.set(ref, JSON.stringify(res.credential))
      // ⚠️⚠️ **登录成功后立刻领取每日积分**（2026-10-17，对齐桌面端）。
      //
      // 桌面端源码里有 `claimDailyCreditsOnSignIn(account, dailyCredits)`：
      // 它在账号状态**刚变为 `authenticated`** 时触发
      // `dailyCredits.claim()`（即 `POST /userapi/v1/user-info`）。
      // ⇒ 这就是「登录即领」的真实机制：**不是**登录的副作用，
      //   而是登录后**紧跟一次领取调用**。
      //
      // ⚠️ 用户实测过的症状：纯插件登录后新账号**没有积分**（推理回 402
      //   「积分不足,请充值」），而在 IDE 里登录同一账号就有 ——
      //   差别正是桌面端替用户调了这一次。
      //
      // ⚠️ **失败绝不反噬登录**：领取是附加动作，凭据已经落盘且可用
      //   ⇒ 这里吞掉一切错误（包括网络异常），只记一条 warn。
      //   若把领取失败上抛，用户会以为「登录失败」而重新登录，更糟。
      // ⚠️ 时机：必须在 `credentials.set` **之后** —— 领取要用刚写入的凭据，
      //   且此时 `resolveCredential` 才读得到。
      try {
        const outcome = await claimAutoclawDailyQuota(res.credential, {
          product: this.product,
          ...(this.options.fetcher === undefined ? {} : { fetcher: this.options.fetcher }),
        })
        if (outcome.kind === 'claimed') {
          this.ctx.logger?.info?.(
            `[autoclaw] 登录后自动领取每日积分：${outcome.credit > 0 ? `+${outcome.credit}` : '已领取（数量以上游为准）'}`,
          )
        }
      } catch (error) {
        this.ctx.logger?.warn?.(
          `[autoclaw] 登录后自动领取每日积分失败（不影响登录）：${error instanceof Error ? error.message : String(error)}`,
        )
      }
    }
    return res
  }

  /**
   * 启动 AutoClaw 登录授权流程（本地服务器承载独立登录页，支持短信验证码与一键本地导入）。
   */
  async startLogin(_options?: { refName?: string }): Promise<StartedAutoclawSmsLoginFlow> {
    return startAutoclawSmsLoginFlow({
      product: this.product,
      fetchImpl: this.fetchImpl,
    })
  }
}
