// 外部指令之時限執行與樹狀結束(Windows)。
// (2026-10-30 修正,見 建議w-scan-dep修正.md(Gitea #24)三與主控裁定:npm install、syft、grype、osv-scanner 皆加時限,
//  環境變數以秒指定,逾時即結束整個子行程樹並拋出含「逾時」之錯誤)
// 只結束子行程本身不夠:shell:true 時子行程為 cmd.exe,其下之 npm(node)仍續跑;外部工具亦可能另啟行程。故逾時一律 taskkill /F /T。
import { spawn, spawnSync } from 'node:child_process'
import { join } from 'node:path'

const SYS32 = join(process.env.SystemRoot || 'C:\\Windows', 'System32')
const TIMER_MAX_MS = 2147483647 // setTimeout 之上限(超過時 Node 改為 1 毫秒)
const KILL_WAIT_MS = 10000 // 樹狀結束後等子行程確實結束之上限
const KILL_CMD_MS = 15000 // taskkill 本身之上限(其卡住時時限不致失效)
const STREAM_GRACE_MS = 2000 // 工具結束後等其輸出串流關閉之上限(子孫行程仍握著管道時不無限等)
const TASKKILL_NOT_FOUND = 128 // taskkill 找不到該行程(已先自行結束)
const DECIMAL = /^(\d+(\.\d*)?|\.\d+)([eE][+-]?\d+)?$/ // 十進位正數(含小數、指數);不收 0x10、0b11 等

export const fmtMs = (ms) => (ms >= 60000 && ms % 60000 === 0 ? `${ms / 60000} 分鐘` : `${ms / 1000} 秒`)

// 讀環境變數 name(秒,十進位正數,換算後至少 1 毫秒、至多 2147483 秒)為毫秒;未設或空白為 defaultSec;不合法即拋錯(不靜默改用預設)
export function timeoutMsFromEnv(name, defaultSec, env = process.env) {
    const raw = env[name]
    if (raw === undefined || String(raw).trim() === '') return defaultSec * 1000
    const s = DECIMAL.test(String(raw).trim()) ? Number(raw) : NaN
    if (!Number.isFinite(s) || s * 1000 < 1 || s * 1000 > TIMER_MAX_MS) {
        throw new Error(`環境變數 ${name} 須為正數(秒,至多 ${Math.floor(TIMER_MAX_MS / 1000)}),目前為「${raw}」`)
    }
    return s * 1000
}

// 等 p 解決或 ms 到期(到期回 false;計時器於 p 先解決時清除,不拖住行程結束)
export function within(p, ms) {
    let t
    return Promise.race([
        p.then(() => true),
        new Promise((resolve) => {
            t = setTimeout(() => resolve(false), ms)
        }),
    ]).finally(() => clearTimeout(t))
}

// 結束 pid 與其所有子孫行程;taskkill 失敗時至少結束 pid 本身。回傳 taskkill 之離開碼(128 為已不存在)
export function killTree(pid, child) {
    const k = spawnSync(join(SYS32, 'taskkill.exe'), ['/F', '/T', '/PID', String(pid)], { windowsHide: true, timeout: KILL_CMD_MS })
    if (k.status !== 0 && child) child.kill()
    return k.status
}

// 等 child 結束(event 為 'exit' 或 'close',後者待輸出串流關閉)至多 timeoutMs;逾時即樹狀結束並等其確實結束。
// 回傳 { timedOut: false, code, error } 或 { timedOut: true, pid, killStatus, gone }。
// 時限邊界上子行程剛好自行結束(taskkill 回 128 找不到行程)視為正常結束,不報逾時
export async function waitChild(child, timeoutMs, event = 'exit') {
    const st = { exited: false, code: null, error: null }
    const done = new Promise((resolve) => {
        child.once(event, (code) => {
            st.exited = true
            st.code = code
            resolve()
        })
        child.once('error', (err) => {
            st.exited = true
            st.error = err
            resolve()
        })
    })
    await within(done, timeoutMs)
    if (st.exited) return { timedOut: false, code: st.code, error: st.error }
    const killStatus = killTree(child.pid, child)
    const gone = await within(done, KILL_WAIT_MS)
    if (gone && killStatus === TASKKILL_NOT_FOUND) return { timedOut: false, code: st.code, error: st.error }
    return { timedOut: true, pid: child.pid, killStatus, gone }
}

// 逾時後之結束情形說明(what 為被結束者之稱呼,連同前後間隔,如「安裝」「 syft 」)
export const killNote = (r, what) => (r.gone && r.killStatus === 0
    ? `已結束${what}子行程樹`
    : `結束${what}子行程樹(PID ${r.pid})未確認成功(taskkill 離開碼 ${r.killStatus})`)

/**
 * 於 timeoutMs 內執行 exe(不經 shell),收集其 stdout/stderr(utf8)。
 * 逾時即樹狀結束並拋出「<label> 逾時(超過 …未完成),已結束 <label> 子行程樹;可設環境變數 <envName>(秒)調整時限」;
 * 無法啟動或輸出超過 maxBuffer 位元組拋「<label> 執行錯誤: …」。非 0 離開碼不拋錯,交呼叫端判斷(osv-scanner 有漏洞時回非 0)。
 * 以 exit 判定結束(已結束者不再 taskkill,避免對已被重用之 PID 動手),其後最多再等 STREAM_GRACE_MS 讓輸出串流收尾
 * cwd 為子行程工作目錄(未給用呼叫端之 cwd);shell 為 true 時 exe 為整條指令字串、args 須為空陣列(npm 在 Windows 為 npm.cmd,須經 shell 啟動;
 * 有 args 時 Node 24 對 shell:true 發出 DEP0190 警告),此時子行程為 cmd.exe,逾時之樹狀結束涵蓋其下之 npm
 */
export async function runTool(exe, args, { label, timeoutMs, envName, env, cwd, shell, maxBuffer = 64 * 1024 * 1024 }) {
    let child
    try {
        child = spawn(exe, args, { env, cwd, shell, stdio: ['ignore', 'pipe', 'pipe'], windowsHide: true })
    }
    catch (e) {
        throw new Error(`${label} 執行錯誤: ${e.message}`)
    }
    const closed = new Promise((resolve) => child.once('close', resolve))
    const out = []
    const err = []
    let size = 0
    let overflow = false
    const collect = (chunks) => (d) => {
        size += d.length
        if (size > maxBuffer) {
            if (overflow) return
            overflow = true
            killTree(child.pid, child)
            return
        }
        chunks.push(d)
    }
    child.stdout.on('data', collect(out))
    child.stderr.on('data', collect(err))
    const r = await waitChild(child, timeoutMs, 'exit')
    if (r.timedOut) {
        throw new Error(`${label} 逾時(超過 ${fmtMs(timeoutMs)}未完成),${killNote(r, ` ${label} `)};可設環境變數 ${envName}(秒)調整時限`)
    }
    if (r.error) throw new Error(`${label} 執行錯誤: ${r.error.message}`)
    await within(closed, STREAM_GRACE_MS)
    child.stdout.destroy()
    child.stderr.destroy()
    if (overflow) throw new Error(`${label} 執行錯誤: 輸出超過 ${maxBuffer} 位元組`)
    return { status: r.code, stdout: Buffer.concat(out).toString('utf8'), stderr: Buffer.concat(err).toString('utf8') }
}
