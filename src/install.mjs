// 掃描目標之 npm 安裝狀態清除:重跑同一 fdOut 時,testDir 內上一次之 package-lock.json 與 node_modules
// 若殘留,npm install 會依舊鎖定檔並沿用已裝套件(僅刪 lock 亦不足),掃到的是「上一次相依樹+本次改動」,
// 不是 package.json 之當前解析結果(2026-10-02 修正,見 建議w-scan-dep修正.md)。
// 只刪 npm 產生之狀態,不刪整個 testDir:fdOut 若誤指專案根目錄,整夾刪除會刪到使用者之 ./test。
// (2026-10-29 修正,見 建議w-scan-dep修正.md(Gitea #24)三:npm install 加時限,逾時即結束整個安裝子行程樹並拋錯,見 npmInstall)
import { rm, access, readFile, readdir } from 'node:fs/promises'
import { spawn } from 'node:child_process'
import { join } from 'node:path'
import { timeoutMsFromEnv, waitChild, killNote, fmtMs } from './proc.mjs'

export const NPM_STATE = ['package-lock.json', 'node_modules']

// npm install 時限之預設(秒):實測 2000 個套件之全新安裝約 4 分鐘(sgud/exp/experience.md §3),取約 5 倍容納較慢之網路與倉庫
export const NPM_INSTALL_TIMEOUT_DEFAULT = 20 * 60

// 時限(毫秒)取自環境變數 W_NPM_INSTALL_TIMEOUT(秒,正數,至多 2147483);未設為預設值,不合法即拋錯(不靜默改用預設)
export function npmInstallTimeoutMs(env = process.env) {
    return timeoutMsFromEnv('W_NPM_INSTALL_TIMEOUT', NPM_INSTALL_TIMEOUT_DEFAULT, env)
}

// 掃描範圍只算 dependencies(2026-10-30,見 建議w-scan-dep調整.md〔Gitea #27〕與 config.mjs 之 SCAN_SCOPE):--omit=dev 使 devDependencies
// (開發與建置工具)及其所附之執行檔不落地,syft 之各編目器(含不分正式或開發之 PE／Go binary 編目器)自然一致;
// 正式套件之對等相依(peerDependencies)、同時為正式套件之相依者(即使 package.json 亦列於 devDependencies)照裝
const NPM_INSTALL_ARGS = '--omit=dev --no-audit --no-fund'

// 會抵消 --omit=dev 之 npm 設定環境變數(2026-10-30 run02,npm 12.1.0 實測;npm 對 omit 與 include 分開記,include 含 dev 即不再省略):
// include=dev、production=false、dev=true、also=dev|development(後三者為 include=dev 之已棄用別名)。
// npm 讀環境變數時前綴不分大小寫(NPM_CONFIG_INCLUDE 亦同),故以 /i 比對。不影響者(實測)不移除:omit、only、optional、NODE_ENV、include=prod、production=true、registry 等。
// 呼叫端專案之 .npmrc 不會被讀到(npm 之專案設定檔取自安裝目錄 fdOut/test 之 package.json 所在處,不往上層找),
// 但使用者層(~/.npmrc)、全域層與 fdOut/test/.npmrc 之同類設定仍會抵消,該三處由安裝後驗證(assertDependenciesOnly)攔下
export const NPM_DEV_OVERRIDE_ENV = /^npm_config_(include|production|dev|also)$/i

// 子行程用之環境變數副本:移除會抵消 --omit=dev 者;只動副本,不改 process.env(呼叫端之環境不受影響)
export function npmInstallEnv(env = process.env) {
    const out = {}
    for (const [k, v] of Object.entries(env)) {
        if (!NPM_DEV_OVERRIDE_ENV.test(k)) out[k] = v
    }
    return out
}

const readJsonIfExists = async (p) => {
    let s
    try {
        s = await readFile(p, 'utf8')
    }
    catch (e) {
        if (e.code === 'ENOENT') return null
        throw new Error(`安裝後無法讀取 ${p} 以驗證掃描範圍(${e.code || e.message}),不輸出 scope: 'dependencies'`)
    }
    try {
        return JSON.parse(s)
    }
    catch (e) {
        throw new Error(`安裝後 ${p} 非有效 JSON 而無法驗證掃描範圍(${e.message}),不輸出 scope: 'dependencies'`)
    }
}

// 安裝後驗證掃描範圍(fail-closed):隔離資料夾內不得有 devDependencies 套件落地,否則拋錯(不輸出 scope: 'dependencies')。
// 依據兩份鎖定檔之 dev 標記(只在開發樹之套件才標 dev:true;同時在正式樹者不標):
//  1. node_modules/.package-lock.json(隱藏鎖定檔,只列實際落地者;npm 12.1.0 實測於 include=dev 時含 dev:true 項、省略成功時無)
//  2. package-lock.json(完整解析結果,省略 dev 時仍含 dev:true 項):dev:true 且其路徑實際存在於磁碟者視為落地
// node_modules 有套件卻兩份鎖定檔皆無時無法驗證,同樣拋錯
export async function assertDependenciesOnly(cwd) {
    const nm = join(cwd, 'node_modules')
    const found = new Set()
    const nameOf = (key) => key.slice(key.lastIndexOf('node_modules/') + 'node_modules/'.length)

    const hidden = await readJsonIfExists(join(nm, '.package-lock.json'))
    for (const [key, v] of Object.entries(hidden?.packages ?? {})) {
        if (key && v?.dev === true) found.add(nameOf(key))
    }
    const lock = await readJsonIfExists(join(cwd, 'package-lock.json'))
    for (const [key, v] of Object.entries(lock?.packages ?? {})) {
        if (key && v?.dev === true && await exists(join(cwd, key))) found.add(nameOf(key))
    }

    if (found.size > 0) {
        const names = [...found].sort()
        const sample = names.slice(0, 5).join('、') + (names.length > 5 ? ` 等 ${names.length} 個` : '')
        throw new Error(
            `隔離安裝(${cwd})裝入了 devDependencies 套件(${sample}),掃描範圍 dependencies 不成立,已中止(不輸出 scope: 'dependencies')。` +
            '成因:npm 設定抵消了 --omit=dev(npm 之 include 含 dev,或 production=false、dev=true、also=dev)。' +
            '本工具已自子行程環境移除 npm_config_include／production／dev／also,故多半來自使用者層設定檔(~/.npmrc)、全域設定檔或安裝資料夾內之 .npmrc;' +
            '請以 npm config list 查出並移除該設定後重跑'
        )
    }

    if (!hidden && !lock) {
        let entries = []
        try {
            entries = (await readdir(nm)).filter((n) => !n.startsWith('.'))
        }
        catch (e) {
            if (e.code !== 'ENOENT') throw new Error(`安裝後無法讀取 ${nm} 以驗證掃描範圍(${e.code || e.message}),不輸出 scope: 'dependencies'`)
        }
        if (entries.length > 0) {
            throw new Error(`隔離安裝(${cwd})之 node_modules 有 ${entries.length} 個項目,卻無 package-lock.json 與 node_modules/.package-lock.json 可驗證掃描範圍,已中止(不輸出 scope: 'dependencies')`)
        }
    }
}

// 於 cwd 執行 npm install;倉庫或網路無回應時 npm 可能久候不止(2026-10-29 提出端曾等約 3.5 小時),
// 逾時即以 taskkill /T 結束整個子行程樹並拋出含「逾時」之錯誤。
// shell:true 時子行程為 cmd.exe,npm 之 node 為其子行程:只結束 cmd.exe 時 npm 仍續跑,故須樹狀結束
// 子行程環境移除會抵消 --omit=dev 者(npmInstallEnv);安裝成功後驗證無 dev 套件落地,否則拋錯(assertDependenciesOnly)
export async function npmInstall(cwd, { timeoutMs = NPM_INSTALL_TIMEOUT_DEFAULT * 1000 } = {}) {
    const child = spawn(`npm install ${NPM_INSTALL_ARGS}`, { cwd, env: npmInstallEnv(), shell: true, stdio: 'inherit', windowsHide: true })
    const r = await waitChild(child, timeoutMs)
    if (r.timedOut) {
        throw new Error(`npm install 逾時(超過 ${fmtMs(timeoutMs)}未完成),${killNote(r, '安裝')};可設環境變數 W_NPM_INSTALL_TIMEOUT(秒)調整時限`)
    }
    if (r.error) throw new Error(`npm install 無法啟動(${r.error.code || r.error.message})`)
    if (r.code !== 0) throw new Error(`npm install 失敗(exit ${r.code})`)
    await assertDependenciesOnly(cwd)
}

const exists = async (p) => {
    try {
        await access(p)
        return true
    }
    catch {
        return false
    }
}

const HINT = 'Windows 下多為檔案或資料夾被占用(編輯器、防毒、終端機停在其內、前次未結束之掃描程序),' +
    '請關閉占用程式或手動刪除後重跑;不以舊內容繼續掃描'

export async function clearNpmState(testDir) {
    for (const name of NPM_STATE) {
        const p = join(testDir, name)
        try {
            // maxRetries:防毒/索引短暫持有檔案時重試(EBUSY、EPERM、ENOTEMPTY)
            await rm(p, { recursive: true, force: true, maxRetries: 5, retryDelay: 200 })
        } catch (e) {
            throw new Error(`清除上次安裝殘留失敗:${p}(${e.code || e.message})。${HINT}`)
        }
        // 回驗:rm 未拋錯不代表已刪除
        if (await exists(p)) throw new Error(`清除上次安裝殘留後仍存在:${p}。${HINT}`)
    }
}
