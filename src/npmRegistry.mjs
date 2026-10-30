// 隔離安裝沿用呼叫端專案之倉庫位址設定(2026-10-30,主控裁定;規則帳本 R-NPM-REGISTRY-01)。
// 隔離安裝(fdOut/test)只複製 package.json,npm 之專案層設定檔(.npmrc)取自安裝目錄,讀不到呼叫端專案層之 .npmrc;
// 自有套件只發布於私有倉庫,專案方常把 registry= 只寫在專案層,此時隔離安裝改由使用者層／預設倉庫解析,
// 自有套件拿到舊版或 ETARGET,掃描結果與專案實際安裝不符。
// 作法:於呼叫端專案目錄(掃描目標 package.json 所在處)執行 npm config list --json,取 npm 之生效值
// (專案層、使用者層、全域層、環境變數合併後者),只挑 registry 與 @scope:registry,寫入 fdOut/test/.npmrc。
// 為何寫檔而非 CLI 旗標:隔離安裝以 shell:true 啟動(Windows 之 npm 為 npm.cmd),旗標值須經 cmd.exe 解析,網址內之 & % ^ 等字元
// 有誤解析與注入之風險;寫入檔案(值以 JSON 字串引號包住)無此問題,且留有可檢視之證據。專案層設定檔之優先序高於使用者層與全域層,
// 環境變數(npm_config_registry 等)本就照傳給安裝子行程且已含於生效值,故安裝所見與呼叫端專案一致。
// 只帶倉庫位址類:不帶 include／production／dev／also／omit(#27 之 scope: 'dependencies' 不得失真),不帶認證值
// (_authToken、_auth、username、_password 與 registry 網址內嵌之帳密;依主機鍵存於使用者層之認證 npm 本來就讀得到)。
// 取得生效設定失敗(逾時、離開碼非 0、輸出非 JSON、無法啟動、npm 未列出 registry)即拋錯,不退回現行行為:退回會使隔離安裝改由預設倉庫解析,
// 掃描結果與專案實際安裝不符而不自知(本修正所要消除者);且 npm 設定讀取失敗時 npm install 多半同樣失敗,拋錯無額外代價。
// 錯誤訊息與 log 一律不含 npm 之 stdout／stderr 原文與設定值(僅含已去除帳密之倉庫網址),以免洩漏認證值
import { rm, writeFile, access } from 'node:fs/promises'
import { join } from 'node:path'
import { runTool, timeoutMsFromEnv } from './proc.mjs'

export const NPM_CONFIG_TIMEOUT_ENV = 'W_NPM_CONFIG_TIMEOUT'
// npm config list 通常 1~2 秒內結束(冷啟動較慢機器亦在數秒內);預設 60 秒容納極忙之機器
export const NPM_CONFIG_TIMEOUT_DEFAULT = 60

// 時限(毫秒)取自環境變數 W_NPM_CONFIG_TIMEOUT(秒,正數,至多 2147483);未設為預設值,不合法即拋錯(不靜默改用預設)
export function npmConfigTimeoutMs(env = process.env) {
    return timeoutMsFromEnv(NPM_CONFIG_TIMEOUT_ENV, NPM_CONFIG_TIMEOUT_DEFAULT, env)
}

const NPM_CONFIG_CMD = 'npm config list --json'

// 倉庫位址類設定之鍵:預設倉庫 registry 與各 scope 之 @scope:registry(scope 名為網址安全字元:英數與 . _ ~ -)
export const REGISTRY_KEY = /^(registry|@[A-Za-z0-9._~-]+:registry)$/

// 倉庫網址轉為可寫入 .npmrc 者:須為 http(s) 網址;去除內嵌之帳密(認證值不帶)。回傳 { url, strippedAuth }
function cleanRegistryUrl(key, raw) {
    let u
    try {
        u = new URL(raw)
    }
    catch {
        u = null
    }
    if (!u || (u.protocol !== 'http:' && u.protocol !== 'https:')) {
        throw new Error(`呼叫端專案之 npm 設定 ${key} 不是 http(s) 網址,無法沿用於隔離安裝(請以 npm config get ${key} 檢視並修正)`)
    }
    const strippedAuth = u.username !== '' || u.password !== ''
    u.username = ''
    u.password = ''
    return { url: u.href, strippedAuth }
}

/**
 * 自 npm config list --json 之輸出物件(npm 生效值)挑出倉庫位址類設定,其餘一律丟棄
 * @param {Object} conf npm config list --json 解析後之物件
 * @returns {{entries: Array<{key: string, url: string}>, strippedAuth: Array<string>}} entries 依 registry 在前、scope 依鍵名排序;strippedAuth 為網址內嵌帳密被去除之鍵
 */
export function pickRegistrySettings(conf) {
    const entries = []
    const strippedAuth = []
    for (const [key, raw] of Object.entries(conf)) {
        if (!REGISTRY_KEY.test(key) || typeof raw !== 'string' || raw.trim() === '') continue
        const { url, strippedAuth: had } = cleanRegistryUrl(key, raw.trim())
        entries.push({ key, url })
        if (had) strippedAuth.push(key)
    }
    entries.sort((a, b) => (a.key === 'registry' ? -1 : b.key === 'registry' ? 1 : a.key < b.key ? -1 : a.key > b.key ? 1 : 0))
    return { entries, strippedAuth }
}

/**
 * 於呼叫端專案目錄取得 npm 之生效倉庫設定(registry 與 @scope:registry)
 * @param {String} callerDir 呼叫端專案目錄(掃描目標 package.json 所在處)
 * @param {Object} [opt] 選項
 * @param {Number} [opt.timeoutMs] 時限毫秒,預設 60000
 * @param {Object} [opt.env] 執行 npm 用之環境變數,預設 process.env
 * @returns {Promise<{entries: Array<{key: string, url: string}>, strippedAuth: Array<string>}>} 見 pickRegistrySettings
 */
export async function readCallerRegistry(callerDir, { timeoutMs = NPM_CONFIG_TIMEOUT_DEFAULT * 1000, env = process.env } = {}) {
    const fail = (why) => new Error(`無法取得呼叫端專案(${callerDir})生效之 npm 倉庫設定,已中止(不改用隔離資料夾之預設設定,以免掃描結果與專案實際安裝不符):${why}`)
    let r
    try {
        r = await runTool(NPM_CONFIG_CMD, [], { label: NPM_CONFIG_CMD, timeoutMs, envName: NPM_CONFIG_TIMEOUT_ENV, env, cwd: callerDir, shell: true })
    }
    catch (e) {
        throw fail(e.message)
    }
    if (r.status !== 0) throw fail(`${NPM_CONFIG_CMD} 離開碼 ${r.status};請於該資料夾執行 npm config list 檢視原因`)
    let conf
    try {
        conf = JSON.parse(r.stdout)
    }
    catch {
        conf = null //不附 JSON.parse 之訊息:其含輸出片段
    }
    if (!conf || typeof conf !== 'object' || Array.isArray(conf)) throw fail(`${NPM_CONFIG_CMD} 之輸出不是 JSON 物件`)
    const picked = pickRegistrySettings(conf)
    // npm 一律列出 registry(未設時為預設倉庫,npm 12.1.0 實測);缺少者是 npm 把網址內嵌帳密之 registry 視為受保護而不列出
    // (npm config get 亦拒絕),此時無從得知倉庫位址,沿用不了:拋錯而非改用預設倉庫(@scope:registry 內嵌帳密亦被隱藏,但無從與未設區分,見規則帳本已知缺口)
    if (!picked.entries.some((v) => v.key === 'registry')) {
        throw fail(`${NPM_CONFIG_CMD} 未列出 registry(npm 對網址內嵌帳密之 registry 視為受保護而不列出);請勿在 .npmrc 之 registry 網址內嵌帳密,改以 //主機/:_authToken 等依主機鍵設定認證`)
    }
    return picked
}

// 隔離資料夾之 .npmrc 內容(僅倉庫位址;值以 JSON 字串引號包住,ini 解析時還原,網址內之 ; # 不致被當註解)
export function renderNpmrc(entries) {
    return [
        '; w-scan-dep:沿用呼叫端專案生效之 npm 倉庫位址設定(registry、@scope:registry);不含認證值與其他設定',
        ...entries.map(({ key, url }) => `${key}=${JSON.stringify(url)}`),
        '',
    ].join('\n')
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

/**
 * 寫入 testDir/.npmrc。testDir 為本工具之隔離資料夾,其 .npmrc 一律由本函式決定:先刪除既有者(上次執行或他處留下者,
 * 使結果只取決於呼叫端專案之設定),entries 非空再寫入;回驗刪除與寫入。
 * @param {String} testDir 隔離安裝資料夾(fdOut/test)
 * @param {Array<{key: string, url: string}>} entries pickRegistrySettings 之 entries
 * @returns {Promise<String|null>} 寫入之檔案路徑,entries 為空時回傳 null
 */
export async function writeRegistryNpmrc(testDir, entries) {
    const file = join(testDir, '.npmrc')
    try {
        await rm(file, { force: true, maxRetries: 5, retryDelay: 200 })
    }
    catch (e) {
        throw new Error(`清除隔離資料夾內舊的 .npmrc 失敗:${file}(${e.code || e.message})`)
    }
    if (await exists(file)) throw new Error(`清除隔離資料夾內舊的 .npmrc 後仍存在:${file}`)
    if (entries.length === 0) return null
    await writeFile(file, renderNpmrc(entries), 'utf8')
    return file
}

// log 用之倉庫說明(網址已去除帳密)
export const describeRegistry = (entries) => entries.map(({ key, url }) => `${key}=${url}`).join('、')
