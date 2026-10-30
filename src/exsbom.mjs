// ex-sbom 驅動:啟動網頁服務 → playwright 上傳 SBOM → 展開拓撲 →
// 對每個「自身被標注漏洞」之套件(紅色卡片)開啟詳情彈窗並截圖。
// 截圖對應報告範本之 image-1(vue)/image-2(xlsx)彈窗樣式。
// (2026-10-03 修正,見 建議w-scan-dep修正.md 與三審複審:
//  1) 工作目錄:ex-sbom 把上傳之 SBOM 以原檔名寫入其工作目錄(v0.2.0 util/file/temp_file.go:34),
//     未指定時落在呼叫端 cwd;改為 fdOut/exsbom-work 下本次專用子夾,ex-sbom 結束後刪除。
//  2) 服務埠:ex-sbom 讀 PORT 環境變數(main.go:56-59),改自 EXSBOM_PORT_FIRST 起依序選用。
//  3) 身分:埠被占用時 ex-sbom 以離開碼 0 結束(main.go:78-80 不處理 bind 錯誤),且只綁 127.0.0.1 之服務
//     可與它同埠並存;故就緒須「該埠之監聽 PID 恰為本次子程序」,不能只認頁面標題。)
// (2026-10-29 修正,見 建議w-scan-dep修正.md(Gitea #24):
//  1) ex-sbom v0.2.0 遇相依循環之 SBOM 即無限遞迴而結束:上傳前剔除構成循環之關係(breakDependencyCycles),剔除者回傳供呼叫端呈現;
//  2) 截圖期間意外結束時,錯誤訊息附 ex-sbom.log 之結束原因(exitReasonFromLog),不再只寫「意外結束」。)
// (2026-10-30 修正:埠之監聽者之身分確認改用 wsemi execProcessPortPidsSync(useBoth),不再自行解析 netstat——
//  Windows 11 26300 + KB5127936 之 TCP 狀態值錯誤,netstat 會整列漏列新起之監聽、對外連線反列 LISTENING;
//  選埠用之全表快照仍為 netstat(listeningPorts),漏列只會使之多選到被占用之埠而換埠重試。)
import { mkdir, rm, mkdtemp, readdir, rmdir, readFile, writeFile, open } from 'node:fs/promises'
import { spawn, spawnSync } from 'node:child_process'
import { join, basename } from 'node:path'
import { chromium } from 'playwright'
import execProcessPortPidsSync from 'wsemi/src/execProcessPortPidsSync.mjs'
import { SHOTS_DIR, EXSBOM_PORT_FIRST, EXSBOM_PORT_LAST } from './config.mjs'

const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms))
const SYS32 = join(process.env.SystemRoot || 'C:\\Windows', 'System32')
const TITLE_RE = /<title>\s*ex-sbom\s*<\/title>/i
const SUB_RE = /^(\d+)-[A-Za-z0-9]{6}$/ // 本次專用子夾:<pid>-<mkdtemp 6 碼>
const MAX_ATTEMPTS = 5
const READY_MS = 90000 // 每次嘗試之就緒期限(牆鐘)

// netstat -ano 之 TCP 監聽列 → Map<port, Set<pid>>,只供選埠(listeningPorts)之全表快照。監聽列只以外部位址 0.0.0.0:0/[::]:0 判定,
// 不看狀態欄:在地化之狀態字不可靠,且 Windows 11 26300(KB5127936)之 TCP 狀態值錯誤,對外連線可被列為 LISTENING(2026-10-30 起不再以 LISTENING 為或條件)。
// 該表亦會漏列新起之監聽,故不用於身分確認(見 portListeners)
export function parseNetstat(text) {
    const map = new Map()
    for (const line of String(text).split(/\r?\n/)) {
        const t = line.trim().split(/\s+/)
        if (t[0] !== 'TCP' || t.length < 5) continue
        if (!/^(0\.0\.0\.0|\[::\]):0$/.test(t[2])) continue
        const port = Number(t[1].slice(t[1].lastIndexOf(':') + 1))
        const pid = Number(t[t.length - 1])
        if (!Number.isInteger(port) || !Number.isInteger(pid)) continue
        if (!map.has(port)) map.set(port, new Set())
        map.get(port).add(pid)
    }
    return map
}

// 執行 netstat 取全表快照,只供選埠(漏列只會多選到實際被占用之埠:bind 失敗或身分確認不符即換埠,有 MAX_ATTEMPTS 重試);失敗即拋錯(不可把「查不到」當成「沒人占用」)。
// wsemi 只提供單一埠之查詢,不提供全表;逐埠查詢每次約 1 秒,不適用於掃描整個埠區間
export function listeningPorts() {
    const r = spawnSync(join(SYS32, 'netstat.exe'), ['-ano'], { encoding: 'utf8', maxBuffer: 16 * 1024 * 1024, windowsHide: true })
    if (r.error || r.status !== 0) throw new Error(`netstat 執行失敗:${r.error?.message || `exit ${r.status}`}`)
    return parseNetstat(r.stdout)
}

// netsh 系統保留埠段(Hyper-V/WSL/Docker 等):不出現在 netstat,但 bind 會失敗
export function parseExcluded(text) {
    return String(text).split(/\r?\n/).map((l) => l.match(/^\s*(\d+)\s+(\d+)/)).filter(Boolean).map((m) => [Number(m[1]), Number(m[2])])
}
export function excludedPorts() {
    const out = []
    for (const fam of ['ipv4', 'ipv6']) {
        const r = spawnSync(join(SYS32, 'netsh.exe'), ['int', fam, 'show', 'excludedportrange', 'protocol=tcp'], { encoding: 'utf8', windowsHide: true })
        if (!r.error && r.status === 0) out.push(...parseExcluded(r.stdout))
    }
    return out
}

// 自 first 起依序取第一個未被監聽、非保留、本次未試過之埠;無則 null
export function pickPort(busy, excluded, first, last, tried = new Set()) {
    for (let p = first; p <= last; p++) {
        if (busy.has(p) || tried.has(p)) continue
        if (excluded.some(([s, e]) => p >= s && p <= e)) continue
        return p
    }
    return null
}

// ex-sbom log 分類:fatal=分析失敗(回 200 卻無漏洞資料之偽陰性來源),warn=不影響漏洞判定者
export function classifyExSbomLog(text) {
    const fatal = []
    const warn = []
    let scannedPath = ''
    for (const line of String(text).split(/\r?\n/)) {
        if (/failed to copy and create file|Failed to parse SPDX SBOM|Failed to process SPDX SBOM/.test(line)) fatal.push(line.trim())
        else if (/failed to get scan result/.test(line)) (/no package/i.test(line) ? warn : fatal).push(line.trim())
        else if (/failed to get lev info/.test(line) && !/no CVEs provided/.test(line)) warn.push(line.trim())
        else if (/failed to get name from ref/.test(line)) warn.push(line.trim())
        const m = line.match(/Scanned (.+) file and found \d+ package/)
        if (m) scannedPath = m[1]
    }
    return { fatal, warn, scannedPath }
}

// ex-sbom v0.2.0 之相依深度計算(上游 internal/service/sbom/spdx_sbom.go:140 getSpdxDependencyDepthMap)走訪時不記錄已走過之節點,
// 相依關係含循環(npm 常見,如 es-abstract ⇄ string.prototype.trim)即無限遞迴,以 fatal error: stack overflow 結束(離開碼 2)。
// 其建圖不看關係類型:每筆 relationships 皆為 spdxElementId → relatedSpdxElement 之邊(識別碼去 SPDXRef- 前綴;外部文件參照取其文件名),
// 略過一端為 DOCUMENT、DocumentRoot-*、File-* 者,自入度 0 之節點遞迴。本套件依同一建圖以深度優先走訪找出回邊並剔除,剔除後之圖無循環。
// 只影響 ex-sbom 拓撲之層級呈現;grype 與 osv-scanner 讀 syft 之原檔,不受影響。上游缺陷依專案原則在本套件繞過,不回報上游。
const nodeKey = (id) => {
    const s = String(id)
    if (s.startsWith('DocumentRef-')) return s.slice('DocumentRef-'.length).split(':')[0]
    return s.startsWith('SPDXRef-') ? s.slice('SPDXRef-'.length) : s
}
const isGeneratedNode = (k) => k === 'DOCUMENT' || k.startsWith('DocumentRoot-') || k.startsWith('File-')

// 回傳 { doc, removed }:無循環時 doc 即原物件、removed 為 [];有則 doc 為剔除後之淺複本(原物件不動),
// removed 為 [{ from, to, relationshipType, spdxElementId, relatedSpdxElement }](原 SBOM 中「from relationshipType to」之關係,from/to 為 名稱@版本)
export function breakDependencyCycles(doc) {
    const rels = Array.isArray(doc?.relationships) ? doc.relationships : []
    const adj = new Map() // 節點 → [{ to, i }](i 為 relationships 之索引)
    const indeg = new Map()
    const order = [] // 節點首次出現之順序(使剔除結果可重現)
    const touch = (k) => {
        if (adj.has(k)) return
        adj.set(k, [])
        indeg.set(k, 0)
        order.push(k)
    }
    rels.forEach((r, i) => {
        const a = nodeKey(r?.spdxElementId)
        const b = nodeKey(r?.relatedSpdxElement)
        if (isGeneratedNode(a) || isGeneratedNode(b)) return
        touch(a)
        touch(b)
        adj.get(a).push({ to: b, i })
        indeg.set(b, indeg.get(b) + 1)
    })
    // 深度優先(以堆疊迭代,不受呼叫堆疊限制);先自入度 0 之節點(同 ex-sbom 之起點),再補走不可達之循環。邊指向「走訪中」之節點即回邊
    const state = new Map() // 1 走訪中、2 已完成
    const back = new Set()
    for (const s of [...order.filter((k) => indeg.get(k) === 0), ...order]) {
        if (state.has(s)) continue
        state.set(s, 1)
        const stack = [{ k: s, j: 0 }]
        while (stack.length) {
            const top = stack[stack.length - 1]
            const edges = adj.get(top.k)
            if (top.j >= edges.length) {
                state.set(top.k, 2)
                stack.pop()
                continue
            }
            const { to, i } = edges[top.j++]
            const st = state.get(to)
            if (st === 1) back.add(i)
            else if (!st) {
                state.set(to, 1)
                stack.push({ k: to, j: 0 })
            }
        }
    }
    if (!back.size) return { doc, removed: [] }
    const label = new Map()
    for (const p of doc.packages || []) {
        if (p?.SPDXID && p.name) label.set(p.SPDXID, p.versionInfo ? `${p.name}@${p.versionInfo}` : String(p.name))
    }
    const removed = [...back].sort((x, y) => x - y).map((i) => {
        const r = rels[i]
        return {
            from: label.get(r.spdxElementId) || String(r.spdxElementId),
            to: label.get(r.relatedSpdxElement) || String(r.relatedSpdxElement),
            relationshipType: r.relationshipType,
            spdxElementId: r.spdxElementId,
            relatedSpdxElement: r.relatedSpdxElement,
        }
    })
    return { doc: { ...doc, relationships: rels.filter((_, i) => !back.has(i)) }, removed }
}

// ex-sbom.log 中本次嘗試(最後一個「=== port … ===」標頭之後)之結束原因:Go runtime 於行首輸出之最後一個 fatal error / panic 行
// (含其前之 runtime: 說明行至多 2 行)及其後 after 行;無則取末 3 個非空行。每行至多 300 字、總長至多 maxChars 字
export function exitReasonFromLog(text, { after = 20, maxChars = 1500 } = {}) {
    const all = String(text).split(/\r?\n/)
    let start = 0
    all.forEach((l, i) => {
        if (/^=== port \d+ /.test(l)) start = i + 1
    })
    const lines = all.slice(start)
    const i = lines.findLastIndex((l) => /^(fatal error|panic):/.test(l))
    let pick
    if (i >= 0) {
        let b = i
        while (b > 0 && b > i - 2 && /^runtime: /.test(lines[b - 1])) b--
        pick = lines.slice(b, i + 1 + after)
    }
    else {
        pick = lines.filter((l) => l.trim()).slice(-3)
    }
    let s = pick.map((l) => (l.length > 300 ? `${l.slice(0, 300)}…` : l)).join('\n').trimEnd()
    if (s.length > maxChars) s = `${s.slice(0, maxChars)}…`
    return s
}

// 一次 tasklist 取得 PID → 映像名稱(失敗回空表,只用於提示)
function processNames() {
    const r = spawnSync(join(SYS32, 'tasklist.exe'), ['/FO', 'CSV', '/NH'], { encoding: 'utf8', maxBuffer: 16 * 1024 * 1024, windowsHide: true })
    const map = new Map()
    for (const line of (r.stdout || '').split(/\r?\n/)) {
        const m = line.match(/^"([^"]*)","(\d+)"/)
        if (m) map.set(Number(m[2]), m[1])
    }
    return map
}

function describeOccupants(busy, ports) {
    const names = processNames()
    return ports.map((p) => {
        const who = [...busy.get(p)].map((pid) => `PID ${pid}${names.has(pid) ? `(${names.get(pid)})` : ''}`).join('、')
        const hint = [...busy.get(p)].some((pid) => /^ex-sbom/i.test(names.get(pid) || '')) ? ',為另一個 ex-sbom,可能是殘留或另一個進行中之掃描' : ''
        return `埠 ${p}:${who}${hint}`
    })
}

const isAlive = (pid) => {
    try {
        process.kill(pid, 0)
        return true
    }
    catch (e) {
        return e.code === 'EPERM'
    }
}

// 讀 ex-sbom.log 之結束原因(讀不到回空字串,只用於訊息)
async function logReason(path) {
    try {
        return exitReasonFromLog(await readFile(path, 'utf8'))
    }
    catch {
        return ''
    }
}

const exitText = (st) => (st.code !== null && st.code !== undefined ? `離開碼 ${st.code}` : `訊號 ${st.signal}`)

async function waitExit(st, ms) {
    const end = Date.now() + ms
    while (!st.exited && Date.now() < end) await sleep(100)
    return st.exited
}

// 結束本次子程序:先以 handle 終止(不受 PID 重用影響),仍在才以 PID 樹狀殺;回傳是否已結束
async function stopChild(ex) {
    const { child, st } = ex
    if (st.exited || !child.pid) return true
    child.kill()
    if (await waitExit(st, 5000)) return true
    spawnSync(join(SYS32, 'taskkill.exe'), ['/F', '/T', '/PID', String(child.pid)], { windowsHide: true })
    if (await waitExit(st, 5000)) return true
    child.unref() // 仍無法結束:不讓其 handle 阻止呼叫端退出
    return false
}

// 查詢監聽某埠之 PID 陣列(數字):wsemi execProcessPortPidsSync,useBoth 為 true(Windows 之 netstat 與 Get-NetTCPConnection 取聯集)。
// 本機(Windows 11 26300 + KB5127936)之 TCP 狀態值錯誤,netstat 會整列漏列新起之監聽、對外連線反列 LISTENING,故身分確認不自行解析 netstat;
// netstat 有列出時預設不再查 PowerShell,可能只得部分監聽者(如漏列同埠並存之 127.0.0.1 服務),故一律 useBoth。
// 查詢失敗即拋錯(空陣列才是「已確認無人」,不可把失敗當成沒人占用);訊息取自 wsemi 之 settle 事件。
// opt 供測試注入 { exec, platform, timeout }(exec 為 spawnSync 形,見 wsemi execProcessPortPidsSync)。同步呼叫,Windows 下每次約 1 秒(阻塞事件迴圈)
export function portListeners(port, opt = {}) {
    let msg = ''
    const pids = execProcessPortPidsSync(port, {
        ...opt,
        useBoth: true,
        onTrace: (e) => {
            if (e.type === 'settle') msg = e.msg
        },
    })
    if (pids === null) throw new Error(`查詢埠 ${port} 之監聽者失敗:${msg}`)
    return pids
}

// 該埠之監聽 PID 集合是否恰為 {pid}
export function ownsPort(port, pid, opt = {}) {
    const set = new Set(portListeners(port, opt))
    return { set, ok: set.size === 1 && set.has(pid) }
}

async function probeTitle(port) {
    for (const base of [`http://127.0.0.1:${port}`, `http://[::1]:${port}`]) {
        try {
            const res = await fetch(base + '/', { signal: AbortSignal.timeout(1500) })
            if (res.ok && TITLE_RE.test(await res.text())) return base
        }
        catch { /* 尚未起來 */ }
    }
    return null
}

// 單次啟動:spawn 後等「子程序存活 ∧ 標題為 ex-sbom ∧ 該埠監聽 PID 恰為本子程序」
async function launchOnce(exe, cwd, port, logPath) {
    const fh = await open(logPath, 'a')
    await fh.write(`=== port ${port} ${new Date().toISOString()} ===\n`)
    const st = { exited: false, code: null, signal: null, error: null }
    let child
    try {
        // stdout/stderr 直接寫入本次子夾之 log 檔(檔案描述元,無背壓);覆寫呼叫端可能已設之 PORT
        child = spawn(exe, [], {
            cwd,
            stdio: ['ignore', fh.fd, fh.fd],
            windowsHide: true,
            env: { ...process.env, PORT: String(port), AUTO_OPEN_BROWSER: 'false', GIN_MODE: 'debug' },
        })
        child.on('exit', (code, signal) => {
            st.exited = true
            st.code = code
            st.signal = signal
        })
        child.on('error', (err) => {
            st.exited = true
            st.error = err
        })
    }
    finally {
        await fh.close() // 子程序持有自己之複本
    }
    const ex = { child, st, port, logPath }
    try {
        const end = Date.now() + READY_MS
        while (Date.now() < end) {
            await sleep(300)
            if (st.exited) {
                const why = st.error ? `無法啟動(${st.error.code || st.error.message};exe=${exe};cwd=${cwd})` : `子程序於就緒前結束(${exitText(st)})`
                return { ok: false, reason: why, tail: await logReason(logPath) }
            }
            const baseUrl = await probeTitle(port)
            if (!baseUrl) continue
            const own = ownsPort(port, child.pid)
            if (own.ok) return { ok: true, ...ex, baseUrl }
            if ([...own.set].some((pid) => pid !== child.pid)) {
                await stopChild(ex)
                return { ok: false, reason: `該埠另有監聽者 PID ${[...own.set].filter((pid) => pid !== child.pid).join('、')}` }
            }
        }
        await stopChild(ex)
        return { ok: false, reason: `${READY_MS / 1000} 秒內未就緒`, tail: await logReason(logPath) }
    }
    catch (e) {
        await stopChild(ex).catch(() => {}) // 例如查詢埠之監聽者失敗(portListeners 拋錯):不留下本次子程序
        throw e
    }
}

// 選埠並啟動,最多 MAX_ATTEMPTS 次。opt.snapshot 可注入選埠用之快照(測試用);就緒驗證一律以真實之埠監聽者查詢(portListeners)
export async function startExSbom(exe, cwd, log = console.log, opt = {}) {
    const snapshot = opt.snapshot || listeningPorts
    const first = opt.first ?? EXSBOM_PORT_FIRST
    const last = opt.last ?? EXSBOM_PORT_LAST
    const excluded = excludedPorts()
    const logPath = join(cwd, 'ex-sbom.log')
    const tried = new Set()
    const fails = []
    for (let i = 1; i <= MAX_ATTEMPTS; i++) {
        const busy = snapshot()
        const port = pickPort(busy, excluded, first, last, tried)
        if (port === null) {
            const occ = describeOccupants(busy, [...busy.keys()].filter((p) => p >= first && p <= last).slice(0, 5))
            throw new Error(`ex-sbom 服務埠 ${first}～${last} 無可用之埠(皆被占用、為系統保留埠或已試過)。\n${occ.join('\n')}`)
        }
        tried.add(port)
        const skipped = [...busy.keys()].filter((p) => p >= first && p < port).sort((a, b) => a - b).slice(0, 5)
        if (skipped.length) log(`[ex-sbom] 略過已被占用之埠:${describeOccupants(busy, skipped).join(';')}`)
        const r = await launchOnce(exe, cwd, port, logPath)
        if (r.ok) return r
        fails.push(`埠 ${port}:${r.reason}${r.tail ? `\n${r.tail}` : ''}`)
        log(`[ex-sbom] 埠 ${port} 啟動失敗(${r.reason}),改試下一個埠`)
    }
    throw new Error(`ex-sbom 連續 ${MAX_ATTEMPTS} 次啟動失敗:\n${fails.join('\n')}`)
}

// 清除前次殘留之工作子夾:只清名稱符合樣式、且建立它的程序已不存在者(進行中之他掃描不動)
// (匯出供測試;被占用而刪不掉者記警告並略過)
export async function cleanStaleWork(workRoot, log) {
    let names = []
    try {
        names = await readdir(workRoot)
    }
    catch {
        return
    }
    for (const n of names) {
        const m = n.match(SUB_RE)
        if (!m || isAlive(Number(m[1]))) continue
        try {
            await rm(join(workRoot, n), { recursive: true, force: true, maxRetries: 3, retryDelay: 200 })
        }
        catch (e) {
            log(`[ex-sbom] 警告:無法清除前次殘留之工作子夾 ${join(workRoot, n)}(${e.code || e.message}),略過`)
        }
    }
}

// 等彈窗內容載入完成(loading spinner 消失,且漏洞詳情實際 render 完成)
async function waitModalReady(page) {
    const content = page.locator('#component-modal-content')
    await content.locator('.animate-spin').waitFor({ state: 'detached', timeout: 60000 }).catch(() => {})
    // 「此元件漏洞數量 / 此元件無已知漏洞」為詳情 render 完成後必出現之靜態標題
    await content.getByText(/此元件漏洞數量|此元件無已知漏洞/).first().waitFor({ timeout: 60000 })
    await sleep(500) // 收尾 render 穩定
}

// 主流程:回傳 { baseUrl, port, scannedPath, overviewShot, componentShots:[{name,version,ids,shot}], summary, removedRelationships }
// opt.workRoot 必填(ex-sbom 工作目錄之根,WScanDep 傳 fdOut/exsbom-work);opt.snapshot、opt.onReady、
// opt.breakCycles(false 時不剔除循環,重現 ex-sbom 之原缺陷)供測試。
// 失敗即 reject;此前已算出之剔除清單附於錯誤物件之 removedRelationships
export async function captureExSbom(exsbomExe, spdxPath, shotsDir = SHOTS_DIR, log = console.log, opt = {}) {
    const workRoot = opt.workRoot
    if (!workRoot) throw new Error('captureExSbom 需指定 opt.workRoot(ex-sbom 之工作目錄根)')
    await mkdir(workRoot, { recursive: true })
    await cleanStaleWork(workRoot, log)
    const cwd = await mkdtemp(join(workRoot, `${process.pid}-`))

    let ex
    let browser
    let aborted = false
    let removed = null
    try {
        // 上傳前剔除構成循環之關係(見 breakDependencyCycles);有剔除時上傳本次子夾內之副本(檔名不變),原檔不動
        let uploadPath = spdxPath
        if (opt.breakCycles !== false) {
            let doc
            try {
                doc = JSON.parse(await readFile(spdxPath, 'utf8'))
            }
            catch (e) {
                throw new Error(`無法讀取或解析 SBOM(${spdxPath}):${e.message}`)
            }
            const r = breakDependencyCycles(doc)
            removed = r.removed
            if (removed.length) {
                const dir = join(cwd, 'upload')
                await mkdir(dir)
                uploadPath = join(dir, basename(spdxPath))
                await writeFile(uploadPath, JSON.stringify(r.doc), 'utf8')
                const list = removed.slice(0, 5).map((x) => `${x.from} ${x.relationshipType} ${x.to}`).join(';')
                log(`[ex-sbom] SBOM 之相依關係含循環(ex-sbom v0.2.0 遇之即無限遞迴而結束),上傳之副本剔除 ${removed.length} 筆:${list}${removed.length > 5 ? ' …' : ''}`)
            }
        }

        log('[ex-sbom] 啟動服務 ...')
        ex = await startExSbom(exsbomExe, cwd, log, opt)
        log(`[ex-sbom] 服務就緒:${ex.baseUrl}(PID ${ex.child.pid})`)
        if (opt.onReady) await opt.onReady(ex)

        // 就緒後才重建截圖夾:啟動失敗時不先刪掉上次之截圖
        await rm(shotsDir, { recursive: true, force: true, maxRetries: 3, retryDelay: 200 })
        await mkdir(shotsDir, { recursive: true })

        // 就緒後子程序若結束即中止:該埠可能被他掃描接手,前端之相對網址會打到對方。訊息附 log 之結束原因(子程序已結束,log 已完整)
        let diedFired = false
        const died = new Promise((resolve, reject) => {
            const fail = () => {
                diedFired = true
                logReason(ex.logPath).then((why) => {
                    reject(new Error(`ex-sbom(PID ${ex.child.pid})於截圖期間意外結束(${exitText(ex.st)}),本次截圖作廢${why ? `;ex-sbom.log 摘錄:\n${why}` : ''}`))
                })
            }
            if (ex.st.exited) fail()
            else ex.child.once('exit', fail)
        })
        died.catch(() => {})

        const flow = (async () => {
            const baseUrl = ex.baseUrl
            // 全新、無頭、隔離之瀏覽器:playwright 自帶 Chromium + 臨時空白 profile,
            // 與使用者本機之 Edge/Chrome、登入身份、cookie 完全無關,互不影響。
            browser = await chromium.launch({ headless: true })
            if (aborted) {
                await browser.close().catch(() => {}) // 啟動瀏覽器期間已中止:finally 先跑完了,自行關閉
                throw new Error('aborted')
            }
            const context = await browser.newContext({ viewport: { width: 1440, height: 900 } })
            const page = await context.newPage()
            log('[ex-sbom] 已啟動獨立無頭瀏覽器(全新臨時 profile,不使用使用者身份資料)')
            await page.goto(baseUrl + '/', { waitUntil: 'domcontentloaded' })

            // 切換正體中文(對齊範本截圖語系)
            await page.locator('#lang-zh').click()
            await sleep(300)

            // 上傳 SBOM(syft.spdx.json)
            log('[ex-sbom] 上傳 SBOM 並等待拓撲分析(可能較久)...')
            await page.setInputFiles('#sbom-file-input', uploadPath)

            // 等分頁出現並點選,等拓撲載入
            await page.locator('#file-tabs > div').first().waitFor({ timeout: 60000 })
            await page.locator('#file-tabs > div').first().click().catch(() => {})
            // 等拓撲層級面板出現(loading 文字消失)
            await page.locator('#tab-content').getByText('直接使用之元件').first()
                .waitFor({ timeout: 180000 })
            await sleep(1000)

            // ex-sbom 處理上傳為同步(create.go:125→166),拓撲出現時其 log 已完整;
            // 分析失敗仍回 200 且畫面顯示「無漏洞」,故以其 log 判定
            const lg = classifyExSbomLog(await readFile(ex.logPath, 'utf8').catch(() => ''))
            if (lg.fatal.length) throw new Error(`ex-sbom 分析 SBOM 失敗,截圖將誤呈無漏洞,中止:\n${lg.fatal.join('\n')}`)
            for (const w of lg.warn) log(`[ex-sbom] 警告:${w}`)
            if (!lg.scannedPath) log('[ex-sbom] 警告:未見 ex-sbom 之掃描紀錄(Scanned …),請確認截圖內容')

            // 讀取各層漏洞徽章摘要(層 header,不受展開影響)
            const summary = await page.evaluate(() => {
                const out = []
                document.querySelectorAll('#tab-content .mb-6.border').forEach((panel) => {
                    const title = panel.querySelector('.font-medium')?.textContent?.trim() || ''
                    const badge = panel.querySelector('.rounded-full')?.textContent?.trim() || ''
                    out.push({ title, badge })
                })
                return out
            })

            // 拓撲總覽截圖:於「展開全部元件之前」擷取(各層預設每層列 10 個+漏洞徽章),
            // 避免展開第 0 級 682 個元件後整頁高達數萬 px。
            const overviewShot = join(shotsDir, 'topology-overview.png')
            await page.screenshot({ path: overviewShot, fullPage: true })
            log('[ex-sbom] 已截圖:拓撲總覽')

            // 展開所有「顯示所有 N 個元件」以免漏掉排序在後之漏洞套件。
            // 逐一點擊並每次重新查詢(避免大層 re-render 造成其他按鈕 stale ref),
            // 直到全部層級都無「顯示所有」按鈕為止(含深層如第 3 級之 vue)。
            for (let guard = 0; guard < 50; guard++) {
                const btn = page.locator('button:has-text("顯示所有")').first()
                if (await btn.count() === 0) break
                await btn.scrollIntoViewIfNeeded().catch(() => {})
                await btn.click().catch(() => {})
                await sleep(300)
            }
            await sleep(500)

            // 收集所有「自身有漏洞」之紅色套件卡片
            const redCards = page.locator('#tab-content .bg-red-50.cursor-pointer')
            const count = await redCards.count()
            log(`[ex-sbom] 偵測到 ${count} 個被標注漏洞之套件卡片`)

            const componentShots = []
            const seen = new Set()
            for (let i = 0; i < count; i++) {
                const card = redCards.nth(i)
                await card.scrollIntoViewIfNeeded().catch(() => {})
                await card.click()
                const modal = page.locator('#component-modal')
                await modal.waitFor({ state: 'visible', timeout: 15000 })
                await waitModalReady(page)

                // 讀取套件名稱/版本(彈窗內容),供去重與檔名/報告標題
                const meta = await page.evaluate(() => {
                    const c = document.getElementById('component-modal-content')
                    const grab = (label) => {
                        const h = Array.from(c.querySelectorAll('h3')).find((x) => x.textContent.includes(label))
                        return h?.nextElementSibling?.textContent?.trim() || ''
                    }
                    const name = grab('元件名稱')
                    const version = grab('版本').split('\n')[0].trim()
                    // 抓漏洞 ID(CVE/GHSA)文字
                    const ids = Array.from(new Set((c.textContent.match(/(CVE-\d{4}-\d+|GHSA-[a-z0-9]{4}-[a-z0-9]{4}-[a-z0-9]{4})/gi) || [])))
                    return { name, version, ids }
                })

                const key = `${meta.name}@${meta.version}`
                if (!seen.has(key) && meta.name) {
                    seen.add(key)
                    const safe = key.replace(/[^\w.@-]+/g, '_')
                    const shot = join(shotsDir, `vuln-${safe}.png`)
                    const modalCard = page.locator('#component-modal > div')
                    await modalCard.screenshot({ path: shot })
                    componentShots.push({ name: meta.name, version: meta.version, ids: meta.ids, shot })
                    log(`[ex-sbom] 已截圖:${key}  漏洞=${meta.ids.join(', ') || '(未解析ID)'}`)
                }

                // 關閉彈窗
                await page.locator('#component-modal-close').click().catch(() => {})
                await modal.waitFor({ state: 'hidden', timeout: 10000 }).catch(() => {})
                await sleep(200)
            }

            // 回傳前重驗:截圖全程之服務仍為本次子程序
            const own = ownsPort(ex.port, ex.child.pid)
            if (!own.ok) {
                const who = describeOccupants(new Map([[ex.port, own.set]]), [ex.port]).join('')
                throw new Error(`截圖完成時埠 ${ex.port} 之監聽者已非本次 ex-sbom(PID ${ex.child.pid};現為 ${who || '無'}),本次截圖作廢`)
            }
            return { baseUrl, port: ex.port, scannedPath: lg.scannedPath, overviewShot, componentShots, summary, removedRelationships: removed ?? [] }
        })()
        flow.catch(() => {})
        try {
            return await Promise.race([flow, died])
        }
        catch (e) {
            // 子程序已結束時以其結束原因(含 log 摘錄)為準:頁面操作可能因服務消失而先失敗、exit 事件稍後才處理,故先短暫等之
            if (!diedFired) await waitExit(ex.st, 2000)
            if (diedFired) await died
            throw e
        }
    }
    catch (e) {
        if (removed && e instanceof Error) e.removedRelationships = removed
        throw e
    }
    finally {
        // 各步只記錄、不拋錯,不遮蔽原錯誤
        aborted = true
        if (browser) await browser.close().catch(() => {})
        if (ex) {
            const gone = await stopChild(ex).catch(() => false)
            let still = false
            try {
                still = portListeners(ex.port).includes(ex.child.pid)
            }
            catch {
                still = true // 查詢失敗:無從確認,不宣稱埠已釋放(只影響訊息)
            }
            log(`[ex-sbom] 服務${gone && !still ? '已關閉,埠已釋放' : `可能未完全關閉(PID ${ex.child.pid},埠 ${ex.port})`}`)
        }
        try {
            await rm(cwd, { recursive: true, force: true, maxRetries: 5, retryDelay: 200 })
        }
        catch (e) {
            log(`[ex-sbom] 警告:無法刪除工作子夾 ${cwd}(${e.code || e.message}),交付前可手動刪除`)
        }
        await rmdir(workRoot).catch(() => {}) // 空了才刪
    }
}
