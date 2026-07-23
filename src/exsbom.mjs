// ex-sbom 驅動:啟動網頁服務 → playwright 上傳 SBOM → 展開拓撲 →
// 對每個「自身被標注漏洞」之套件(紅色卡片)開啟詳情彈窗並截圖。
// 截圖對應報告範本之 image-1(vue)/image-2(xlsx)彈窗樣式。
import { mkdir, rm } from 'node:fs/promises'
import { spawn, spawnSync } from 'node:child_process'
import { join } from 'node:path'
import { chromium } from 'playwright'
import { SHOTS_DIR, EXSBOM_PORT } from './config.mjs'

const sleep = (ms) => new Promise((r) => setTimeout(r, ms))

// 偵測 ex-sbom 服務端點:優先 IPv6([::1]) 以避開 8080 被其他程式占用時之衝突,
// 再退回 127.0.0.1;僅接受 title 為 ex-sbom 之頁面。
async function detectBaseUrl(port, log) {
    const candidates = [`http://[::1]:${port}`, `http://127.0.0.1:${port}`]
    for (let i = 0; i < 90; i++) {
        for (const base of candidates) {
            try {
                const res = await fetch(base + '/', { signal: AbortSignal.timeout(2000) })
                if (res.ok) {
                    const html = await res.text()
                    if (/<title>\s*ex-sbom\s*<\/title>/i.test(html)) {
                        log(`[ex-sbom] 服務就緒:${base}`)
                        return base
                    }
                }
            } catch { /* 尚未起來 */ }
        }
        await sleep(1000)
    }
    throw new Error('ex-sbom 服務啟動逾時(90s)')
}

// 樹狀終止程序並回驗埠已釋放(§11.4)
function killTree(pid) {
    if (!pid) return
    spawnSync('cmd', ['/c', `taskkill /F /T /PID ${pid}`], { encoding: 'utf8' })
}

// 檢查是否有程式正在 LISTENING 指定埠。於 JS 內解析 netstat(不用 findstr,
// 其空白會被當 OR 分隔且巢狀引號易失真);比對本地位址欄尾之 :port。
function portInUse(port) {
    const r = spawnSync('netstat', ['-ano'], { encoding: 'utf8', maxBuffer: 16 * 1024 * 1024 })
    const hits = (r.stdout || '').split(/\r?\n/).filter((l) => {
        if (!/LISTENING/i.test(l)) return false
        return l.split(/\s+/).some((tok) => tok.endsWith(':' + port))
    })
    return hits.join('\n').trim()
}

// 等彈窗內容載入完成(loading spinner 消失,且漏洞詳情實際 render 完成)
async function waitModalReady(page) {
    const content = page.locator('#component-modal-content')
    await content.locator('.animate-spin').waitFor({ state: 'detached', timeout: 60000 }).catch(() => {})
    // 「此元件漏洞數量 / 此元件無已知漏洞」為詳情 render 完成後必出現之靜態標題
    await content.getByText(/此元件漏洞數量|此元件無已知漏洞/).first().waitFor({ timeout: 60000 })
    await sleep(500) // 收尾 render 穩定
}

// 主流程:回傳 { baseUrl, overviewShot, componentShots:[{name,version,shot}], summary }
export async function captureExSbom(exsbomExe, spdxPath, shotsDir = SHOTS_DIR, log = console.log) {
    await rm(shotsDir, { recursive: true, force: true })
    await mkdir(shotsDir, { recursive: true })

    // 埠 8080 前置檢查:ex-sbom 服務埠固定寫死為 8080 無法變更,
    // 若已被占用則直接報錯並提示,不做 workaround(避免撞上其他服務造成不確定行為)。
    const pre = portInUse(EXSBOM_PORT)
    if (pre) {
        throw new Error(
            `偵測到本機 ${EXSBOM_PORT} port 已被占用，ex-sbom 服務埠固定為 ${EXSBOM_PORT} 無法變更，` +
            `請先關閉占用該埠之程式後再重新執行。\n占用資訊(netstat)：\n${pre}`,
        )
    }

    log('[ex-sbom] 啟動服務 ...')
    // AUTO_OPEN_BROWSER=false:抑制 ex-sbom 啟動時自動開啟使用者預設瀏覽器
    // (ex-sbom 原始碼:AutoOpenBrowser = os.Getenv("AUTO_OPEN_BROWSER") != "false")
    const child = spawn(exsbomExe, [], {
        stdio: 'ignore', windowsHide: true,
        env: { ...process.env, AUTO_OPEN_BROWSER: 'false' },
    })
    const childPid = child.pid

    let browser
    try {
        const baseUrl = await detectBaseUrl(EXSBOM_PORT, log)
        // 全新、無頭、隔離之瀏覽器:playwright 自帶 Chromium + 臨時空白 profile,
        // 與使用者本機之 Edge/Chrome、登入身份、cookie 完全無關,互不影響。
        browser = await chromium.launch({ headless: true })
        const context = await browser.newContext({ viewport: { width: 1440, height: 900 } })
        const page = await context.newPage()
        log('[ex-sbom] 已啟動獨立無頭瀏覽器(全新臨時 profile,不使用使用者身份資料)')
        await page.goto(baseUrl + '/', { waitUntil: 'domcontentloaded' })

        // 切換正體中文(對齊範本截圖語系)
        await page.locator('#lang-zh').click()
        await sleep(300)

        // 上傳 SBOM(syft.spdx.json)
        log('[ex-sbom] 上傳 SBOM 並等待拓撲分析(可能較久)...')
        await page.setInputFiles('#sbom-file-input', spdxPath)

        // 等分頁出現並點選,等拓撲載入
        await page.locator('#file-tabs > div').first().waitFor({ timeout: 60000 })
        await page.locator('#file-tabs > div').first().click().catch(() => {})
        // 等拓撲層級面板出現(loading 文字消失)
        await page.locator('#tab-content').getByText('直接使用之元件').first()
            .waitFor({ timeout: 180000 })
        await sleep(1000)

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

        return { baseUrl, overviewShot, componentShots, summary }
    } finally {
        if (browser) await browser.close().catch(() => {})
        killTree(childPid)
        await sleep(1000)
        const still = portInUse(EXSBOM_PORT)
        // 僅檢查是否仍有「本次 ex-sbom」之殘留(埠可能仍被原占用程式持有,屬正常)
        log(`[ex-sbom] 服務已關閉${still ? '(埠仍有其他程式監聽,非本工具)' : ',埠已釋放'}`)
    }
}
