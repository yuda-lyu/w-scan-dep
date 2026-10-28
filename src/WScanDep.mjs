// WScanDep:依賴套件漏洞掃描之函式化入口。
// 傳入 package.json 位置(fpIn)、輸出資料夾(fdOut)。
// (2026-07-23 使用者裁定: 移除 opt.install——一律複製 package.json 至 fdOut/test 全新安裝後掃 test,
//  不複製 lock 由 npm 重新解析產出 package-lock.json; 掃描目標(fdOut/test)與工具夾(fdOut/tools)分離,
//  一併根治「syft 整樹編目把剛下載之掃描工具 exe 一起掃進 SBOM」之自掃污染)
// (2026-10-02 修正: 安裝前先刪除 fdOut/test 內上一次之 package-lock.json 與 node_modules 並回驗,
//  否則重跑時 npm 依舊鎖定檔增量安裝,掃到的是上一次之相依樹)
// (2026-10-03 修正: ex-sbom 改用 fdOut/exsbom-work 內之專用工作目錄、服務埠自 18080 起自動選用並以 PID 確認身分,見 exsbom.mjs;
//  同時掃描多個專案須以不同 node 程序、不同 fdOut 執行)
// (2026-10-29 外部執行檔改依 bin/manifest.json 經 ensureBins(wsemi fsEnsureBins)取得並校驗,存於快取而非 fdOut/tools;
//  移除 opt.fdTools(改由環境變數 W_BIN_CACHE 指定共用快取),見 README〈外部執行檔〉與〈Breaking changes〉)
// 流程:
//   0) 經 ensureBins 取得 syft/grype/osv-scanner/ex-sbom(清單為 bin/manifest.json,校驗 SHA-256 與大小;取不到時即中止,不待 npm install 後才發現)
//   1) 清除 fdOut/test 上次安裝殘留,複製 package.json 並 npm install(產出 package-lock.json 與 node_modules)
//   2) 以上述工具掃描 fdOut/test
//   3) ex-sbom 各漏洞套件截圖存 fdOut/pics/*.png
//   4) 檢測數據(含截圖相對路徑 ./pics、結果文字)寫入 fdOut/result.json
//   5) 產製 md 報告(圖以相對路徑 ./pics)寫入 fdOut/result.md
//   6) 連鎖更新清單寫入 fdOut/待更新套件.md
// 回傳 'ok'。
import { mkdir, copyFile, writeFile, access, stat } from 'node:fs/promises'
import { spawnSync } from 'node:child_process'
import { join, basename, dirname, resolve } from 'node:path'
import { resolveLayout, assertToolsOutside } from './layout.mjs'
import { clearNpmState, NPM_STATE } from './install.mjs'
import ensureBins from './ensureBins.mjs'
import { readToolVersions } from './toolVersions.mjs'
import { runScan } from './scan.mjs'
import { captureExSbom } from './exsbom.mjs'
import { buildReport } from './report.mjs'
import { computeUpdateList, buildUpdateListMd } from './updatelist.mjs'

const exists = async (p) => {
    try {
        await access(p); return true
    }
    catch {
        return false
    }
}
const isoDate = (d) => {
    const p = (n) => String(n).padStart(2, '0')
    return `${d.getFullYear()}-${p(d.getMonth() + 1)}-${p(d.getDate())}`
}

// 解析 fpIn:接受 package.json 檔路徑,或含 package.json 之資料夾
async function resolvePackageJson(fpIn) {
    const abs = resolve(fpIn)
    if ((await stat(abs)).isDirectory()) {
        const p = join(abs, 'package.json')
        if (!await exists(p)) throw new Error(`資料夾內找不到 package.json:${p}`)
        return p
    }
    if (basename(abs) !== 'package.json') throw new Error(`fpIn 需為 package.json 檔或其所在資料夾:${abs}`)
    return abs
}

// updateList(含 Map)序列化為純 JSON
function serializeUpdateList(ul) {
    const origins = [...ul.byOrigin.entries()].map(([origin, m]) => ({ origin, items: [...m.values()] }))
    const seen = new Set()
    const cascades = []
    for (const c of ul.cascades) {
        const k = `${c.leaf}|${c.chainStr}`
        if (seen.has(k)) continue
        seen.add(k)
        cascades.push(c)
    }
    return { origins, cascades }
}

/**
 * 依賴套件漏洞掃描
 *
 * 經ensureBins取得syft、grype、osv-scanner、ex-sbom(依bin/manifest.json校驗SHA-256與大小，首次使用時下載並存於快取)，掃描指定專案之依賴套件，並將檢測數據、markdown報告、連鎖更新清單與ex-sbom各漏洞套件截圖輸出至指定資料夾，僅支援Windows
 *
 * 外部執行檔不含於npm包，快取預設為套件根之bin-cache/，可由環境變數W_BIN_CACHE改位置(多個專案共用同一份)；W_BIN_MIRROR指定離線鏡像，W_BIN_OFFLINE=1時不連網；部署前可預先呼叫WScanDep.ensureBins()，見README〈外部執行檔〉。
 * ex-sbom服務埠自18080起自動選用；同時掃描多個專案須以不同node程序、不同fdOut執行
 *
 * @class
 * @param {String} fpIn 輸入待掃描之package.json檔案路徑字串，亦可傳入含package.json之資料夾路徑字串
 * @param {String} fdOut 輸入輸出資料夾路徑字串，將產出test/(複製package.json全新安裝之掃描目標)、result.json、result.md、待更新套件.md與pics/*.png；掃描工具存於快取，不產出於此
 * @returns {Promise} 回傳Promise，resolve回傳'ok'，reject回傳錯誤訊息
 * @example
 *
 * import wsd from 'w-scan-dep'
 *
 * async function test() {
 *
 *     let fpIn = './test/prj/package.json'
 *     let fdOut = './test/output'
 *
 *     let r = await wsd(fpIn, fdOut)
 *     console.log(r)
 *     // => 'ok'
 *
 *     // 產出於fdOut:
 *     //   result.json 檢測數據(含各工具版本、osv/grype掃描結果、ex-sbom截圖相對路徑、連鎖更新清單)
 *     //   result.md 掃描報告
 *     //   待更新套件.md 連鎖更新清單
 *     //   pics/*.png ex-sbom拓撲總覽與各漏洞套件截圖
 *
 *     // 部署前預先取得掃描工具(連網機器設W_BIN_CACHE=<資料夾>後執行，該資料夾即可作為離線鏡像W_BIN_MIRROR):
 *     // let bins = await wsd.ensureBins()
 *
 * }
 * test()
 *     .catch((err) => {
 *         console.log(err)
 *     })
 *
 */
async function WScanDep(fpIn, fdOut, opt) {
    // 第三參數(原 opt.fdTools)已移除:明確拒絕,避免舊呼叫端以為工具仍放在其指定之資料夾
    if (opt !== undefined && opt !== null) {
        throw new Error('WScanDep 已不接受第三參數 opt(原 opt.fdTools 已移除);掃描工具存於快取,改以環境變數 W_BIN_CACHE 指定,見 README〈外部執行檔〉')
    }

    const log = (m) => console.log(m)
    const now = new Date()
    const date = isoDate(now)

    const pkgJson = await resolvePackageJson(fpIn)
    const layout = resolveLayout(fdOut)
    const { outDir, testDir, scanDir, picsDir, exsbomDir } = layout

    log('════════════════════════════════════════════')
    log(' WScanDep 依賴套件漏洞掃描')
    log(`  package.json：${pkgJson}`)
    log(`  輸出資料夾：${outDir}`)
    log(`  掃描目標：${testDir}(複製 package.json 全新安裝)`)
    log('════════════════════════════════════════════')

    // 0) 經 ensureBins 取得掃描工具(依 bin/manifest.json 校驗;取不到即中止,不待 npm install 數分鐘後才發現)
    log('[tools] 取得/檢查掃描工具(bin/manifest.json,校驗 SHA-256 與大小)...')
    const onProgress = (ev) => {
        if (ev.step === 'manifest' && ev.source === 'baseline') log('[tools] 取不到主幹清單,改用套件內基準清單')
        else if (ev.step === 'download') log(`[tools] 下載 ${ev.name}:${ev.url}`)
        else if (ev.step === 'extract') log(`[tools] 解壓 ${ev.name}(${ev.member})`)
    }
    const bins = await ensureBins({ onProgress })
    assertToolsOutside(Object.values(bins), layout)
    const tools = await readToolVersions(bins)
    log(`  工具快取：${dirname(dirname(bins['syft.exe']))}`)
    for (const [k, v] of Object.entries(tools)) log(`  ${k} ${v.version}：${v.exePath}`)

    await mkdir(outDir, { recursive: true })

    // 1) 複製 package.json 至 fdOut/test 並全新安裝(不複製 lock, 由 npm 重新解析產出 package-lock.json 與 node_modules)
    await mkdir(testDir, { recursive: true })
    log(`[npm] 清除 test 上次安裝殘留(${NPM_STATE.join('、')})...`)
    await clearNpmState(testDir)
    await copyFile(pkgJson, join(testDir, 'package.json'))
    log('[npm] 於 test 全新安裝相依(npm install)...')
    const ni = spawnSync('npm install --no-audit --no-fund', {
        cwd: testDir, shell: true, stdio: 'inherit',
    })
    if (ni.status !== 0) throw new Error(`npm install 失敗(exit ${ni.status})`)
    const scanTarget = testDir

    // 2) 掃描
    log('[scan] 執行 syft / grype / osv-scanner ...')
    const scan = await runScan(tools, scanTarget, scanDir, log)

    // 3) ex-sbom 網頁截圖(存 fdOut/pics;ex-sbom 之工作目錄為 fdOut/exsbom-work 下本次專用子夾,結束後刪除)
    log('[ex-sbom] 網頁展示與截圖 ...')
    const exsbom = await captureExSbom(tools['ex-sbom'].exePath, scan.syft.spdx, picsDir, log, { workRoot: exsbomDir })

    // 4) 檢測數據 result.json(截圖以相對路徑 ./pics)
    const picRel = (abs) => './pics/' + basename(abs)
    const updateList = computeUpdateList(scanTarget, scan, exsbom, log)
    const result = {
        date,
        source: pkgJson,
        outputDir: outDir,
        tools: Object.fromEntries(Object.entries(tools).map(([k, v]) => [k, v.version])),
        osv: { summary: (scan.osv.mdText || '').split('\n').slice(0, 2).join(' ').trim(), markdown: scan.osv.mdText, packages: scan.osv.packages },
        grype: { matches: scan.grype.matches },
        exsbom: {
            overview: exsbom.overviewShot ? picRel(exsbom.overviewShot) : null,
            components: (exsbom.componentShots || []).map((c) => ({
                name: c.name, version: c.version, ids: c.ids, image: picRel(c.shot),
            })),
            levelSummary: exsbom.summary,
        },
        updateList: serializeUpdateList(updateList),
    }
    await writeFile(join(outDir, 'result.json'), JSON.stringify(result, null, 2), 'utf8')

    // 5) md 報告 result.md(圖以相對路徑 ./pics)
    const md = buildReport({ target: pkgJson, toolVersions: tools, scan, exsbom, date, picsPrefix: './pics/' })
    await writeFile(join(outDir, 'result.md'), md, 'utf8')

    // 6) 連鎖更新清單
    const upMd = buildUpdateListMd({ target: pkgJson, date, updateList })
    await writeFile(join(outDir, '待更新套件.md'), upMd, 'utf8')

    log('════════════════════════════════════════════')
    log(' 完成!')
    log(`  ${join(outDir, 'result.json')}`)
    log(`  ${join(outDir, 'result.md')}`)
    log(`  ${join(outDir, '待更新套件.md')}`)
    log(`  ${picsDir}(${(exsbom.componentShots || []).length + 1} 張截圖)`)
    log('════════════════════════════════════════════')
    return 'ok'
}

// ensureBins 以靜態屬性提供(不另加具名匯出,使 UMD 打包後 default 匯出形態不變):供部署前預先取得掃描工具,見 README〈外部執行檔〉
WScanDep.ensureBins = ensureBins

export default WScanDep
