// WScanDep:依賴套件漏洞掃描之函式化入口。
// 傳入 package.json 位置(fpIn)、輸出資料夾(fdOut)、選項(opt):
//   opt.install:true → 複製 package.json(及 lock)至 fdOut 並執行 npm install,
//                       掃描 fdOut 全新安裝之相依;
//                 false(預設)→ 不安裝,直接掃描來源資料夾既有之 node_modules。
//                 (是否安裝由外部決定:資安驗收多掃「實際交付的 node_modules」故預設不裝)
// 流程:
//   1) (install 時)複製 package.json/lock 至 fdOut 並 npm install
//   2) 下載最新版 syft/grype/osv-scanner/ex-sbom 至 fdOut/tools(隨產出交付業主)並掃描
//   3) ex-sbom 各漏洞套件截圖存 fdOut/pics/*.png
//   4) 檢測數據(含截圖相對路徑 ./pics、結果文字)寫入 fdOut/result.json
//   5) 產製 md 報告(圖以相對路徑 ./pics)寫入 fdOut/result.md
//   6) 連鎖更新清單寫入 fdOut/待更新套件.md
// 回傳 'ok'。
import { mkdir, copyFile, writeFile, access, stat } from 'node:fs/promises'
import { spawnSync } from 'node:child_process'
import { join, basename, resolve, dirname } from 'node:path'
import { TOOLS } from './config.mjs'
import { ensureAllTools } from './download.mjs'
import { runScan } from './scan.mjs'
import { captureExSbom } from './exsbom.mjs'
import { buildReport } from './report.mjs'
import { computeUpdateList, buildUpdateListMd } from './updatelist.mjs'

const exists = async (p) => { try { await access(p); return true } catch { return false } }
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
 * 自動下載最新版syft、grype、osv-scanner、ex-sbom，掃描指定專案之依賴套件，並將檢測數據、markdown報告、連鎖更新清單與ex-sbom各漏洞套件截圖輸出至指定資料夾，僅支援Windows
 *
 * @class
 * @param {String} fpIn 輸入待掃描之package.json檔案路徑字串，亦可傳入含package.json之資料夾路徑字串
 * @param {String} fdOut 輸入輸出資料夾路徑字串，將產出result.json、result.md、待更新套件.md、pics/*.png與tools/(本次使用之掃描工具)
 * @param {Object} [opt={}] 輸入設定物件，預設{}
 * @param {Boolean} [opt.install=false] 輸入是否複製package.json(及package-lock.json)至fdOut並執行npm install，掃描fdOut全新安裝相依之布林值，若給false則不安裝，直接掃描來源資料夾既有之node_modules，預設false
 * @returns {Promise} 回傳Promise，resolve回傳'ok'，reject回傳錯誤訊息
 * @example
 *
 * import wsm from 'w-scan-dep'
 *
 * async function test() {
 *
 *     let fpIn = './test/prj/package.json'
 *     let fdOut = './test/output'
 *     let opt = { install: true }
 *
 *     let r = await wsm(fpIn, fdOut, opt)
 *     console.log(r)
 *     // => 'ok'
 *
 *     // 產出於fdOut:
 *     //   result.json 檢測數據(含各工具版本、osv/grype掃描結果、ex-sbom截圖相對路徑、連鎖更新清單)
 *     //   result.md 掃描報告
 *     //   待更新套件.md 連鎖更新清單
 *     //   pics/*.png ex-sbom拓撲總覽與各漏洞套件截圖
 *     //   tools/ 本次掃描使用之工具執行檔(syft/grype/osv-scanner/ex-sbom,依版本存放)
 *
 * }
 * test()
 *     .catch((err) => {
 *         console.log(err)
 *     })
 *
 */
async function WScanDep(fpIn, fdOut, opt = {}) {
    const log = (m) => console.log(m)
    const install = opt.install === true   // 是否 npm install(預設不裝,掃既有 node_modules)
    const now = new Date()
    const date = isoDate(now)

    const pkgJson = await resolvePackageJson(fpIn)
    const srcDir = dirname(pkgJson)
    const outDir = resolve(fdOut)
    const scanDir = join(outDir, 'scan')   // syft/grype/osv 原始產物
    const picsDir = join(outDir, 'pics')   // ex-sbom 截圖
    const toolsDir = join(outDir, 'tools') // 掃描工具(隨 fdOut 交付業主;各次掃描工具版本可能不同,不跨次共用)

    log('════════════════════════════════════════════')
    log(' WScanDep 依賴套件漏洞掃描')
    log(`  package.json：${pkgJson}`)
    log(`  輸出資料夾：${outDir}`)
    log(`  安裝模式：${install ? 'npm install 全新安裝後掃描' : '掃描來源既有 node_modules(不安裝)'}`)
    log('════════════════════════════════════════════')

    await mkdir(outDir, { recursive: true })

    // 1) 決定掃描目標:install 則複製+安裝至 fdOut;否則掃來源既有 node_modules
    let scanTarget
    if (install) {
        await copyFile(pkgJson, join(outDir, 'package.json'))
        const lock = join(srcDir, 'package-lock.json')
        if (await exists(lock)) {
            await copyFile(lock, join(outDir, 'package-lock.json'))
            log('[copy] 已複製 package.json 與 package-lock.json')
        } else {
            log('[copy] 已複製 package.json(來源無 package-lock.json)')
        }
        log('[npm] 安裝相依(npm install)...')
        const ni = spawnSync('npm install --no-audit --no-fund', {
            cwd: outDir, shell: true, stdio: 'inherit',
        })
        if (ni.status !== 0) throw new Error(`npm install 失敗(exit ${ni.status})`)
        scanTarget = outDir
    } else {
        if (!await exists(join(srcDir, 'node_modules'))) {
            throw new Error(`opt.install 未啟用,但來源資料夾無 node_modules:${srcDir}\n請先於來源安裝相依,或改以 opt.install=true 執行。`)
        }
        scanTarget = srcDir
        log(`[scan] 掃描來源既有 node_modules：${srcDir}`)
    }

    // 2) 下載最新版工具並掃描
    log('[tools] 下載/檢查最新版掃描工具 ...')
    const tools = await ensureAllTools(TOOLS, { toolsDir, log })
    log('[scan] 執行 syft / grype / osv-scanner ...')
    const scan = await runScan(tools, scanTarget, scanDir, log)

    // 3) ex-sbom 網頁截圖(存 fdOut/pics)
    log('[ex-sbom] 網頁展示與截圖 ...')
    const exsbom = await captureExSbom(tools['ex-sbom'].exePath, scan.syft.spdx, picsDir, log)

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

export default WScanDep
