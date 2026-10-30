// 掃描執行:syft 產 SBOM → grype + osv-scanner 依各自資料庫判斷風險套件。
// 除人類可讀之 table/markdown 外,另產 json 供報告端解析出「被標注漏洞之套件清單」。
import { mkdir, readFile, writeFile, rm } from 'node:fs/promises'
import { basename, join } from 'node:path'
import { OUTPUT_DIR } from './config.mjs'
import { runTool, timeoutMsFromEnv } from './proc.mjs'

// 各掃描工具單次執行之時限:預設值(秒)與調整用之環境變數(秒,正數,至多 2147483;不合法即拋錯)
// 預設依實測定(2026-10-30,1364 個元件之專案:syft 暖 6 秒、冷〔剛安裝之檔案〕81 秒、本機被他程序占滿〔CPU 88%〕時 519 秒;
// grype 冷資料庫〔含下載〕86 秒;osv-scanner 每次 3.5 秒內;見 sgud/exp/experience.md),取實測最大值之 5 倍以上:
// 慢網路、冷啟動或機器忙碌不致誤判逾時,卡住時仍於合理時間內結束。時限為單次執行(osv-scanner 對 markdown 與 json 各跑一次,各自計時)
export const SCAN_TIMEOUTS = {
    'syft': { envName: 'W_SYFT_TIMEOUT', defaultSec: 3600 },
    'grype': { envName: 'W_GRYPE_TIMEOUT', defaultSec: 1800 },
    'osv-scanner': { envName: 'W_OSV_SCANNER_TIMEOUT', defaultSec: 600 },
}

// 讀三個工具之時限(毫秒)
export function scanTimeoutsMs(env = process.env) {
    return Object.fromEntries(Object.entries(SCAN_TIMEOUTS).map(([k, v]) => [k, timeoutMsFromEnv(v.envName, v.defaultSec, env)]))
}

// 執行掃描工具(不經 shell,逾時即結束整個子行程樹並拋錯,見 proc.mjs runTool)
function run(exe, args, label, timeoutMs) {
    const { envName, defaultSec } = SCAN_TIMEOUTS[label]
    return runTool(exe, args, {
        label,
        timeoutMs: timeoutMs ?? timeoutMsFromEnv(envName, defaultSec),
        envName,
        env: { ...process.env, NO_COLOR: '1' }, // 關閉 grype 等之 ANSI 色碼
    }) // 呼叫端自行判斷 status(osv-scanner 有漏洞時回非 0)
}

// syft:產 spdx-json 與 cyclonedx-json
export async function runSyft(syftExe, target, outDir = OUTPUT_DIR, log = console.log, timeoutMs) {
    const name = basename(target) || 'target'
    const spdx = join(outDir, 'syft.spdx.json')
    const cdx = join(outDir, 'syft.cdx.json')
    log('[syft] 產生 SBOM ...')
    const r = await run(syftExe, [
        'scan', `dir:${target}`,
        '--source-name', name,
        '--source-version', '1.0.0',
        '-o', `spdx-json=${spdx}`,
        '-o', `cyclonedx-json=${cdx}`,
    ], 'syft', timeoutMs)
    if (r.status !== 0) throw new Error(`syft 失敗 (code ${r.status}): ${r.stderr}`)
    return { spdx, cdx }
}

// grype:依 cyclonedx SBOM 掃描,產 table(人類)+ json(解析)
export async function runGrype(grypeExe, cdxPath, outDir = OUTPUT_DIR, log = console.log, timeoutMs) {
    const tablePath = join(outDir, 'report(grype).txt')
    const jsonPath = join(outDir, 'grype.json')
    log('[grype] 漏洞掃描 ...')
    const r = await run(grypeExe, [
        `sbom:${cdxPath}`,
        '-o', `table=${tablePath}`,
        '-o', `json=${jsonPath}`,
    ], 'grype', timeoutMs)
    if (r.status !== 0) throw new Error(`grype 失敗 (code ${r.status}): ${r.stderr}`)

    let matches = []
    try {
        const j = JSON.parse(await readFile(jsonPath, 'utf8'))
        matches = (j.matches || []).map((m) => ({
            name: m.artifact?.name,
            version: m.artifact?.version,
            id: m.vulnerability?.id,
            severity: m.vulnerability?.severity,
            fixedIn: (m.vulnerability?.fix?.versions || []).join(', '),
        }))
    }
    catch (e) {
        log(`[grype] json 解析警告: ${e.message}`)
    }
    return { tablePath, jsonPath, matches }
}

// osv-scanner:依 cyclonedx SBOM(-L),產 markdown(嵌入報告)+ json(解析)
export async function runOsv(osvExe, cdxPath, outDir = OUTPUT_DIR, log = console.log, timeoutMs) {
    const mdPath = join(outDir, 'report(osv).md')
    const jsonPath = join(outDir, 'osv.json')
    log('[osv-scanner] 漏洞掃描 ...')
    // 先刪上一次之輸出:osv-scanner 於 exit 127(執行錯誤)、128(SBOM 無套件)時不寫輸出檔、保留既有檔
    // (2026-10-02 實測 v2.4.0),未刪則重跑時讀到上一次之掃描結果
    await rm(mdPath, { force: true })
    await rm(jsonPath, { force: true })
    // osv-scanner 對每種格式各跑一次(--output-file 僅接單一輸出)
    // 離開碼 0:無漏洞、1:有漏洞、128:SBOM 無套件(無輸出檔,視為無漏洞);其餘為執行錯誤
    for (const [fmt, out] of [['markdown', mdPath], ['json', jsonPath]]) {
        const r = await run(osvExe, ['-L', cdxPath, `--format=${fmt}`, `--output-file=${out}`], 'osv-scanner', timeoutMs)
        if (![0, 1, 128].includes(r.status)) throw new Error(`osv-scanner 失敗 (code ${r.status}): ${r.stderr}`)
    }

    let mdText = ''
    try {
        mdText = (await readFile(mdPath, 'utf8')).trim()
    }
    catch { /* SBOM 無套件(exit 128)時無檔 */ }

    // 解析 json → 被標注漏洞之套件清單
    const packages = []
    try {
        const j = JSON.parse(await readFile(jsonPath, 'utf8'))
        for (const res of j.results || []) {
            for (const p of res.packages || []) {
                const vulns = (p.vulnerabilities || []).map((v) => ({
                    id: v.id,
                    summary: v.summary || '',
                    aliases: v.aliases || [],
                }))
                if (vulns.length > 0) {
                    packages.push({
                        name: p.package?.name,
                        version: p.package?.version,
                        ecosystem: p.package?.ecosystem,
                        vulns,
                    })
                }
            }
        }
    }
    catch (e) {
        log(`[osv-scanner] json 解析警告: ${e.message}`)
    }
    return { mdPath, jsonPath, mdText, packages }
}

// 執行完整掃描流程;timeouts 為各工具單次執行之時限(毫秒,見 scanTimeoutsMs),未傳時讀環境變數
export async function runScan(tools, target, outDir = OUTPUT_DIR, log = console.log, timeouts = scanTimeoutsMs()) {
    await mkdir(outDir, { recursive: true })
    const syft = await runSyft(tools['syft'].exePath, target, outDir, log, timeouts['syft'])
    const grype = await runGrype(tools['grype'].exePath, syft.cdx, outDir, log, timeouts['grype'])
    const osv = await runOsv(tools['osv-scanner'].exePath, syft.cdx, outDir, log, timeouts['osv-scanner'])
    return { syft, grype, osv }
}

// 由既有掃描產物載入結果(不重跑 syft/grype/osv);供 --skip-scan 重產報告用
export async function loadScan(outDir = OUTPUT_DIR, log = console.log) {
    const spdx = join(outDir, 'syft.spdx.json')
    const cdx = join(outDir, 'syft.cdx.json')
    const grypeJson = join(outDir, 'grype.json')
    const osvJson = join(outDir, 'osv.json')
    const osvMd = join(outDir, 'report(osv).md')
    log('[skip-scan] 由 output/ 既有產物載入掃描結果 ...')

    let matches = []
    try {
        const j = JSON.parse(await readFile(grypeJson, 'utf8'))
        matches = (j.matches || []).map((m) => ({
            name: m.artifact?.name,
            version: m.artifact?.version,
            id: m.vulnerability?.id,
            severity: m.vulnerability?.severity,
            fixedIn: (m.vulnerability?.fix?.versions || []).join(', '),
        }))
    }
    catch (e) {
        throw new Error(`載入 grype.json 失敗:${e.message}(請先完整掃描一次)`)
    }

    const packages = []
    let mdText = ''
    try {
        mdText = (await readFile(osvMd, 'utf8')).trim()
    }
    catch { /* 無漏洞可能無檔 */ }
    try {
        const j = JSON.parse(await readFile(osvJson, 'utf8'))
        for (const res of j.results || []) {
            for (const p of res.packages || []) {
                const vulns = (p.vulnerabilities || []).map((v) => ({ id: v.id, summary: v.summary || '', aliases: v.aliases || [] }))
                if (vulns.length) packages.push({ name: p.package?.name, version: p.package?.version, ecosystem: p.package?.ecosystem, vulns })
            }
        }
    }
    catch (e) {
        throw new Error(`載入 osv.json 失敗:${e.message}(請先完整掃描一次)`)
    }

    return {
        syft: { spdx, cdx },
        grype: { tablePath: join(outDir, 'report(grype).txt'), jsonPath: grypeJson, matches },
        osv: { mdPath: osvMd, jsonPath: osvJson, mdText, packages },
    }
}
