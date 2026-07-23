// 掃描執行:syft 產 SBOM → grype + osv-scanner 依各自資料庫判斷風險套件。
// 除人類可讀之 table/markdown 外,另產 json 供報告端解析出「被標注漏洞之套件清單」。
import { mkdir, readFile, writeFile } from 'node:fs/promises'
import { spawnSync } from 'node:child_process'
import { basename, join } from 'node:path'
import { OUTPUT_DIR } from './config.mjs'

function run(exe, args, label) {
    const r = spawnSync(exe, args, {
        encoding: 'utf8',
        maxBuffer: 64 * 1024 * 1024,
        env: { ...process.env, NO_COLOR: '1' },   // 關閉 grype 等之 ANSI 色碼
    })
    if (r.error) throw new Error(`${label} 執行錯誤: ${r.error.message}`)
    return r   // 呼叫端自行判斷 status(osv-scanner 有漏洞時回非 0)
}

// syft:產 spdx-json 與 cyclonedx-json
export function runSyft(syftExe, target, outDir = OUTPUT_DIR, log = console.log) {
    const name = basename(target) || 'target'
    const spdx = join(outDir, 'syft.spdx.json')
    const cdx = join(outDir, 'syft.cdx.json')
    log('[syft] 產生 SBOM ...')
    const r = run(syftExe, [
        'scan', `dir:${target}`,
        '--source-name', name,
        '--source-version', '1.0.0',
        '-o', `spdx-json=${spdx}`,
        '-o', `cyclonedx-json=${cdx}`,
    ], 'syft')
    if (r.status !== 0) throw new Error(`syft 失敗 (code ${r.status}): ${r.stderr}`)
    return { spdx, cdx }
}

// grype:依 cyclonedx SBOM 掃描,產 table(人類)+ json(解析)
export async function runGrype(grypeExe, cdxPath, outDir = OUTPUT_DIR, log = console.log) {
    const tablePath = join(outDir, 'report(grype).txt')
    const jsonPath = join(outDir, 'grype.json')
    log('[grype] 漏洞掃描 ...')
    const r = run(grypeExe, [
        `sbom:${cdxPath}`,
        '-o', `table=${tablePath}`,
        '-o', `json=${jsonPath}`,
    ], 'grype')
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
    } catch (e) {
        log(`[grype] json 解析警告: ${e.message}`)
    }
    return { tablePath, jsonPath, matches }
}

// osv-scanner:依 cyclonedx SBOM(-L),產 markdown(嵌入報告)+ json(解析)
export async function runOsv(osvExe, cdxPath, outDir = OUTPUT_DIR, log = console.log) {
    const mdPath = join(outDir, 'report(osv).md')
    const jsonPath = join(outDir, 'osv.json')
    log('[osv-scanner] 漏洞掃描 ...')
    // osv-scanner 對每種格式各跑一次(--output-file 僅接單一輸出)
    run(osvExe, ['-L', cdxPath, '--format=markdown', `--output-file=${mdPath}`], 'osv-scanner')
    run(osvExe, ['-L', cdxPath, '--format=json', `--output-file=${jsonPath}`], 'osv-scanner')

    let mdText = ''
    try { mdText = (await readFile(mdPath, 'utf8')).trim() } catch { /* 無漏洞時可能無檔 */ }

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
    } catch (e) {
        log(`[osv-scanner] json 解析警告: ${e.message}`)
    }
    return { mdPath, jsonPath, mdText, packages }
}

// 執行完整掃描流程
export async function runScan(tools, target, outDir = OUTPUT_DIR, log = console.log) {
    await mkdir(outDir, { recursive: true })
    const syft = runSyft(tools['syft'].exePath, target, outDir, log)
    const grype = await runGrype(tools['grype'].exePath, syft.cdx, outDir, log)
    const osv = await runOsv(tools['osv-scanner'].exePath, syft.cdx, outDir, log)
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
            name: m.artifact?.name, version: m.artifact?.version,
            id: m.vulnerability?.id, severity: m.vulnerability?.severity,
            fixedIn: (m.vulnerability?.fix?.versions || []).join(', '),
        }))
    } catch (e) { throw new Error(`載入 grype.json 失敗:${e.message}(請先完整掃描一次)`) }

    const packages = []
    let mdText = ''
    try { mdText = (await readFile(osvMd, 'utf8')).trim() } catch { /* 無漏洞可能無檔 */ }
    try {
        const j = JSON.parse(await readFile(osvJson, 'utf8'))
        for (const res of j.results || []) {
            for (const p of res.packages || []) {
                const vulns = (p.vulnerabilities || []).map((v) => ({ id: v.id, summary: v.summary || '', aliases: v.aliases || [] }))
                if (vulns.length) packages.push({ name: p.package?.name, version: p.package?.version, ecosystem: p.package?.ecosystem, vulns })
            }
        }
    } catch (e) { throw new Error(`載入 osv.json 失敗:${e.message}(請先完整掃描一次)`) }

    return {
        syft: { spdx, cdx },
        grype: { tablePath: join(outDir, 'report(grype).txt'), jsonPath: grypeJson, matches },
        osv: { mdPath: osvMd, jsonPath: osvJson, mdText, packages },
    }
}
