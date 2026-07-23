// 報告產製:結合範本結構 + 真實掃描資料 + ex-sbom 截圖 + 已知套件說明。
// 產出之 md 內圖片路徑相對於報告檔(位於 ROOT),截圖置於 ROOT/shots。
import { basename } from 'node:path'
import { PACKAGE_NOTES, GUIDE_URL, TOOLS } from './config.mjs'

const REPO_OF = Object.fromEntries(TOOLS.map((t) => [t.key, t.repo]))

// 由掃描結果組出被標注漏洞之套件清單(以 osv 為主,grype 補充)
function flaggedPackages(scan) {
    const map = new Map()
    for (const p of scan.osv.packages) {
        if (!p.name) continue
        map.set(`${p.name}@${p.version}`, {
            name: p.name, version: p.version,
            osvVulns: p.vulns.map((v) => v.id),
            grypeVulns: [],
        })
    }
    for (const m of scan.grype.matches) {
        const k = `${m.name}@${m.version}`
        if (!map.has(k)) map.set(k, { name: m.name, version: m.version, osvVulns: [], grypeVulns: [] })
        map.get(k).grypeVulns.push(m.id)
    }
    return [...map.values()]
}

export function buildReport({ target, toolVersions, scan, exsbom, date, picsPrefix = 'shots/' }) {
    const L = []
    const pkgs = flaggedPackages(scan)
    const rel = (abs) => picsPrefix + basename(abs)

    L.push('# 依賴套件掃描報告')
    L.push('')

    // 掃描資訊
    L.push('## 掃描資訊')
    L.push('')
    L.push(`- 掃描日期：${date}`)
    L.push(`- 掃描目標：\`${target}\``)
    L.push('')
    L.push('本次掃描所下載使用之各工具版本（皆為執行當下之最新版，供業主查核）：')
    L.push('')
    L.push('| 工具 | 版本 | 來源 |')
    L.push('| --- | --- | --- |')
    for (const k of ['syft', 'grype', 'osv-scanner', 'ex-sbom']) {
        if (toolVersions[k]) {
            const repo = REPO_OF[k] ? `https://github.com/${REPO_OF[k]}` : '—'
            L.push(`| ${k} | ${toolVersions[k].version} | ${repo} |`)
        }
    }
    L.push('')

    // 一、掃描技術
    L.push('## 一、依賴套件掃描技術')
    L.push(`基於「SBOM 開源工具使用說明」所提及之工具進行高放主系統之依賴套件掃描：`)
    L.push(GUIDE_URL)
    L.push('')
    L.push('1. 使用 syft 掃描高放主系統安裝依賴')
    L.push('2. 使用 grype 與 osv-scanner 依照各自資料庫去判斷所依賴之風險套件')
    L.push('')
    L.push('註：grype 未列於「Guide_to_SBOM_and_OSV_Tools」，但此為 syft 同家產品，資料庫 osv-scanner 相較更新比較完整。')
    L.push('')

    // 二、掃描結果
    L.push('## 二、掃描結果')
    L.push('')
    L.push('osv-scanner 掃描如下：')
    L.push('')
    L.push(scan.osv.mdText || '(osv-scanner 未回報任何漏洞)')
    L.push('')

    // grype 對照
    if (scan.grype.matches.length) {
        const g = scan.grype.matches.map((m) => `${m.name}(${m.version}) → ${m.id} [${m.severity}]`).join('；')
        L.push(`grype 掃描結果：${g}。`)
    } else {
        L.push('grype 掃描結果：未標注任何漏洞套件。')
    }
    L.push('')

    // ex-sbom 網頁呈現(截圖依套件名、版本排序,呈現較整齊)
    const exShots = [...(exsbom?.componentShots || [])].sort(
        (a, b) => (a.name || '').localeCompare(b.name || '') || (a.version || '').localeCompare(b.version || ''),
    )
    L.push('使用 ex-sbom 通過網頁呈現：')
    L.push('')
    if (exsbom?.overviewShot) {
        L.push(`![ex-sbom 拓撲總覽](${rel(exsbom.overviewShot)})`)
        L.push('')
    }
    for (const c of exShots) {
        L.push(`![${c.name} (${c.version})](${rel(c.shot)})`)
        L.push('')
    }

    // ex-sbom(依其內建漏洞資料庫)判定之漏洞套件清單(與上方截圖逐一對應)
    const exPkgs = exShots
    if (exPkgs.length) {
        const exList = exPkgs.map((c) => `${c.name}(${c.version})`).join('、')
        L.push(`ex-sbom(依其內建漏洞資料庫)判定為漏洞之套件共 ${exPkgs.length} 個，分別為：${exList}。`)
        L.push('')
    }

    // 摘要句(資料驅動)
    if (exsbom?.summary?.length) {
        const lvl = exsbom.summary.map((s) => `${s.title.replace(/\s*[（(].*$/, '').trim()}(${s.badge})`).join('、')
        L.push(`ex-sbom 拓撲分層漏洞概況：${lvl}。`)
        L.push('')
    }

    // 三項工具之綜合(去重,以套件名為單位;各工具資料庫不同故標注範圍略有差異)
    const allNames = new Set([...pkgs.map((p) => p.name), ...exPkgs.map((c) => c.name)].filter(Boolean))
    if (allNames.size) {
        L.push(`綜合 osv-scanner、grype 與 ex-sbom 三項工具(各自資料庫不同)，本次被標注為漏洞之套件(以套件名去重)共 ${allNames.size} 種：${[...allNames].join('、')}。`)
    } else {
        L.push('本次掃描未偵測到被標注為漏洞之套件。')
    }
    L.push('')

    // 已知套件說明(命中 PACKAGE_NOTES 者;三項工具任一標注即納入)
    const notedNames = allNames
    for (const name of Object.keys(PACKAGE_NOTES)) {
        if (notedNames.has(name)) {
            const note = PACKAGE_NOTES[name]
            L.push(note.heading)
            L.push('')
            L.push(note.body)
            L.push('')
        }
    }

    return L.join('\n').replace(/\n{3,}/g, '\n\n').trimEnd() + '\n'
}
