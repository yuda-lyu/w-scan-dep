// 待更新套件計算:對每個被標注之風險套件,自實際相依樹(npm ls)找出所有引入路徑,
// 定位每條路徑中「最底層的自有套件」(fix 起點)——只要它更新其直接依賴(風險套件本身,
// 或引入風險套件之外部中介),再由上層自有套件連鎖重發版,該漏洞即消失。
// 產出 z待更新套件.md:以「底層自有套件」分組列出待更新之外部套件 + 連鎖更新鏈。
import { spawnSync } from 'node:child_process'
import { SELF_OWNED, PACKAGE_NOTES } from './config.mjs'

const isOwn = (node) => node.root === true || SELF_OWNED(node.name)
const normFixed = (f) => (!f || f === '--' || f === '') ? '' : f

// 解析 osv markdown 表格 → 每列 { osvUrl, cvss, pkg, version, fixed }
function parseOsvTable(md) {
    const rows = []
    for (const line of (md || '').split('\n')) {
        if (!/^\|\s*https?:\/\//.test(line)) continue
        const c = line.split('|').map((s) => s.trim())
        // c[0]='' c[1]=url c[2]=cvss c[3]=eco c[4]=pkg c[5]=ver c[6]=fixed c[7]=source
        rows.push({ osvUrl: c[1], cvss: c[2], pkg: c[4], version: c[5], fixed: c[6] })
    }
    return rows
}

// 匯整所有風險葉套件(name@version) + 其修補版 / CVSS / 漏洞 ID
function collectLeaves(scan, exsbom) {
    const map = new Map()
    const get = (name, version) => {
        const k = `${name}@${version}`
        if (!map.has(k)) map.set(k, { name, version, ids: new Set(), cvss: '', fixed: '' })
        return map.get(k)
    }
    for (const r of parseOsvTable(scan.osv.mdText)) {
        const e = get(r.pkg, r.version)
        if (r.osvUrl) e.ids.add(r.osvUrl.split('/').pop())
        if (!e.cvss) e.cvss = r.cvss
        if (!normFixed(e.fixed) && normFixed(r.fixed)) e.fixed = r.fixed
    }
    for (const m of scan.grype.matches) {
        const e = get(m.name, m.version)
        if (m.id) e.ids.add(m.id)
        if (!normFixed(e.fixed) && m.fixedIn) e.fixed = m.fixedIn
    }
    for (const c of exsbom?.componentShots || []) {
        const e = get(c.name, c.version)
        for (const id of c.ids || []) e.ids.add(id)
    }
    return [...map.values()].map((e) => ({ ...e, ids: [...e.ids] }))
}

// npm ls <name> --json(於 target 執行),回傳相依樹;失敗回 null。
// Windows 之 npm 為 npm.cmd,須經 shell;以字串命令避免 DEP0190。
// name 來自掃描結果之套件名,先驗字元避免命令注入。
// npm ls 遇問題會以非 0 結束但 stdout 仍含合法 JSON;偶發空輸出則重試一次。
function npmLs(target, name, log = console.log) {
    if (!/^[@a-z0-9._/-]+$/i.test(name)) return null
    for (let attempt = 0; attempt < 2; attempt++) {
        const r = spawnSync(`npm ls ${name} --json`, {
            cwd: target, encoding: 'utf8', shell: true, maxBuffer: 128 * 1024 * 1024,
        })
        try {
            const j = JSON.parse(r.stdout)
            if (j && typeof j === 'object') return j
        } catch { /* 空或非 JSON,下方重試/回報 */ }
        if (attempt === 1) {
            log(`[update-list] npm ls ${name} 無有效輸出（stdout ${((r.stdout || '').trim().length)} 字元；stderr: ${((r.stderr || '').trim().slice(0, 120))}）`)
        }
    }
    return null
}

// DFS 找出 root→(name@version 節點) 的所有路徑(每節點 {name, version, root?})
function findPaths(tree, leafName, leafVersion) {
    const out = []
    const walk = (node, name, path) => {
        const here = [...path, { name, version: node.version }]
        if (name === leafName && node.version === leafVersion) out.push(here)
        for (const [dn, dnode] of Object.entries(node.dependencies || {})) walk(dnode, dn, here)
    }
    const root = { name: tree.name, version: tree.version, root: true }
    for (const [dn, dnode] of Object.entries(tree.dependencies || {})) walk(dnode, dn, [root])
    return out
}

// 由一條路徑求 fix 起點:最深之自有節點(含 root),其下一節點即待更新之依賴
function fixEdge(path) {
    let lastOwn = 0
    for (let i = 0; i < path.length - 1; i++) if (isOwn(path[i])) lastOwn = i
    const origin = path[lastOwn]
    const dep = path[lastOwn + 1]
    // 連鎖更新鏈:自 fix 起點往上至 root 之自有節點(bottom → top)
    const chain = path.slice(0, lastOwn + 1).filter(isOwn).reverse()
    return { origin, dep, chain }
}

const label = (n) => n.root ? `主系統 package.json（${n.name}）` : n.name

// 計算待更新結構
export function computeUpdateList(target, scan, exsbom, log = console.log) {
    const leaves = collectLeaves(scan, exsbom)
        .filter((l) => !PACKAGE_NOTES[l.name]) // vue/xlsx 屬已知案例(見報告),不列入連鎖更新
    const byOrigin = new Map()   // originLabel -> Map(depKey -> record)
    const cascades = []          // { leaf, chainStr }

    for (const leaf of leaves) {
        const tree = npmLs(target, leaf.name, log)
        if (!tree) { log(`[update-list] npm ls ${leaf.name} 失敗,略過`); continue }
        const paths = findPaths(tree, leaf.name, leaf.version)
        for (const p of paths) {
            const { origin, dep, chain } = fixEdge(p)
            const oLabel = label(origin)
            const direct = dep.name === leaf.name  // fix 起點是否直接依賴風險套件
            if (!byOrigin.has(oLabel)) byOrigin.set(oLabel, new Map())
            const depKey = `${dep.name}@${dep.version}->${leaf.name}@${leaf.version}`
            byOrigin.get(oLabel).set(depKey, {
                depName: dep.name, depVersion: dep.version, direct,
                leafName: leaf.name, leafVersion: leaf.version,
                fixed: normFixed(leaf.fixed), ids: leaf.ids, cvss: leaf.cvss,
            })
            cascades.push({
                leaf: `${leaf.name}@${leaf.version}`,
                chainStr: chain.map((n) => n.root ? '主系統' : n.name).join(' → '),
            })
        }
    }
    return { byOrigin, cascades }
}

// 產製 z待更新套件.md
export function buildUpdateListMd({ target, date, updateList }) {
    const { byOrigin, cascades } = updateList
    const L = []
    L.push('# 待更新套件清單')
    L.push('')
    L.push(`- 產生日期：${date}`)
    L.push(`- 掃描目標：\`${target}\``)
    L.push('')
    L.push('> 原理：每個風險套件都由一或多個「最底層之自有套件」引入。只要該底層自有套件更新其直接依賴')
    L.push('>（風險套件本身，或引入風險套件之外部中介套件），再由上層自有套件連鎖重發版（cascade），')
    L.push('> 該漏洞即可消除。以下依「底層自有套件（修復起點）」分組，列出各自需更新之外部套件。')
    L.push('> 註：vue、xlsx 屬已知案例（框架升級／誤報），詳見掃描報告，不列於本連鎖更新清單。')
    L.push('')

    if (byOrigin.size === 0) {
        L.push('本次無需連鎖更新之項目（未偵測到可經套件更新修復之風險套件，或風險套件均為已知案例）。')
        L.push('')
        return L.join('\n')
    }

    // 依 origin 名稱排序(主系統置頂)
    const origins = [...byOrigin.keys()].sort((a, b) => {
        if (a.startsWith('主系統')) return -1
        if (b.startsWith('主系統')) return 1
        return a.localeCompare(b)
    })

    L.push('## 一、待更新套件（依底層自有套件分組）')
    L.push('')
    for (const o of origins) {
        L.push(`### ${o}`)
        for (const rec of byOrigin.get(o).values()) {
            const ids = rec.ids.length ? `${rec.ids.join(', ')}${rec.cvss ? `, CVSS ${rec.cvss}` : ''}` : (rec.cvss ? `CVSS ${rec.cvss}` : '')
            if (rec.direct) {
                const to = rec.fixed ? `→ ${rec.fixed}` : '→ ⚠ 目前無修補版／需查最新版'
                L.push(`- [ ] 更新 **${rec.depName}**：${rec.depVersion} ${to}`)
                L.push(`  - 清除漏洞：${rec.leafName}@${rec.leafVersion}（${ids}）`)
            } else {
                const need = rec.fixed ? `需其引入之 ${rec.leafName} ≥ ${rec.fixed}` : `目前 ${rec.leafName} 無修補版／需查最新版`
                L.push(`- [ ] 更新 **${rec.depName}**（現 ${rec.depVersion}；其傳遞引入 ${rec.leafName}@${rec.leafVersion}）`)
                L.push(`  - 升至不再引入風險版本之 ${rec.depName}，${need}；或於此自有套件加 npm \`overrides\` 強制 ${rec.leafName}`)
                L.push(`  - 清除漏洞：${rec.leafName}@${rec.leafVersion}（${ids}）`)
            }
        }
        L.push('')
    }

    // 連鎖更新鏈(去重)
    L.push('## 二、連鎖更新鏈（由底層往上重發版之順序）')
    L.push('')
    const seen = new Set()
    const byLeaf = new Map()
    for (const c of cascades) {
        const k = `${c.leaf}|${c.chainStr}`
        if (seen.has(k)) continue
        seen.add(k)
        if (!byLeaf.has(c.leaf)) byLeaf.set(c.leaf, [])
        byLeaf.get(c.leaf).push(c.chainStr)
    }
    for (const [leaf, chains] of [...byLeaf.entries()].sort()) {
        L.push(`- **${leaf}**`)
        for (const ch of chains) L.push(`  - ${ch}`)
    }
    L.push('')
    L.push('> 說明：以「nodemailer」為例，`w-email → w-web-sso → 主系統` 表示先於 w-email 更新 nodemailer 並發版，')
    L.push('> w-web-sso 再更新 w-email 發版，最後主系統更新 w-web-sso。逐層重發即完成連鎖更新。')
    L.push('')
    return L.join('\n')
}
