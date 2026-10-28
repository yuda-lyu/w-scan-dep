// 由 ensureBins 取得之執行檔推得各工具之版本標籤(供 result.json 與報告記錄用)。
// 快取路徑為 <快取>/<sha256>/<檔名>,故以「清單項之 sha256(壓縮檔者為解出之檔)等於路徑上的 sha256」判定該清單項即為實際所用之檔,
// 版本標籤取自其廠商網址 /releases/download/<標籤>/。清單來源依序為:本次取得之主幹清單副本(<快取>/manifest-last.json,fsEnsureBins 紀錄用)、套件內基準清單;
// 兩者皆查無對應者為 'unknown'(不因顯示用資訊而中止掃描)。
import { readFile } from 'node:fs/promises'
import { basename, dirname, join } from 'node:path'
import { ROOT, TOOLS } from './config.mjs'

const TAG_RE = /^https:\/\/github\.com\/[^/]+\/[^/]+\/releases\/download\/([^/]+)\//

const shaOf = (f) => (f.extract ? f.extract.sha256 : f.sha256)

async function readManifest(fp) {
    try {
        return JSON.parse(await readFile(fp, 'utf8'))
    }
    catch {
        return null
    }
}

// bins 為 ensureBins 之回傳({ [檔名]: 絕對路徑 }),回傳 { [key]: { key, version, exePath } }
export async function readToolVersions(bins) {
    const out = {}
    for (const t of TOOLS) {
        const exePath = bins[t.exeName]
        const sha = basename(dirname(exePath))
        const sources = [join(dirname(dirname(exePath)), 'manifest-last.json'), join(ROOT, 'bin', 'manifest.json')]
        let version = 'unknown'
        for (const fp of sources) {
            const m = await readManifest(fp)
            const f = m && Array.isArray(m.files) ? m.files.find((v) => v && v.name === t.exeName && shaOf(v) === sha) : null
            const hit = f && typeof f.url === 'string' ? TAG_RE.exec(f.url) : null
            if (hit) {
                version = hit[1]
                break
            }
        }
        out[t.key] = { key: t.key, version, exePath }
    }
    return out
}
