// 掃描工具下載:自 GitHub latest release 取當前最新版,依版本快取。
// 已存在對應版本之 exe 即略過下載(滿足「取最新版」又不重複下載);
// 傳 force=true 可強制重抓。zip 資產以 Windows 內建 bsdtar 解壓。
import { mkdir, writeFile, access, rm, readdir } from 'node:fs/promises'
import { join } from 'node:path'
import { spawnSync } from 'node:child_process'
import { TOOLS_DIR } from './config.mjs'

const GH_HEADERS = { 'User-Agent': 'dependency-scan-automation', 'Accept': 'application/vnd.github+json' }

// Windows 內建 bsdtar(可解 zip);不用 git 的 GNU tar(不支援 zip)
const BSDTAR = join(process.env.SystemRoot || 'C:\\Windows', 'System32', 'tar.exe')

async function exists(p) {
    try { await access(p); return true } catch { return false }
}

async function fetchLatestRelease(repo) {
    const url = `https://api.github.com/repos/${repo}/releases/latest`
    const res = await fetch(url, { headers: GH_HEADERS })
    if (!res.ok) {
        const body = await res.text().catch(() => '')
        throw new Error(`GitHub API ${res.status} for ${repo}: ${body.slice(0, 200)}`)
    }
    return res.json()
}

async function downloadTo(url, dest) {
    const res = await fetch(url, { headers: GH_HEADERS, redirect: 'follow' })
    if (!res.ok) throw new Error(`下載失敗 ${res.status}: ${url}`)
    const buf = Buffer.from(await res.arrayBuffer())
    await writeFile(dest, buf)
    return buf.length
}

// 以 bsdtar 解壓 zip,並回傳解壓目錄內第一個符合 exeName 的絕對路徑
async function unzipAndFindExe(zipPath, destDir, exeName) {
    const r = spawnSync(BSDTAR, ['-xf', zipPath, '-C', destDir], { encoding: 'utf8' })
    if (r.status !== 0) throw new Error(`解壓失敗 (${BSDTAR}): ${r.stderr || r.error?.message}`)
    // syft/grype 之 zip 解壓後 exe 位於根層
    const direct = join(destDir, exeName)
    if (await exists(direct)) return direct
    // 保險:遞迴尋找
    const found = await findFile(destDir, exeName)
    if (!found) throw new Error(`解壓後找不到 ${exeName} 於 ${destDir}`)
    return found
}

async function findFile(dir, name) {
    for (const ent of await readdir(dir, { withFileTypes: true })) {
        const p = join(dir, ent.name)
        if (ent.isDirectory()) {
            const sub = await findFile(p, name)
            if (sub) return sub
        } else if (ent.name === name) {
            return p
        }
    }
    return null
}

// 確保單一工具就緒,回傳 { key, version, exePath }
export async function ensureTool(tool, { force = false, log = console.log, toolsDir = TOOLS_DIR } = {}) {
    log(`[${tool.key}] 查詢最新版本...`)
    const rel = await fetchLatestRelease(tool.repo)
    const version = rel.tag_name || 'unknown'
    const verDir = join(toolsDir, tool.key, version)
    const exePath = join(verDir, tool.exeName)

    if (!force && await exists(exePath)) {
        log(`[${tool.key}] 已有最新版 ${version}(快取),略過下載`)
        return { key: tool.key, version, exePath }
    }

    const asset = (rel.assets || []).find((a) => tool.matchAsset(a.name))
    if (!asset) throw new Error(`[${tool.key}] ${version} 找不到符合的 Windows 資產`)

    await rm(verDir, { recursive: true, force: true })
    await mkdir(verDir, { recursive: true })
    log(`[${tool.key}] 下載 ${asset.name} (${version}) ...`)

    if (tool.kind === 'zip') {
        const zipPath = join(verDir, asset.name)
        const bytes = await downloadTo(asset.browser_download_url, zipPath)
        log(`[${tool.key}] 下載完成 ${(bytes / 1048576).toFixed(1)}MB,解壓中...`)
        const found = await unzipAndFindExe(zipPath, verDir, tool.exeName)
        await rm(zipPath, { force: true })
        return { key: tool.key, version, exePath: found }
    } else {
        const bytes = await downloadTo(asset.browser_download_url, exePath)
        log(`[${tool.key}] 下載完成 ${(bytes / 1048576).toFixed(1)}MB`)
        return { key: tool.key, version, exePath }
    }
}

// 確保所有工具就緒,回傳 { syft, grype, 'osv-scanner', 'ex-sbom' } → {version, exePath}
export async function ensureAllTools(tools, opts = {}) {
    const out = {}
    for (const t of tools) {
        out[t.key] = await ensureTool(t, opts)
    }
    return out
}
