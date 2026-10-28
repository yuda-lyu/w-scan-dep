//產生並更新bin/manifest.json(規格M1: 不手寫sha256與大小; M3: 廠商檔以廠商公告之checksums核對; U2、U3: 主幹模式之更新流程)
//
//本套件為主幹模式(mode為floating, 已於主控帳本G10登記): 掃描工具須保持新版, 故清單放GitHub主幹, 執行時取最新清單; npm包內帶同一份作為基準清單
//各項為廠商發布之版本標籤資產網址(/releases/download/<tag>/<檔>, 不得為releases/latest), 並記壓縮檔與解出之執行檔各自之sha256與大小
//
//用法(於套件根執行, 需連網):
//  node toolg/genBinManifest.mjs                       查四個廠商之最新版, 下載資產與checksums並核對, 寫入bin/manifest.json
//  node toolg/genBinManifest.mjs --dry-run             同上但不寫檔, 只列出與現有清單之差異
//  node toolg/genBinManifest.mjs --only syft,grype     只更新指定工具(syft、grype、osv-scanner、ex-sbom), 其餘沿用現有清單
//  node toolg/genBinManifest.mjs --tag syft=v1.55.0    指定某工具之版本標籤(可重複給), 預設為廠商releases/latest所指之標籤
//  環境變數GITHUB_TOKEN(選填)只用於提高GitHub API之請求額度, 不會輸出
//更新流程(規格U2): 執行本工具 → 跑測試 → 將bin/manifest.json推GitHub即生效(執行時取主幹清單); npm包內之基準清單於下次發布時更新
//核對失敗(雜湊、大小不符, 或checksums與GitHub API之digest不一致)時不寫入任何檔案並以非0結束
import fs from 'fs'
import path from 'path'
import { execFileSync } from 'child_process'
import { fileURLToPath } from 'url'
import fsDownloadFileVerify from 'wsemi/src/fsDownloadFileVerify.mjs'
import fsGetBinManifestEntry from 'wsemi/src/fsGetBinManifestEntry.mjs'


//VENDORS, 各工具之廠商資產定義(只改這段): name為清單之name(執行檔名, 須同src/config.mjs之TOOLS.exeName), asset為Windows資產之名稱樣式(須恰好符合一個),
//checksums為廠商公告之checksums資產名稱樣式(無則null, 清單note記首次下載自算), member為壓縮檔內之執行檔路徑(非壓縮檔者省略)
export const VENDORS = [
    { key: 'syft', name: 'syft.exe', repo: 'anchore/syft', asset: /^syft_[\d.]+_windows_amd64\.zip$/, checksums: /^syft_[\d.]+_checksums\.txt$/, member: 'syft.exe' },
    { key: 'grype', name: 'grype.exe', repo: 'anchore/grype', asset: /^grype_[\d.]+_windows_amd64\.zip$/, checksums: /^grype_[\d.]+_checksums\.txt$/, member: 'grype.exe' },
    { key: 'osv-scanner', name: 'osv-scanner.exe', repo: 'google/osv-scanner', asset: /^osv-scanner_windows_amd64\.exe$/, checksums: /^osv-scanner_SHA256SUMS$/ },
    { key: 'ex-sbom', name: 'ex-sbom.exe', repo: 'nics-tw/ex-sbom', asset: /^ex-sbom\.exe$/, checksums: null },
]


//parseChecksums, 解析checksums文字(每行`<64碼十六進位>  <檔名>`, 檔名前可有*), 回傳Map(檔名→小寫sha256)
export function parseChecksums(text) {
    let m = new Map()
    for (let line of String(text).split(/\r?\n/)) {
        let r = /^([0-9a-fA-F]{64})\s+\*?(.+?)\s*$/.exec(line)
        if (r) {
            m.set(r[2], r[1].toLowerCase())
        }
    }
    return m
}


//tagUrl, 版本標籤之資產網址(規格M2: 不得為releases/latest)
export function tagUrl(repo, tag, name) {
    return `https://github.com/${repo}/releases/download/${encodeURIComponent(tag)}/${encodeURIComponent(name)}`
}


//tagOfUrl, 取清單項url中之版本標籤, 非標籤網址回傳''
export function tagOfUrl(url) {
    let r = /^https:\/\/github\.com\/[^/]+\/[^/]+\/releases\/download\/([^/]+)\//.exec(String(url || ''))
    return r ? decodeURIComponent(r[1]) : ''
}


//tarProg, Windows為內建tar.exe(bsdtar, 須支援zip; Git Bash之tar為GNU tar不可用), 其他系統為bsdtar
let tarProg = process.platform === 'win32' ? path.join(process.env.SystemRoot || 'C:\\Windows', 'System32', 'tar.exe') : 'bsdtar'


//getJson, 取JSON(GitHub API), 失敗拋錯
async function getJson(fetch, url, headers) {
    let res = await fetch(url, { headers })
    if (!res.ok) {
        throw new Error(`HTTP ${res.status}: ${url}`)
    }
    return res.json()
}


//getText, 取文字(checksums), 失敗拋錯
async function getText(fetch, url, headers) {
    let res = await fetch(url, { headers })
    if (!res.ok) {
        throw new Error(`HTTP ${res.status}: ${url}`)
    }
    return res.text()
}


//genEntry, 查單一廠商之發布(opt.tag給了用該標籤, 否則為latest), 下載資產與checksums並核對, 回傳清單項與核對說明
//opt: fetch(預設全域fetch)、api(GitHub API基底, 預設https://api.github.com)、workDir(暫存夾)、today(YYYY-MM-DD, 寫入note)、tag、token
export async function genEntry(v, opt = {}) {
    let fetch = opt.fetch || globalThis.fetch
    let api = opt.api || 'https://api.github.com'
    let headers = { 'User-Agent': 'w-scan-dep-genBinManifest', 'Accept': 'application/vnd.github+json' }
    if (opt.token) {
        headers.Authorization = `Bearer ${opt.token}`
    }

    let release = await getJson(fetch, opt.tag ? `${api}/repos/${v.repo}/releases/tags/${encodeURIComponent(opt.tag)}` : `${api}/repos/${v.repo}/releases/latest`, headers)
    let tag = release.tag_name
    if (typeof tag !== 'string' || tag === '') {
        throw new Error(`${v.key}: release has no tag_name`)
    }
    if (release.draft || release.prerelease) {
        throw new Error(`${v.key}: ${tag} is a draft or prerelease`)
    }
    let assets = Array.isArray(release.assets) ? release.assets : []

    //asset, 恰好符合一個才採用(多個符合時無法判斷, 少於一個即該版無Windows資產)
    let hit = assets.filter((a) => v.asset.test(a.name))
    if (hit.length !== 1) {
        throw new Error(`${v.key}: ${tag} has ${hit.length} asset(s) matching ${v.asset}`)
    }
    let asset = hit[0]

    //兩個獨立來源: 廠商公告之checksums檔(M3), GitHub API之asset.digest(上傳時由GitHub計算); 兩者皆有時必須一致
    let fromSums = ''
    let nameSums = ''
    if (v.checksums) {
        let hs = assets.filter((a) => v.checksums.test(a.name))
        if (hs.length !== 1) {
            throw new Error(`${v.key}: ${tag} has ${hs.length} checksums asset(s) matching ${v.checksums}`)
        }
        nameSums = hs[0].name
        let sums = parseChecksums(await getText(fetch, hs[0].browser_download_url, headers))
        fromSums = sums.get(asset.name) || ''
        if (fromSums === '') {
            throw new Error(`${v.key}: ${nameSums} has no entry for ${asset.name}`)
        }
    }
    let fromApi = /^sha256:([0-9a-f]{64})$/.exec(String(asset.digest || ''))
    fromApi = fromApi ? fromApi[1] : ''
    if (fromSums !== '' && fromApi !== '' && fromSums !== fromApi) {
        throw new Error(`${v.key}: ${asset.name} checksums(${fromSums}) differs from the GitHub API digest(${fromApi})`)
    }
    let expected = fromSums || fromApi
    if (expected === '') {
        throw new Error(`${v.key}: ${asset.name} has neither a checksums file nor a GitHub API digest to verify against`)
    }

    //下載資產(經fsDownloadFileVerify: 暫存檔、sha256與大小驗證後原子更名)
    let fd = path.join(opt.workDir, v.key)
    fs.rmSync(fd, { recursive: true, force: true })
    fs.mkdirSync(fd, { recursive: true })
    let fpAsset = path.join(fd, asset.name)
    await fsDownloadFileVerify(asset.browser_download_url, fpAsset, { sha256: expected, size: asset.size }, { fetch: opt.fetch, maxAttempts: 2 })

    let url = tagUrl(v.repo, tag, asset.name)
    let entry = await fsGetBinManifestEntry(fpAsset, { name: v.name, url })

    //壓縮檔: 解出成員並另記其sha256與大小
    if (v.member) {
        execFileSync(tarProg, ['-xf', asset.name, '--', v.member], { cwd: fd, windowsHide: true })
        let fpMember = path.join(fd, v.member)
        if (!fs.statSync(fpMember).isFile()) {
            throw new Error(`${v.key}: member ${v.member} is not a file`)
        }
        let x = await fsGetBinManifestEntry(fpMember)
        entry.extract = { type: 'zip', member: v.member, sha256: x.sha256, size: x.size }
    }

    let how = nameSums !== ''
        ? `${tag}: SHA-256依廠商公告之${nameSums}核對${fromApi !== '' ? ',且與GitHub API之asset digest一致' : ''}(${opt.today})`
        : `${tag}: 廠商未公告checksums,首次下載自算SHA-256(${opt.today}),且與GitHub API之asset digest一致`
    entry.note = how

    return { key: v.key, tag, asset: asset.name, checksums: nameSums || null, entry }
}


//localDate, 本機時區之日期YYYY-MM-DD(寫入note)
function localDate(d) {
    let p = (n) => String(n).padStart(2, '0')
    return `${d.getFullYear()}-${p(d.getMonth() + 1)}-${p(d.getDate())}`
}


//sameFile, 兩個清單項之來源與校驗值是否相同(忽略note)
function sameFile(a, b) {
    let pick = (f) => JSON.stringify([f.name, f.url, f.sha256, f.size, f.extract || null])
    return !!a && !!b && pick(a) === pick(b)
}


//genManifest, 產生清單物件(不寫檔): only為工具key陣列(省略為全部), tags為{ key: 版本標籤 }, cur為現有清單物件(沿用未更新之項目)
export async function genManifest(opt = {}) {
    let { pkg, cur = null, only = null, tags = {}, log = () => {} } = opt
    let today = opt.today || localDate(new Date())
    let vendors = VENDORS.filter((v) => only === null || only.includes(v.key))
    if (vendors.length === 0) {
        throw new Error(`no vendor selected, available: ${VENDORS.map((v) => v.key).join(', ')}`)
    }
    if (only !== null && cur === null) {
        throw new Error('--only needs an existing bin/manifest.json to keep the other entries')
    }

    let got = new Map()
    let changes = []
    for (let v of vendors) {
        let before = cur && Array.isArray(cur.files) ? cur.files.find((f) => f.name === v.name) : null
        let r = await genEntry(v, { ...opt, tag: tags[v.key] || '', today, workDir: opt.workDir })
        got.set(v.name, r.entry)
        let changed = !sameFile(before, r.entry)
        //來源與校驗值未變時沿用舊note(避免只因日期不同而產生差異)
        if (!changed) {
            r.entry.note = before.note
        }
        changes.push({ key: v.key, from: before ? tagOfUrl(before.url) : '', to: r.tag, changed, checksums: r.checksums })
        log(`${v.key}: ${before ? tagOfUrl(before.url) || '(none)' : '(none)'} -> ${r.tag}  ${changed ? 'CHANGED' : 'same'}  checksums=${r.checksums || 'none(GitHub API digest only)'}`)
    }

    //檔案順序同VENDORS
    let files = VENDORS.map((v) => got.get(v.name) || (cur && cur.files.find((f) => f.name === v.name))).filter((f) => f)
    let manifest = {
        schema: 1,
        pkg,
        mode: 'floating',
        repo: `yuda-lyu/${pkg}`,
        note: '主幹模式(規格M5): 執行時取GitHub主幹之本檔, 取不到時用npm包內之基準清單; 由toolg/genBinManifest.mjs產生, 勿手寫',
        files,
    }
    return { manifest, changes }
}


//main, 命令列入口
async function main() {
    let args = process.argv.slice(2)
    let dry = args.includes('--dry-run')
    let flag = (name) => {
        let i = args.indexOf(name)
        return i >= 0 ? String(args[i + 1] || '') : null
    }
    let onlyArg = flag('--only')
    let only = onlyArg === null ? null : onlyArg.split(',').map((v) => v.trim()).filter((v) => v !== '')
    let tags = {}
    args.forEach((a, i) => {
        if (a === '--tag') {
            let r = /^([\w-]+)=(.+)$/.exec(String(args[i + 1] || ''))
            if (!r) {
                throw new Error('--tag needs <tool>=<tag>, e.g. --tag syft=v1.55.0')
            }
            tags[r[1]] = r[2]
        }
    })

    let pkg = JSON.parse(fs.readFileSync('package.json', 'utf8')).name
    let fpManifest = 'bin/manifest.json'
    let cur = fs.existsSync(fpManifest) ? JSON.parse(fs.readFileSync(fpManifest, 'utf8')) : null
    let workDir = path.resolve('./tmp/genBinManifest')

    try {
        let { manifest, changes } = await genManifest({ pkg, cur, only, tags, workDir, token: process.env.GITHUB_TOKEN || '', log: console.log })
        let text = `${JSON.stringify(manifest, null, 2)}\n`
        let same = cur !== null && text === fs.readFileSync(fpManifest, 'utf8')
        if (dry) {
            console.log(same ? 'dry-run: bin/manifest.json is up to date, nothing would change' : `dry-run: bin/manifest.json would change (${changes.filter((c) => c.changed).map((c) => c.key).join(', ') || 'notes only'}), nothing written`)
        }
        else if (same) {
            console.log('bin/manifest.json is up to date, nothing written')
        }
        else {
            fs.mkdirSync(path.dirname(fpManifest), { recursive: true })
            fs.writeFileSync(fpManifest, text)
            console.log(`bin/manifest.json: written (${manifest.files.length} file(s))`)
        }
    }
    finally {
        fs.rmSync(workDir, { recursive: true, force: true })
    }
}


//僅直接以node執行時進入命令列(被測試匯入時不執行)
if (process.argv[1] && path.resolve(process.argv[1]).toLowerCase() === fileURLToPath(import.meta.url).toLowerCase()) {
    main()
        .catch((err) => {
            console.log(`failed: ${err && err.message ? err.message : err}`)
            process.exit(1)
        })
}
