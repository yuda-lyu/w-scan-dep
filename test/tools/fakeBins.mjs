//測試輔助(不帶.test.中綴, 不被runner當測試檔): 假廠商檔、假套件根與本機伺服器
//外部執行檔之測試不連外網: 廠商檔為小型假檔(壓縮檔以Windows內建tar.exe真實製作), GitHub以本機HTTP伺服器扮演(fetch只改主機指向本機)
import fs from 'fs'
import path from 'path'
import http from 'http'
import crypto from 'crypto'
import { spawnSync } from 'child_process'

export const RAW = 'https://raw.githubusercontent.com'
export const GH = 'https://github.com'

export const sha256 = (buf) => crypto.createHash('sha256').update(buf).digest('hex')

//tar.exe, Windows內建bsdtar(可製作zip; Git Bash之tar為GNU tar不可用)
const tarProg = process.platform === 'win32' ? path.join(process.env.SystemRoot || 'C:\\Windows', 'System32', 'tar.exe') : 'bsdtar'

//makeZip, 以files({ 檔名: Buffer })製作zip並回傳其位元組
export function makeZip(fdWork, files) {
    let src = path.join(fdWork, `zipsrc-${Math.random().toString(36).slice(2, 8)}`)
    fs.mkdirSync(src, { recursive: true })
    for (let [n, c] of Object.entries(files)) {
        fs.writeFileSync(path.join(src, n), c)
    }
    let fpZip = path.join(fdWork, `${path.basename(src)}.zip`)
    let r = spawnSync(tarProg, ['-a', '-cf', fpZip, '-C', src, ...Object.keys(files)], { encoding: 'utf8', windowsHide: true })
    if (r.status !== 0) {
        throw new Error(`tar failed: ${r.stderr}`)
    }
    let buf = fs.readFileSync(fpZip)
    fs.rmSync(src, { recursive: true, force: true })
    fs.rmSync(fpZip, { force: true })
    return buf
}

//TOOLS, 與src/config.mjs之TOOLS對應之廠商repo與資產命名(假版本)
const KINDS = [
    { key: 'syft', name: 'syft.exe', repo: 'anchore/syft', zip: (v) => `syft_${v}_windows_amd64.zip` },
    { key: 'grype', name: 'grype.exe', repo: 'anchore/grype', zip: (v) => `grype_${v}_windows_amd64.zip` },
    { key: 'osv-scanner', name: 'osv-scanner.exe', repo: 'google/osv-scanner', raw: 'osv-scanner_windows_amd64.exe' },
    { key: 'ex-sbom', name: 'ex-sbom.exe', repo: 'nics-tw/ex-sbom', raw: 'ex-sbom.exe' },
]

//makeRelease, 依各工具版本標籤製作假廠商發布: ver為{ syft: '9.9.9', grype: '8.8.8', 'osv-scanner': '7.7.7', 'ex-sbom': '0.2.0' }(標籤為v加版本)
//回傳 { files: 網址路徑→位元組(供伺服器), finals: 檔名→最終檔位元組, manifest: 清單物件(floating, 標籤網址) }
export function makeRelease(fdWork, ver) {
    let files = {}
    let finals = {}
    let entries = []
    for (let k of KINDS) {
        let v = ver[k.key]
        let tag = `v${v}`
        let exe = Buffer.from(`MZ-fake-${k.key}-${v}-`.padEnd(4096, 'x'))
        finals[k.name] = exe
        if (k.zip) {
            let asset = k.zip(v)
            let zip = makeZip(fdWork, { [k.name]: exe, 'LICENSE': Buffer.from('license'), 'README.md': Buffer.from('readme') })
            files[`/${k.repo}/releases/download/${tag}/${asset}`] = zip
            entries.push({
                name: k.name,
                url: `${GH}/${k.repo}/releases/download/${tag}/${asset}`,
                sha256: sha256(zip),
                size: zip.length,
                extract: { type: 'zip', member: k.name, sha256: sha256(exe), size: exe.length },
                note: `${tag}: 測試用假檔`,
            })
        }
        else {
            files[`/${k.repo}/releases/download/${tag}/${k.raw}`] = exe
            entries.push({
                name: k.name,
                url: `${GH}/${k.repo}/releases/download/${tag}/${k.raw}`,
                sha256: sha256(exe),
                size: exe.length,
                note: `${tag}: 測試用假檔`,
            })
        }
    }
    let manifest = {
        schema: 1,
        pkg: 'w-scan-dep',
        mode: 'floating',
        repo: 'yuda-lyu/w-scan-dep',
        files: entries,
    }
    return { files, finals, manifest }
}

//putMirror, 把最終檔依鏡像結構(<鏡像>/<套件>/<sha256>/<name>)放入fd(sha256為最終檔之值)
export function putMirror(fd, manifest, finals) {
    for (let f of manifest.files) {
        let sha = f.extract ? f.extract.sha256 : f.sha256
        let dir = path.join(fd, manifest.pkg, sha)
        fs.mkdirSync(dir, { recursive: true })
        fs.writeFileSync(path.join(dir, f.name), finals[f.name])
    }
}

//makeFakePkg, 於root組一個假套件根: 複製本套件src/(被測程式碼原樣)與給定之基準清單bin/manifest.json
//被安裝為相依套件時之行為(套件根與cwd無關、快取預設於套件根)必須以獨立之套件根測試, 不可寫入本repo之bin-cache/
export function makeFakePkg(root, manifest) {
    fs.rmSync(root, { recursive: true, force: true })
    fs.mkdirSync(path.join(root, 'bin'), { recursive: true })
    fs.cpSync(path.resolve('src'), path.join(root, 'src'), { recursive: true })
    fs.writeFileSync(path.join(root, 'bin/manifest.json'), `${JSON.stringify(manifest, null, 2)}\n`)
    fs.writeFileSync(path.join(root, 'package.json'), JSON.stringify({ name: 'w-scan-dep', version: '0.0.0-test', type: 'module' }))
    return root
}

//listFiles, 遞迴列出資料夾內所有檔案(不存在回傳空陣列)
export function listFiles(fd) {
    if (!fs.existsSync(fd)) {
        return []
    }
    return fs.readdirSync(fd, { recursive: true, withFileTypes: true }).filter((v) => v.isFile()).map((v) => path.join(v.parentPath, v.name))
}

//serve, 本機HTTP伺服器扮GitHub: assets為網址路徑→位元組; routes可動態覆寫(回傳{ status, body }或undefined沿用assets); hits記錄請求路徑
export async function serve(port, assets, routes = () => undefined) {
    let hits = []
    let server = http.createServer((req, res) => {
        hits.push(req.url)
        let r = routes(req.url)
        if (r === undefined) {
            let b = assets[req.url]
            r = b === undefined ? { status: 404, body: Buffer.alloc(0) } : { status: 200, body: b }
        }
        res.writeHead(r.status, { 'content-length': String(r.body.length) })
        res.end(r.body)
    })
    await new Promise((resolve, reject) => {
        server.once('error', reject)
        server.listen(port, '127.0.0.1', resolve)
    })
    return {
        server,
        hits,
        close: () => new Promise((resolve) => {
            server.close(resolve)
        }),
    }
}

//mkFetch, 只接受GitHub與raw.githubusercontent.com之網址並改指本機伺服器, 其餘(外網)一律拋錯; urls記錄被請求之原網址
export function mkFetch(port, urls) {
    return (url, init) => {
        let u = String(url)
        urls.push(u)
        if (u.startsWith(`${RAW}/`)) {
            return globalThis.fetch(u.replace(RAW, `http://127.0.0.1:${port}`), init)
        }
        if (u.startsWith(`${GH}/`)) {
            return globalThis.fetch(u.replace(GH, `http://127.0.0.1:${port}`), init)
        }
        throw new Error(`unexpected url[${u}]`)
    }
}

//fetchBan, 任何網路請求皆視為錯誤(用於斷言未連網)
export function mkFetchBan(urls) {
    return (url) => {
        urls.push(String(url))
        throw new Error(`network access is not allowed in this case[${url}]`)
    }
}

//flip, 複製位元組並反轉第i個位元組(超出長度時改反轉最後一個), 長度不變
export const flip = (buf, i = 1000) => {
    let b = Buffer.from(buf)
    let k = Math.min(i, b.length - 1)
    b[k] = b[k] ^ 0xff
    return b
}

//withEnv, 暫時設定環境變數(值為undefined代表刪除), 結束後還原
export async function withEnv(vars, fun) {
    let old = {}
    for (let k of Object.keys(vars)) {
        old[k] = process.env[k]
        if (vars[k] === undefined) {
            delete process.env[k]
        }
        else {
            process.env[k] = vars[k]
        }
    }
    try {
        return await fun()
    }
    finally {
        for (let k of Object.keys(vars)) {
            if (old[k] === undefined) {
                delete process.env[k]
            }
            else {
                process.env[k] = old[k]
            }
        }
    }
}

export async function catchErr(fun) {
    try {
        await fun()
    }
    catch (err) {
        return err
    }
    return null
}
