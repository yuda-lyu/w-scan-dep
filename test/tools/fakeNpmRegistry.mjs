//本機假 npm registry(npm_config_registry 指向 url): 依 packages 提供 packument 與 tarball, 不連外網
//packages: { [套件名]: { [版本]: { dependencies, peerDependencies, files: { [相對路徑]: 內容字串或 Buffer } } } }
//tarball 即時以 ustar + gzip 組成(不經 npm pack、不依賴外部 tar), 套件內容只有 package.json 與 files
import http from 'http'
import zlib from 'zlib'
import crypto from 'crypto'


//ustar 標頭(512 位元組): 名稱 100、mode 8、uid 8、gid 8、size 12、mtime 12、chksum 8、typeflag 1、linkname 100、magic 6、version 2
function tarHeader(name, size) {
    let h = Buffer.alloc(512)
    let put = (s, off, len) => h.write(s.padEnd(len, '\0').slice(0, len), off, 'latin1')
    put(name, 0, 100)
    put('0000644\0', 100, 8)
    put('0000000\0', 108, 8)
    put('0000000\0', 116, 8)
    put(size.toString(8).padStart(11, '0') + '\0', 124, 12)
    put('00000000000\0', 136, 12)
    put('        ', 148, 8) //計算檢查碼時 chksum 欄位視為 8 個空白
    put('0', 156, 1)
    put('ustar\0', 257, 6)
    put('00', 263, 2)
    let sum = 0
    for (let i = 0; i < 512; i++) sum += h[i]
    put(sum.toString(8).padStart(6, '0') + '\0 ', 148, 8)
    return h
}

//files: { [tar 內路徑]: 內容 } -> gzip 之 tar(Buffer)
export function makeTgz(files) {
    let parts = []
    for (let [name, content] of Object.entries(files)) {
        let data = Buffer.isBuffer(content) ? content : Buffer.from(String(content), 'utf8')
        parts.push(tarHeader(name, data.length), data, Buffer.alloc((512 - (data.length % 512)) % 512))
    }
    parts.push(Buffer.alloc(1024)) //結尾: 兩個全零區塊
    return zlib.gzipSync(Buffer.concat(parts))
}

export async function fakeNpmRegistry(port, packages) {
    let url = `http://127.0.0.1:${port}/`
    let packuments = {}
    let tarballs = {}
    for (let [name, versions] of Object.entries(packages)) {
        let vs = {}
        for (let [version, spec] of Object.entries(versions)) {
            let { files = {}, ...fields } = spec
            let manifest = { name, version, ...fields }
            let tgz = makeTgz({ 'package/package.json': JSON.stringify(manifest), ...Object.fromEntries(Object.entries(files).map(([k, v]) => [`package/${k}`, v])) })
            let file = `${name}-${version}.tgz`
            tarballs[`/${name}/-/${file}`] = tgz
            vs[version] = {
                ...manifest,
                dist: {
                    tarball: `${url}${name}/-/${file}`,
                    shasum: crypto.createHash('sha1').update(tgz).digest('hex'),
                    integrity: 'sha512-' + crypto.createHash('sha512').update(tgz).digest('base64'),
                },
            }
        }
        let latest = Object.keys(vs).sort((a, b) => a.localeCompare(b, 'en', { numeric: true })).pop()
        packuments[`/${name}`] = { name, 'dist-tags': { latest }, 'versions': vs }
    }

    let requests = []
    let srv = http.createServer((req, res) => {
        let p = decodeURIComponent((req.url || '').split('?')[0])
        requests.push(p)
        if (tarballs[p]) {
            res.writeHead(200, { 'content-type': 'application/octet-stream', 'content-length': tarballs[p].length })
            res.end(tarballs[p])
        }
        else if (packuments[p]) {
            res.writeHead(200, { 'content-type': 'application/json' })
            res.end(JSON.stringify(packuments[p]))
        }
        else {
            res.writeHead(404, { 'content-type': 'application/json' })
            res.end(JSON.stringify({ error: 'not found' }))
        }
    })
    await new Promise((resolve, reject) => {
        srv.once('error', reject)
        srv.listen(port, '127.0.0.1', resolve)
    })
    return {
        url,
        requests: () => requests.slice(),
        close: async () => {
            srv.closeAllConnections()
            await new Promise((resolve) => srv.close(resolve))
        },
    }
}
