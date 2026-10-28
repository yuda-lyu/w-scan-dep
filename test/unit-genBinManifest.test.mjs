import fs from 'fs'
import path from 'path'
import http from 'http'
import assert from 'assert'
import fsEnsureBins from 'wsemi/src/fsEnsureBins.mjs'
import { parseChecksums, tagUrl, tagOfUrl, genManifest, genEntry, VENDORS } from '../toolg/genBinManifest.mjs'
import { makeRelease, sha256, flip, catchErr } from './tools/fakeBins.mjs'


//規格: 外部執行檔之存放下載校驗與離線(制式規格) M1~M3、U2、U3: 更新工具由廠商最新版產生清單, 且不手寫雜湊
//GitHub API與資產下載由本機HTTP伺服器扮演(genManifest之api選項), 壓縮檔以tar.exe真實製作與解出, 不連外網
describe(`toolg/genBinManifest.mjs`, function() {
    this.timeout(120000)

    let port = 8983
    let api = `http://127.0.0.1:${port}`
    let fdt = path.resolve('./test/_tmp/genBinManifest')
    let fdWork = path.join(fdt, 'work')
    let ver = { 'syft': '9.9.9', 'grype': '8.8.8', 'osv-scanner': '7.7.7', 'ex-sbom': '0.2.0' }
    let rel = null
    let server = null

    //世界狀態: 各repo之發布(可由個案改動); 資產之位元組取自makeRelease
    let world = null
    let sums = null //repo→checksums文字
    let reset = () => {
        world = {}
        sums = {}
        for (let v of VENDORS) {
            let tag = `v${ver[v.key]}`
            let prefix = `/${v.repo}/releases/download/${tag}/`
            let assets = Object.entries(rel.files).filter(([p]) => p.startsWith(prefix)).map(([p, bytes]) => ({ name: p.slice(prefix.length), bytes }))
            world[v.repo] = { tag, draft: false, prerelease: false, assets, digest: true, flipAsset: false }
            if (v.checksums) {
                let a = assets[0]
                let name = v.key === 'osv-scanner' ? 'osv-scanner_SHA256SUMS' : `${v.key}_${ver[v.key]}_checksums.txt`
                let text = `${sha256(a.bytes)}  ${a.name}\r\n`
                sums[v.repo] = { name, text }
            }
        }
    }

    let releaseJson = (repo) => {
        let w = world[repo]
        let list = w.assets.map((a) => ({ name: a.name, size: a.bytes.length, digest: w.digest ? `sha256:${sha256(a.bytes)}` : undefined, browser_download_url: `${api}/dl/${repo}/${w.tag}/${a.name}` }))
        if (sums[repo]) {
            list.push({ name: sums[repo].name, size: sums[repo].text.length, browser_download_url: `${api}/dl/${repo}/${w.tag}/${sums[repo].name}` })
        }
        return { tag_name: w.tag, draft: w.draft, prerelease: w.prerelease, assets: list }
    }

    let hits = []
    before(async function() {
        fs.rmSync(fdt, { recursive: true, force: true })
        fs.mkdirSync(fdWork, { recursive: true })
        rel = makeRelease(fdWork, ver)
        reset()
        server = http.createServer((req, res) => {
            hits.push(req.url)
            let send = (status, body, type = 'application/json') => {
                res.writeHead(status, { 'content-type': type, 'content-length': String(Buffer.byteLength(body)) })
                res.end(body)
            }
            let m = /^\/repos\/([^/]+\/[^/]+)\/releases\/(latest|tags\/([^/]+))$/.exec(req.url)
            if (m && world[m[1]]) {
                let w = world[m[1]]
                if (m[3] && m[3] !== w.tag && m[3] !== 'v1.0.0') {
                    return send(404, '{}')
                }
                let j = releaseJson(m[1])
                if (m[3]) {
                    j.tag_name = m[3] //指定標籤: 假伺服器回該標籤(資產沿用)
                }
                return send(200, JSON.stringify(j))
            }
            m = /^\/dl\/([^/]+\/[^/]+)\/[^/]+\/([^/]+)$/.exec(req.url)
            if (m && world[m[1]]) {
                let w = world[m[1]]
                if (sums[m[1]] && m[2] === sums[m[1]].name) {
                    return send(200, sums[m[1]].text, 'text/plain')
                }
                let a = w.assets.find((v) => v.name === m[2])
                if (a) {
                    let b = w.flipAsset ? flip(a.bytes, 10) : a.bytes
                    res.writeHead(200, { 'content-length': String(b.length) })
                    return res.end(b)
                }
            }
            send(404, '{}')
        })
        await new Promise((resolve, reject) => {
            server.once('error', reject)
            server.listen(port, '127.0.0.1', resolve)
        })
    })

    after(async function() {
        await new Promise((resolve) => {
            server.close(resolve)
        })
        fs.rmSync(fdt, { recursive: true, force: true, maxRetries: 5, retryDelay: 200 })
    })

    beforeEach(function() {
        reset()
        hits = []
    })

    let gen = (o = {}) => genManifest({ pkg: 'w-scan-dep', api, workDir: fdWork, today: '2026-01-02', ...o })
    let shaOf = (f) => (f.extract ? f.extract.sha256 : f.sha256)

    it(`should parse checksums text with two spaces, binary mark, CRLF and upper-case hex, ignoring other lines (M3)`, function() {
        let h1 = 'a'.repeat(64)
        let h2 = 'B'.repeat(64)
        let m = parseChecksums(`${h1}  x_windows_amd64.zip\r\n${h2} *y.exe\nnot a line\n${'c'.repeat(63)}  short.bin\n`)
        assert.strict.deepStrictEqual([...m.entries()], [['x_windows_amd64.zip', h1], ['y.exe', 'b'.repeat(64)]])
    })

    it(`should build tag asset urls, never releases/latest, and read the tag back (M2)`, function() {
        let u = tagUrl('anchore/syft', 'v1.55.0', 'syft_1.55.0_windows_amd64.zip')
        assert.strict.equal(u, 'https://github.com/anchore/syft/releases/download/v1.55.0/syft_1.55.0_windows_amd64.zip')
        assert.strict.equal(tagOfUrl(u), 'v1.55.0')
        assert.strict.equal(tagOfUrl('https://github.com/anchore/syft/releases/latest/download/x.zip'), '')
        assert.strict.equal(tagOfUrl(''), '')
    })

    it(`should generate a floating manifest of the four tools from the latest releases: tag urls, archive and extracted exe hashes, verified notes, accepted by fsEnsureBins (M1, M2, M3, U2)`, async function() {
        let { manifest, changes } = await gen()
        assert.strict.deepStrictEqual(Object.keys(manifest), ['schema', 'pkg', 'mode', 'repo', 'note', 'files'])
        assert.strict.equal(manifest.mode, 'floating')
        assert.strict.equal(manifest.repo, 'yuda-lyu/w-scan-dep')
        assert.strict.deepStrictEqual(manifest.files.map((f) => f.name), ['syft.exe', 'grype.exe', 'osv-scanner.exe', 'ex-sbom.exe'])
        for (let f of manifest.files) {
            let want = rel.manifest.files.find((v) => v.name === f.name)
            assert.strict.equal(f.url, want.url, f.name) //版本標籤之資產網址
            assert.strict.equal(f.sha256, want.sha256, f.name)
            assert.strict.equal(f.size, want.size, f.name)
            assert.strict.deepStrictEqual(f.extract, want.extract, f.name) //tar.exe真實解出成員後算得
        }
        assert.strict.equal(manifest.files[0].note, 'v9.9.9: SHA-256依廠商公告之syft_9.9.9_checksums.txt核對,且與GitHub API之asset digest一致(2026-01-02)')
        assert.strict.equal(manifest.files[2].note, 'v7.7.7: SHA-256依廠商公告之osv-scanner_SHA256SUMS核對,且與GitHub API之asset digest一致(2026-01-02)')
        assert.strict.equal(manifest.files[3].note, 'v0.2.0: 廠商未公告checksums,首次下載自算SHA-256(2026-01-02),且與GitHub API之asset digest一致') //M3: 無checksums者
        assert.strict.deepStrictEqual(changes.map((c) => [c.key, c.to, c.changed]), [['syft', 'v9.9.9', true], ['grype', 'v8.8.8', true], ['osv-scanner', 'v7.7.7', true], ['ex-sbom', 'v0.2.0', true]])
        assert.strict.equal(hits.every((u) => u.startsWith('/repos/') || u.startsWith('/dl/')), true)

        //產生之清單可被fsEnsureBins接受(離線且快取為空 → 缺檔而非E_MANIFEST)
        fs.mkdirSync(path.join(fdt, 'pkg/bin'), { recursive: true })
        fs.writeFileSync(path.join(fdt, 'pkg/bin/manifest.json'), JSON.stringify(manifest))
        let err = await catchErr(() => fsEnsureBins('bin/manifest.json', { pkgRoot: path.join(fdt, 'pkg'), cacheDir: path.join(fdt, 'cache'), mirror: '', offline: true }))
        assert.strict.equal(err && err.code, 'E_OFFLINE_MISSING', err && err.message)
        assert.strict.deepStrictEqual(err.missing.map((v) => v.sha256), manifest.files.map(shaOf))
    })

    it(`should only return the manifest object, leaving the writing of bin/manifest.json to the command line entry (U2)`, async function() {
        let before = fs.existsSync('bin/manifest.json') ? fs.readFileSync('bin/manifest.json', 'utf8') : null
        await gen()
        let after = fs.existsSync('bin/manifest.json') ? fs.readFileSync('bin/manifest.json', 'utf8') : null
        assert.strict.equal(after, before) //genManifest只回傳物件, 寫檔僅在命令列入口
    })

    it(`should reject when the vendor checksums differ from the GitHub API digest (M3)`, async function() {
        let r = 'anchore/syft'
        sums[r].text = `${'0'.repeat(64)}  ${world[r].assets[0].name}\n`
        let err = await catchErr(() => gen({ only: ['syft'], cur: rel.manifest }))
        assert.strict.equal(err instanceof Error && /differs from the GitHub API digest/.test(err.message), true, err && err.message)
    })

    it(`should reject when the checksums file has no entry for the asset (M3)`, async function() {
        sums['anchore/grype'].text = `${sha256(Buffer.from('x'))}  other.zip\n`
        let err = await catchErr(() => gen({ only: ['grype'], cur: rel.manifest }))
        assert.strict.equal(err instanceof Error && /has no entry for grype_8\.8\.8_windows_amd64\.zip/.test(err.message), true, err && err.message)
    })

    it(`should reject when the downloaded bytes differ from the verified hash (M3, D2)`, async function() {
        world['google/osv-scanner'].flipAsset = true
        let err = await catchErr(() => gen({ only: ['osv-scanner'], cur: rel.manifest }))
        assert.strict.equal(err && err.code, 'E_HASH_MISMATCH', err && err.message)
    })

    it(`should reject a draft or prerelease, a missing or ambiguous asset, and a release verifiable by neither checksums nor digest (M2, M3)`, async function() {
        world['anchore/syft'].draft = true
        let e1 = await catchErr(() => gen({ only: ['syft'], cur: rel.manifest }))
        assert.strict.equal(e1 instanceof Error && /draft or prerelease/.test(e1.message), true, e1 && e1.message)

        world['anchore/grype'].prerelease = true
        let e2 = await catchErr(() => gen({ only: ['grype'], cur: rel.manifest }))
        assert.strict.equal(e2 instanceof Error && /draft or prerelease/.test(e2.message), true, e2 && e2.message)

        world['nics-tw/ex-sbom'].assets = []
        let e3 = await catchErr(() => gen({ only: ['ex-sbom'], cur: rel.manifest }))
        assert.strict.equal(e3 instanceof Error && /has 0 asset\(s\) matching/.test(e3.message), true, e3 && e3.message)

        let w = world['google/osv-scanner']
        w.assets = [...w.assets, { name: 'osv-scanner_windows_amd64.exe', bytes: Buffer.from('dup') }]
        let e4 = await catchErr(() => gen({ only: ['osv-scanner'], cur: rel.manifest }))
        assert.strict.equal(e4 instanceof Error && /has 2 asset\(s\) matching/.test(e4.message), true, e4 && e4.message)

        reset()
        world['nics-tw/ex-sbom'].digest = false //ex-sbom無checksums檔, 且API無digest: 無可核對之雜湊
        let e5 = await catchErr(() => gen({ only: ['ex-sbom'], cur: rel.manifest }))
        assert.strict.equal(e5 instanceof Error && /neither a checksums file nor a GitHub API digest/.test(e5.message), true, e5 && e5.message)
    })

    it(`should use the given tag instead of the latest, still as a tag url (U3)`, async function() {
        let { manifest } = await gen({ only: ['osv-scanner'], cur: rel.manifest, tags: { 'osv-scanner': 'v1.0.0' } })
        let f = manifest.files.find((v) => v.name === 'osv-scanner.exe')
        assert.strict.equal(f.url, 'https://github.com/google/osv-scanner/releases/download/v1.0.0/osv-scanner_windows_amd64.exe')
        assert.strict.equal(hits.some((u) => u.includes('/releases/tags/v1.0.0')), true)
        assert.strict.equal(hits.some((u) => u.includes('/releases/latest')), false)
    })

    it(`should keep the other entries with --only, and keep the old note of an entry whose source and hashes did not change (U2, U3)`, async function() {
        let first = (await gen({ today: '2026-01-02' })).manifest
        hits = []
        let { manifest, changes } = await gen({ only: ['syft', 'ex-sbom'], cur: first, today: '2026-02-03' })
        assert.strict.deepStrictEqual(changes.map((c) => [c.key, c.changed]), [['syft', false], ['ex-sbom', false]])
        assert.strict.deepStrictEqual(manifest, first) //未選之grype、osv-scanner沿用, 選了但未變者note不因日期而變
        assert.strict.equal(hits.filter((u) => u.includes('anchore/grype') || u.includes('google/osv-scanner')).length, 0) //未選者不連網

        //版本更新: syft出新版 → 該項改變, 其餘不動
        world['anchore/syft'] = { ...world['anchore/syft'], tag: 'v9.9.10' }
        let r2 = await gen({ only: ['syft'], cur: first, today: '2026-03-04' })
        assert.strict.deepStrictEqual(r2.changes.map((c) => [c.key, c.from, c.to, c.changed]), [['syft', 'v9.9.9', 'v9.9.10', true]])
        assert.strict.equal(r2.manifest.files[0].url.includes('/v9.9.10/'), true)
        assert.strict.equal(r2.manifest.files[0].note.endsWith('(2026-03-04)'), true)
        assert.strict.deepStrictEqual(r2.manifest.files.slice(1), first.files.slice(1))
    })

    it(`should refuse --only without an existing manifest, and an empty selection`, async function() {
        let e1 = await catchErr(() => gen({ only: ['syft'] }))
        assert.strict.equal(e1 instanceof Error && /needs an existing bin\/manifest\.json/.test(e1.message), true, e1 && e1.message)
        let e2 = await catchErr(() => gen({ only: ['nope'], cur: rel.manifest }))
        assert.strict.equal(e2 instanceof Error && /no vendor selected/.test(e2.message), true, e2 && e2.message)
    })

    it(`should export genEntry returning the entry with the verification basis (M3)`, async function() {
        let r = await genEntry(VENDORS[3], { api, workDir: fdWork, today: '2026-01-02' })
        assert.strict.deepStrictEqual([r.key, r.tag, r.asset, r.checksums], ['ex-sbom', 'v0.2.0', 'ex-sbom.exe', null])
    })

})
