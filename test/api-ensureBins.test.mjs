import fs from 'fs'
import os from 'os'
import path from 'path'
import assert from 'assert'
import { spawnSync } from 'child_process'
import { pathToFileURL } from 'url'
import { RAW, makeRelease, putMirror, makeFakePkg, listFiles, serve, mkFetch, mkFetchBan, flip, withEnv, catchErr } from './tools/fakeBins.mjs'


//規格: 外部執行檔之存放下載校驗與離線(制式規格) D1~D4、O1~O4、M5、E2、E3、§8 T3~T8
//本套件為主幹模式(floating): 清單取GitHub主幹, 取不到時用套件內基準清單。廠商檔(syft、grype、osv-scanner、ex-sbom)不在repo內,
//故以小型假檔(壓縮檔以tar.exe真實製作)經本機HTTP伺服器(扮GitHub原始檔與release下載, fetch只改主機指向本機)與本地資料夾(扮鏡像與快取)走完真實的下載、解壓與校驗, 不連外網。
//被測之src/複製到獨立之假套件根(原樣複製、不改一字): 套件根決定預設快取位置, 不可寫入本repo之bin-cache/
describe(`ensureBins`, function() {
    this.timeout(120000)

    let port = 8981
    let TRUNK = '/yuda-lyu/w-scan-dep/master/bin/manifest.json'
    let fdt = path.resolve('./test/_tmp/ensureBins')
    let fdWork = path.join(fdt, 'work')
    let fdPkg = path.join(fdt, 'pkg')

    //A為套件內基準清單(syft 9.9.9、grype 8.8.8), B為主幹清單(syft 10.0.0、grype 8.9.0; osv-scanner與ex-sbom同A, 證明主幹模式可只更新部分工具)
    let A = null
    let B = null
    let urlOf = (f) => f.url.replace('https://github.com', '')
    let sha = (f) => (f.extract ? f.extract.sha256 : f.sha256)
    let names = ['syft.exe', 'grype.exe', 'osv-scanner.exe', 'ex-sbom.exe']

    //伺服器狀態: trunkMode為ok、missing(404)、badschema(schema為2)、badjson(非JSON)、badextract(syft之extract.sha256錯); tamper為{ path, how('flip'|'short') }
    let trunkMode = 'ok'
    let tamper = null
    let gone = null //下架(404)之資產路徑
    let srv = null
    let ensureBins = null
    let urls = []
    let fetch = null
    let fetchBan = null

    let routes = (url) => {
        if (url === TRUNK) {
            let m = JSON.parse(JSON.stringify(B.manifest))
            if (trunkMode === 'missing') {
                return { status: 404, body: Buffer.alloc(0) }
            }
            if (trunkMode === 'badschema') {
                m.schema = 2
            }
            if (trunkMode === 'badextract') {
                m.files[0].extract.sha256 = '0'.repeat(64)
            }
            let text = trunkMode === 'badjson' ? '<html>not json</html>' : JSON.stringify(m)
            return { status: 200, body: Buffer.from(text) }
        }
        if (gone !== null && url === gone) {
            return { status: 404, body: Buffer.alloc(0) }
        }
        if (tamper && url === tamper.path) {
            let b = srv.assets[url]
            return { status: 200, body: tamper.how === 'short' ? b.subarray(0, b.length - 1) : flip(b, 2000) }
        }
        return undefined
    }

    //每案獨立資料夾, afterEach刪除
    let seq = 0
    let temps = []
    let newDir = (tag) => {
        seq++
        let fd = path.join(fdt, `${tag}-${seq}`)
        temps.push(fd)
        return fd
    }

    //不含主幹清單副本(manifest-last.json, 紀錄用)之快取內檔案
    let cacheFiles = (fd) => listFiles(fd).filter((v) => path.basename(v) !== 'manifest-last.json')

    before(async function() {
        fs.rmSync(fdt, { recursive: true, force: true })
        fs.mkdirSync(fdWork, { recursive: true })
        A = makeRelease(fdWork, { 'syft': '9.9.9', 'grype': '8.8.8', 'osv-scanner': '7.7.7', 'ex-sbom': '0.2.0' })
        B = makeRelease(fdWork, { 'syft': '10.0.0', 'grype': '8.9.0', 'osv-scanner': '7.7.7', 'ex-sbom': '0.2.0' })
        let assets = { ...A.files, ...B.files }
        srv = await serve(port, assets, routes)
        srv.assets = assets
        makeFakePkg(fdPkg, A.manifest)
        ensureBins = (await import(pathToFileURL(path.join(fdPkg, 'src/ensureBins.mjs')).href)).default
        fetch = mkFetch(port, urls)
        fetchBan = mkFetchBan(urls)
    })

    after(async function() {
        await srv.close()
        fs.rmSync(fdt, { recursive: true, force: true, maxRetries: 5, retryDelay: 200 })
    })

    beforeEach(function() {
        trunkMode = 'ok'
        tamper = null
        gone = null
        urls.length = 0
        srv.hits.length = 0
    })

    afterEach(function() {
        for (let fd of temps) {
            fs.rmSync(fd, { recursive: true, force: true, maxRetries: 5, retryDelay: 200 })
        }
        temps = []
    })

    it(`should have the baseline manifest in the fake package equal to release A, and A differ from the trunk B (precondition of the cases below)`, function() {
        assert.strict.deepStrictEqual(JSON.parse(fs.readFileSync(path.join(fdPkg, 'bin/manifest.json'), 'utf8')), A.manifest)
        assert.strict.notEqual(sha(A.manifest.files[0]), sha(B.manifest.files[0])) //syft
        assert.strict.notEqual(sha(A.manifest.files[1]), sha(B.manifest.files[1])) //grype
        assert.strict.equal(sha(A.manifest.files[2]), sha(B.manifest.files[2])) //osv-scanner
    })

    it(`should take the trunk manifest, download the tag assets, verify, extract and cache only the final files; later calls download nothing (T3, M5, D1, D3, D4, D5, F3)`, async function() {
        let cacheDir = newDir('cache')

        let r1 = await ensureBins({ cacheDir, fetch, mirror: '', offline: false })
        assert.strict.deepStrictEqual(Object.keys(r1).sort(), [...names].sort())
        for (let f of B.manifest.files) {
            assert.strict.equal(r1[f.name], path.join(cacheDir, sha(f), f.name)) //D3: <快取>/<sha256>/<name>
            assert.strict.equal(fs.readFileSync(r1[f.name]).equals(B.finals[f.name]), true) //D5: 解出之檔即最終檔
        }
        //M5: 先取主幹清單, 再依序取其所載之版本標籤資產(非baseline之9.9.9、非releases/latest)
        assert.strict.deepStrictEqual(urls, [`${RAW}${TRUNK}`, ...B.manifest.files.map((f) => f.url)])
        assert.strict.equal(urls.some((u) => /\/latest\b/.test(u)), false)
        //F3: 快取只存最終檔(與主幹清單之紀錄副本), 不留壓縮檔與暫存夾
        assert.strict.deepStrictEqual(cacheFiles(cacheDir).sort(), names.map((n) => r1[n]).sort())

        //第二次(連網): 快取命中且校驗, 不再下載資產, 只取主幹清單
        urls.length = 0
        let r2 = await ensureBins({ cacheDir, fetch, mirror: '', offline: false })
        assert.strict.deepStrictEqual(r2, r1)
        assert.strict.deepStrictEqual(urls, [`${RAW}${TRUNK}`])

        //第三次(離線): 完全不連網, 用基準清單A, A之syft與grype不在快取故缺檔
        urls.length = 0
        let err = await catchErr(() => ensureBins({ cacheDir, fetch: fetchBan, mirror: '', offline: true }))
        assert.strict.equal(err && err.code, 'E_OFFLINE_MISSING', err && err.message)
        assert.strict.deepStrictEqual(err.missing.map((v) => v.name).sort(), ['grype.exe', 'syft.exe'])
        assert.strict.deepStrictEqual(urls, [])
    })

    it(`should return the cached path of the trunk files when the call is offline and only the tools unchanged since the baseline are asked (T3, D4, O3)`, async function() {
        let cacheDir = newDir('cache')
        await ensureBins({ cacheDir, fetch, mirror: '', offline: false })
        urls.length = 0
        srv.hits.length = 0
        let r = await ensureBins({ cacheDir, fetch: fetchBan, mirror: '', offline: true, names: ['osv-scanner.exe', 'ex-sbom.exe'] })
        assert.strict.deepStrictEqual(Object.keys(r).sort(), ['ex-sbom.exe', 'osv-scanner.exe'])
        assert.strict.deepStrictEqual(urls, [])
        assert.strict.equal(srv.hits.length, 0)
    })

    it(`should download only the asked names (E1, names)`, async function() {
        let cacheDir = newDir('cache')
        let r = await ensureBins({ cacheDir, fetch, mirror: '', offline: false, names: 'osv-scanner.exe' })
        assert.strict.deepStrictEqual(Object.keys(r), ['osv-scanner.exe'])
        assert.strict.deepStrictEqual(urls, [`${RAW}${TRUNK}`, B.manifest.files[2].url])
        assert.strict.deepStrictEqual(cacheFiles(cacheDir), [r['osv-scanner.exe']])
    })

    it(`should reject an asset whose bytes differ from the manifest, with the same size, and leave no file (T4, M2, D2)`, async function() {
        for (let i of [0, 2]) { //zip壓縮檔(syft)與直接下載之exe(osv-scanner)
            let f = B.manifest.files[i]
            tamper = { path: urlOf(f), how: 'flip' }
            let cacheDir = newDir('cache')
            let err = await catchErr(() => ensureBins({ cacheDir, fetch, mirror: '', offline: false, maxAttempts: 1, names: f.name }))
            assert.strict.equal(err && err.code, 'E_HASH_MISMATCH', err && err.message)
            assert.strict.deepStrictEqual(cacheFiles(cacheDir), [], f.name)
        }
    })

    it(`should reject an asset shorter than the manifest size and leave no file (T4, M2, D2)`, async function() {
        let f = B.manifest.files[2]
        tamper = { path: urlOf(f), how: 'short' }
        let cacheDir = newDir('cache')
        let err = await catchErr(() => ensureBins({ cacheDir, fetch, mirror: '', offline: false, maxAttempts: 1, names: f.name }))
        assert.strict.equal(err && err.code, 'E_SIZE_MISMATCH', err && err.message)
        assert.strict.deepStrictEqual(cacheFiles(cacheDir), [])
    })

    it(`should reject an extracted file whose hash differs from the manifest extract and leave no file (T4, D5)`, async function() {
        trunkMode = 'badextract'
        let cacheDir = newDir('cache')
        let err = await catchErr(() => ensureBins({ cacheDir, fetch, mirror: '', offline: false, maxAttempts: 1, names: 'syft.exe' }))
        assert.strict.equal(err && err.code, 'E_HASH_MISMATCH', err && err.message)
        assert.strict.deepStrictEqual(cacheFiles(cacheDir), [])
    })

    it(`should reject an HTTP error status of an asset without leaving a file (T4, E3)`, async function() {
        let f = B.manifest.files[3]
        gone = urlOf(f) //ex-sbom之資產下架(404)
        let cacheDir = newDir('cache')
        let err = await catchErr(() => ensureBins({ cacheDir, fetch, mirror: '', offline: false, maxAttempts: 1, names: f.name }))
        assert.strict.equal(err && err.code, 'E_HTTP', err && err.message)
        assert.strict.deepStrictEqual(cacheFiles(cacheDir), [])
    })

    it(`should get the files from a folder mirror without network, and refuse a tampered mirror file (T5, O1, O2, O3)`, async function() {
        let mirror = newDir('mirror')
        putMirror(mirror, A.manifest, A.finals)
        let cacheDir = newDir('cache')
        let r = await ensureBins({ cacheDir, fetch: fetchBan, mirror, offline: true })
        for (let f of A.manifest.files) {
            assert.strict.equal(r[f.name], path.join(cacheDir, sha(f), f.name))
            assert.strict.equal(fs.readFileSync(r[f.name]).equals(A.finals[f.name]), true)
        }
        assert.strict.deepStrictEqual(urls, [])
        assert.strict.equal(srv.hits.length, 0)

        //鏡像之檔被竄改(同長度): 離線時拒用且不進快取
        let f0 = A.manifest.files[0]
        let fpBad = path.join(mirror, 'w-scan-dep', sha(f0), f0.name)
        fs.writeFileSync(fpBad, flip(fs.readFileSync(fpBad), 100))
        let cacheDir2 = newDir('cache')
        let err = await catchErr(() => ensureBins({ cacheDir: cacheDir2, fetch: fetchBan, mirror, offline: true, names: f0.name }))
        assert.strict.equal(err && err.code, 'E_OFFLINE_MISSING', err && err.message)
        assert.strict.deepStrictEqual(cacheFiles(cacheDir2), [])
    })

    it(`should prefer the mirror to GitHub online, fetching only the trunk manifest (T5, O2)`, async function() {
        let mirror = newDir('mirror')
        putMirror(mirror, B.manifest, B.finals)
        let cacheDir = newDir('cache')
        let r = await ensureBins({ cacheDir, fetch, mirror, offline: false })
        for (let f of B.manifest.files) {
            assert.strict.equal(fs.readFileSync(r[f.name]).equals(B.finals[f.name]), true)
        }
        assert.strict.deepStrictEqual(urls, [`${RAW}${TRUNK}`]) //資產皆取自鏡像
    })

    it(`should reject offline with E_OFFLINE_MISSING naming each file, sha256, size and the cache path when nothing is available (T6, O3, E3)`, async function() {
        let cacheDir = newDir('cache')
        let err = await catchErr(() => ensureBins({ cacheDir, fetch: fetchBan, mirror: '', offline: true }))
        assert.strict.equal(err && err.code, 'E_OFFLINE_MISSING', err && err.message)
        for (let f of A.manifest.files) { //離線時用基準清單A
            let size = f.extract ? f.extract.size : f.size
            assert.strict.equal(err.message.includes(f.name), true, err.message)
            assert.strict.equal(err.message.includes(sha(f)), true, err.message)
            assert.strict.equal(err.message.includes(`${size} bytes`), true, err.message)
            assert.strict.equal(err.message.includes(path.join(cacheDir, sha(f), f.name)), true, err.message)
        }
        assert.strict.deepStrictEqual(err.missing.map((v) => [v.name, v.sha256, v.cachePath]), A.manifest.files.map((f) => [f.name, sha(f), path.join(cacheDir, sha(f), f.name)]))
        assert.strict.deepStrictEqual(urls, [])
        assert.strict.equal(srv.hits.length, 0)
        assert.strict.deepStrictEqual(cacheFiles(cacheDir), [])
    })

    it(`should re-obtain a cached file that was altered with the same size or truncated (T7, D4)`, async function() {
        let mirror = newDir('mirror')
        putMirror(mirror, A.manifest, A.finals)
        let cacheDir = newDir('cache')
        let r1 = await ensureBins({ cacheDir, fetch: fetchBan, mirror, offline: true })

        fs.writeFileSync(r1['syft.exe'], flip(fs.readFileSync(r1['syft.exe']), 100))
        fs.truncateSync(r1['osv-scanner.exe'], 10)
        let r2 = await ensureBins({ cacheDir, fetch: fetchBan, mirror, offline: true })
        assert.strict.deepStrictEqual(r2, r1)
        for (let f of A.manifest.files) {
            assert.strict.equal(fs.readFileSync(r2[f.name]).equals(A.finals[f.name]), true, f.name)
        }
    })

    it(`should use the baseline manifest when the trunk manifest can not be got, is not JSON or fails the schema (T8, M5)`, async function() {
        for (let mode of ['missing', 'badjson', 'badschema']) {
            trunkMode = mode
            urls.length = 0
            let cacheDir = newDir('cache')
            let r = await ensureBins({ cacheDir, fetch, mirror: '', offline: false })
            //先嘗試主幹清單, 失敗後下載的是基準清單A(9.9.9)之資產
            assert.strict.deepStrictEqual(urls, [`${RAW}${TRUNK}`, ...A.manifest.files.map((f) => f.url)], mode)
            for (let f of A.manifest.files) {
                assert.strict.equal(r[f.name], path.join(cacheDir, sha(f), f.name), mode)
                assert.strict.equal(fs.readFileSync(r[f.name]).equals(A.finals[f.name]), true, mode)
            }
        }
    })

    it(`should read W_BIN_CACHE, W_BIN_MIRROR and W_BIN_OFFLINE from the environment (D3, O1, O3)`, async function() {
        let mirror = newDir('mirror')
        putMirror(mirror, A.manifest, A.finals)
        let envRoot = newDir('envroot')
        let r = await withEnv({ W_BIN_CACHE: envRoot, W_BIN_MIRROR: mirror, W_BIN_OFFLINE: '1' }, () => {
            return ensureBins({ fetch: fetchBan })
        })
        //D3: 共用快取為<W_BIN_CACHE>/<套件>/<sha256>/<name>
        for (let f of A.manifest.files) {
            assert.strict.equal(r[f.name], path.join(envRoot, 'w-scan-dep', sha(f), f.name))
        }
        assert.strict.deepStrictEqual(urls, [])

        //W_BIN_OFFLINE=1且無快取無鏡像: E_OFFLINE_MISSING, 不連網
        let envRoot2 = newDir('envroot')
        let err = await withEnv({ W_BIN_CACHE: envRoot2, W_BIN_MIRROR: undefined, W_BIN_OFFLINE: '1' }, () => {
            return catchErr(() => ensureBins({ fetch: fetchBan }))
        })
        assert.strict.equal(err && err.code, 'E_OFFLINE_MISSING', err && err.message)
        assert.strict.equal(err.message.includes(path.join(envRoot2, 'w-scan-dep')), true, err.message)
        assert.strict.deepStrictEqual(urls, [])

        //O4: 設W_BIN_CACHE取得所得之資料夾即為鏡像(結構相同)
        let cacheDir = newDir('cache')
        let r3 = await ensureBins({ cacheDir, fetch: fetchBan, mirror: path.join(envRoot), offline: true })
        assert.strict.equal(fs.readFileSync(r3['grype.exe']).equals(A.finals['grype.exe']), true)
    })

    it(`should place the default cache under the package root even when the module is loaded from another working directory (D3, E2)`, function() {
        //pkgRoot於模組載入時決定, 故以子行程於他處工作目錄載入(被安裝為相依套件時, 載入時之工作目錄為使用者專案而非套件根)
        let env = { ...process.env }
        for (let k of ['W_BIN_CACHE', 'W_BIN_MIRROR', 'W_BIN_OFFLINE']) {
            delete env[k]
        }
        let cwdOther = os.tmpdir()
        let r = spawnSync(process.execPath, [path.resolve('test/tools/ensureBinsChild.mjs'), path.join(fdPkg, 'src/ensureBins.mjs')], { cwd: cwdOther, env, encoding: 'utf8', windowsHide: true })
        assert.strict.equal(r.status, 0, r.stderr)
        let o = JSON.parse(r.stdout.trim().split('\n').pop())
        assert.strict.equal(path.resolve(o.cwd), path.resolve(cwdOther)) //確實於他處載入
        assert.strict.equal(o.code, 'E_OFFLINE_MISSING')
        let f0 = A.manifest.files[0] //離線用基準清單: 缺檔之應放路徑為(假)套件根下之預設快取, 與cwd無關
        assert.strict.equal(o.cachePath, path.join(fdPkg, 'bin-cache', sha(f0), f0.name))
        fs.rmSync(path.join(fdPkg, 'bin-cache'), { recursive: true, force: true }) //離線缺檔時wsemi會建立空的快取根
    })

    it(`should not forward floatingManifestUrl, which would change the trust anchor of the manifest (E2, M5)`, async function() {
        //floatingManifestUrl被轉傳時, 非本repo之網址會使fsEnsureBins以E_ARG拒絕; 套件端丟棄它故仍取標準之主幹清單網址
        let cacheDir = newDir('cache')
        let r = await ensureBins({ cacheDir, fetch, mirror: '', offline: false, names: 'ex-sbom.exe', floatingManifestUrl: `${RAW}/evil/other/master/x.json` })
        assert.strict.deepStrictEqual(Object.keys(r), ['ex-sbom.exe'])
        assert.strict.equal(urls[0], `${RAW}${TRUNK}`)
        assert.strict.equal(urls.some((u) => u.includes('/evil/')), false)
    })

})
