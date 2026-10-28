import fs from 'fs'
import path from 'path'
import assert from 'assert'
import cp from 'node:child_process'
import { syncBuiltinESMExports } from 'node:module'
import { pathToFileURL } from 'url'
import { makeRelease, putMirror, makeFakePkg, withEnv } from './tools/fakeBins.mjs'


//規格: 外部執行檔之存放下載校驗與離線(制式規格)§9 套件層測試: 無法注入fetch之入口(主函數WScanDep)須攔截全域fetch並斷言未被呼叫,
//並攔截child_process.spawn/spawnSync斷言所啟動者為ensureBins回傳之路徑(快取), 而非套件根或fdOut內之他處
//被測之src/複製到獨立之假套件根(原樣複製), 其bin/manifest.json為假廠商檔之清單; W_BIN_MIRROR指本機資料夾、W_BIN_OFFLINE=1, 不連外網
describe(`WScanDep entry (ensureBins, fetch and spawn interception)`, function() {
    this.timeout(120000)

    let fdt = path.resolve('./test/_tmp/wsdEntry')
    let fdPkg = path.join(fdt, 'pkg')
    let fpIn = path.join(fdt, 'prj/package.json')
    let mirror = path.join(fdt, 'mirror')
    let A = null
    let WScanDep = null
    let ensureBins = null

    let sha = (f) => (f.extract ? f.extract.sha256 : f.sha256)
    let cacheOf = (cacheRoot, name) => {
        let f = A.manifest.files.find((v) => v.name === name)
        return path.join(cacheRoot, 'w-scan-dep', sha(f), name)
    }

    //攔截
    let netCalls = []
    let calls = []
    let fetchBak = null
    let spawnBak = null
    let spawnSyncBak = null

    before(async function() {
        fs.rmSync(fdt, { recursive: true, force: true })
        fs.mkdirSync(path.join(fdt, 'prj'), { recursive: true })
        fs.writeFileSync(fpIn, JSON.stringify({ name: 'prj', version: '1.0.0', dependencies: {} }))
        A = makeRelease(path.join(fdt, 'work'), { 'syft': '9.9.9', 'grype': '8.8.8', 'osv-scanner': '7.7.7', 'ex-sbom': '0.2.0' })
        putMirror(mirror, A.manifest, A.finals)
        makeFakePkg(fdPkg, A.manifest)
        WScanDep = (await import(pathToFileURL(path.join(fdPkg, 'src/WScanDep.mjs')).href)).default
        ensureBins = (await import(pathToFileURL(path.join(fdPkg, 'src/ensureBins.mjs')).href)).default

        fetchBak = globalThis.fetch
        globalThis.fetch = (url) => {
            netCalls.push(String(url))
            throw new Error(`network access is forbidden in tests: ${url}`)
        }
        spawnBak = cp.spawn
        spawnSyncBak = cp.spawnSync
        cp.spawnSync = (cmd, args, opt) => {
            let c = String(cmd)
            if (/^npm install/.test(c)) {
                calls.push({ kind: 'npm', cmd: c, cwd: args && args.cwd })
                return { status: 0 }
            }
            if (/(syft|grype|osv-scanner)\.exe$/i.test(c)) {
                calls.push({ kind: 'spawnSync', cmd: c })
                return { status: 0, stdout: '', stderr: '' }
            }
            return spawnSyncBak(cmd, args, opt) //netstat、netsh等系統指令照常
        }
        cp.spawn = (cmd, args, opt) => {
            calls.push({ kind: 'spawn', cmd: String(cmd), cwd: opt && opt.cwd })
            throw new Error(`intercepted spawn: ${cmd}`)
        }
        syncBuiltinESMExports() //使以具名匯入取用spawn、spawnSync之模組取得攔截後之函數
    })

    after(function() {
        globalThis.fetch = fetchBak
        cp.spawn = spawnBak
        cp.spawnSync = spawnSyncBak
        syncBuiltinESMExports()
        fs.rmSync(fdt, { recursive: true, force: true, maxRetries: 5, retryDelay: 200 })
    })

    beforeEach(function() {
        netCalls = []
        calls = []
    })

    it(`should export ensureBins as the static property WScanDep.ensureBins without adding a named export (D1, E2)`, async function() {
        assert.strict.equal(typeof ensureBins, 'function')
        assert.strict.equal(WScanDep.ensureBins, ensureBins)
        let mod = await import(pathToFileURL(path.join(fdPkg, 'src/WScanDep.mjs')).href)
        assert.strict.deepStrictEqual(Object.keys(mod), ['default'])
    })

    it(`should obtain the tools by ensureBins before npm install, never touch the global fetch, and launch syft, grype, osv-scanner and ex-sbom from the verified cache paths (E2, D1, D3)`, async function() {
        let cacheRoot = path.join(fdt, 'cache-a')
        let out = path.join(fdt, 'out-a')
        let err = await withEnv({ W_BIN_CACHE: cacheRoot, W_BIN_MIRROR: mirror, W_BIN_OFFLINE: '1' }, () => {
            return WScanDep(fpIn, out).then(() => null, (e) => e)
        })
        //流程進行到啟動ex-sbom(被攔截)為止
        assert.strict.equal(err instanceof Error, true)
        assert.strict.equal(err.message.startsWith('intercepted spawn: '), true, err && err.message)

        assert.strict.deepStrictEqual(netCalls, []) //未使用全域fetch(回歸為直連GitHub時此處會有請求)
        //osv-scanner對markdown與json各跑一次(scan.mjs runOsv)
        assert.strict.deepStrictEqual(calls.map((v) => v.kind), ['npm', 'spawnSync', 'spawnSync', 'spawnSync', 'spawnSync', 'spawn'])
        let want = ['syft.exe', 'grype.exe', 'osv-scanner.exe', 'ex-sbom.exe'].map((n) => cacheOf(cacheRoot, n))
        assert.strict.deepStrictEqual(calls.slice(1).map((v) => v.cmd), [want[0], want[1], want[2], want[2], want[3]]) //所啟動者即ensureBins回傳之快取路徑
        for (let p of want) {
            assert.strict.equal(fs.existsSync(p), true, p)
            assert.strict.equal(p.startsWith(path.join(fdPkg, 'src')), false, p) //不在套件原始碼夾
            assert.strict.equal(p.startsWith(out), false, p) //不在輸出資料夾(不再有fdOut/tools)
        }
        assert.strict.equal(fs.existsSync(path.join(out, 'tools')), false)
        //ensureBins與WScanDep取得同一批路徑
        let got = await withEnv({ W_BIN_CACHE: cacheRoot, W_BIN_MIRROR: mirror, W_BIN_OFFLINE: '1' }, () => ensureBins())
        assert.strict.deepStrictEqual(want, ['syft.exe', 'grype.exe', 'osv-scanner.exe', 'ex-sbom.exe'].map((n) => got[n]))
        //ex-sbom之工作目錄為fdOut/exsbom-work之專用子夾, 非執行檔所在夾(執行期資料不寫入快取夾)
        let ex = calls[5]
        assert.strict.equal(ex.cwd.startsWith(path.join(out, 'exsbom-work')), true, ex.cwd)
        assert.strict.notEqual(path.dirname(ex.cmd), ex.cwd)
    })

    it(`should fail before npm install when a tool can not be obtained, with the code of ensureBins (E3)`, async function() {
        let cacheRoot = path.join(fdt, 'cache-b')
        let out = path.join(fdt, 'out-b')
        let err = await withEnv({ W_BIN_CACHE: cacheRoot, W_BIN_MIRROR: path.join(fdt, 'empty-mirror'), W_BIN_OFFLINE: '1' }, () => {
            return WScanDep(fpIn, out).then(() => null, (e) => e)
        })
        assert.strict.equal(err && err.code, 'E_OFFLINE_MISSING', err && err.message)
        assert.strict.deepStrictEqual(calls, []) //npm install尚未執行
        assert.strict.deepStrictEqual(netCalls, [])
        assert.strict.equal(fs.existsSync(out), false) //亦尚未建立輸出資料夾
    })

    it(`should reject a tool cache placed inside fdOut/test, which syft would catalog, before npm install`, async function() {
        let out = path.join(fdt, 'out-c')
        let cacheRoot = path.join(out, 'test', 'cache')
        let err = await withEnv({ W_BIN_CACHE: cacheRoot, W_BIN_MIRROR: mirror, W_BIN_OFFLINE: '1' }, () => {
            return WScanDep(fpIn, out).then(() => null, (e) => e)
        })
        assert.strict.equal(err instanceof Error, true)
        assert.strict.equal(err.message.includes('掃描工具不可位於輸出資料夾之 test 內'), true, err && err.message)
        assert.strict.equal(err.message.includes('W_BIN_CACHE'), true)
        assert.strict.deepStrictEqual(calls, [])
    })

    it(`should reject the removed third argument (opt.fdTools) before doing anything`, async function() {
        let out = path.join(fdt, 'out-d')
        for (let opt of [{ fdTools: path.join(fdt, 'tools') }, {}, 'x']) {
            let err = await WScanDep(fpIn, out, opt).then(() => null, (e) => e)
            assert.strict.equal(err instanceof Error, true, JSON.stringify(opt))
            assert.strict.equal(err.message.includes('不接受第三參數') && err.message.includes('W_BIN_CACHE'), true, err.message)
        }
        assert.strict.deepStrictEqual(calls, [])
        assert.strict.deepStrictEqual(netCalls, [])
        assert.strict.equal(fs.existsSync(out), false)
        assert.strict.equal(fs.existsSync(path.join(fdt, 'tools')), false)
    })

})
