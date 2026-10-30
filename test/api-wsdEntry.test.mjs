import fs from 'fs'
import path from 'path'
import assert from 'assert'
import { EventEmitter } from 'events'
import { PassThrough } from 'stream'
import cp from 'node:child_process'
import { syncBuiltinESMExports } from 'node:module'
import { pathToFileURL } from 'url'
import { makeRelease, putMirror, makeFakePkg, withEnv } from './tools/fakeBins.mjs'
import { hangRegistry } from './tools/hangRegistry.mjs'
import { fakeNpmRegistry } from './tools/fakeNpmRegistry.mjs'
import { scopePackages, scopeProject, scopeInstalled, scopeNotInstalled } from './tools/scopeFixture.mjs'


//規格: 外部執行檔之存放下載校驗與離線(制式規格)§9 套件層測試: 無法注入fetch之入口(主函數WScanDep)須攔截全域fetch並斷言未被呼叫,
//並攔截child_process.spawn/spawnSync斷言所啟動者為ensureBins回傳之路徑(快取), 而非套件根或fdOut內之他處
//被測之src/複製到獨立之假套件根(原樣複製), 其bin/manifest.json為假廠商檔之清單; W_BIN_MIRROR指本機資料夾、W_BIN_OFFLINE=1, 不連外網
//被攔截之syft/grype/osv-scanner寫出假產物(syft之SBOM為含相依循環之test/fixtures/cycle.spdx.json, grype與osv各標注semver@7.0.0),
//建議w-scan-dep修正.md(Gitea #24)之WScanDep層案例據以斷言「ex-sbom失敗只作廢截圖、掃描結果照常寫出」
describe(`WScanDep entry (ensureBins, fetch and spawn interception)`, function() {
    this.timeout(120000)

    let fdt = path.resolve('./test/_tmp/wsdEntry')
    let fdPkg = path.join(fdt, 'pkg')
    let fpIn = path.join(fdt, 'prj/package.json')
    let mirror = path.join(fdt, 'mirror')
    let fakeExSbom = path.resolve('./test/tools/fakeExSbom.mjs')
    let hangTool = path.resolve('./test/tools/hangTool.mjs')
    let cycleSpdx = fs.readFileSync('./test/fixtures/cycle.spdx.json', 'utf8')
    let ks = ['date', 'source', 'outputDir', 'scope', 'tools', 'osv', 'grype', 'exsbom', 'updateList']
    let scopeMd = '- 掃描範圍：僅 dependencies（正式相依樹，含其所附之執行檔）；devDependencies 之開發與建置工具不在範圍內'
    let ksEx = ['ok', 'error', 'overview', 'components', 'levelSummary', 'removedRelationships']
    let A = null
    let WScanDep = null
    let ensureBins = null

    //攔截之模式(beforeEach重設): ex-sbom 'throw'為啟動即拋錯、'crash'為改啟動扮演ex-sbom之fakeExSbom.mjs; npm install 'ok'為假裝成功、'real'為真實執行;
    //hangTool為卡住之掃描工具名('syft'、'grype'、'osv-scanner'), 該工具改啟動永遠等待之替身(hangTool.mjs), 其餘工具照常寫出假產物
    let exMode = 'throw'
    let npmMode = 'ok'
    let hangName = null
    let hangPort = 8989

    //依被攔截之掃描工具之參數寫出其產物(scan.mjs之runSyft、runGrype、runOsv所讀者)
    let argOut = (args, prefix) => (args.find((a) => a.startsWith(prefix)) || '').slice(prefix.length)
    let semverVuln = { id: 'GHSA-c2qf-rxjj-qqgw', summary: 'semver vulnerable to Regular Expression Denial of Service', aliases: ['CVE-2022-25883'] }
    let writeScanOutput = (cmd, args) => {
        if (/syft\.exe$/i.test(cmd)) {
            fs.writeFileSync(argOut(args, 'spdx-json='), cycleSpdx)
            fs.writeFileSync(argOut(args, 'cyclonedx-json='), '{}')
        }
        else if (/grype\.exe$/i.test(cmd)) {
            fs.writeFileSync(argOut(args, 'table='), 'semver 7.0.0 7.5.2 npm GHSA-c2qf-rxjj-qqgw Medium\n')
            fs.writeFileSync(argOut(args, 'json='), JSON.stringify({ matches: [{ artifact: { name: 'semver', version: '7.0.0' }, vulnerability: { id: semverVuln.id, severity: 'Medium', fix: { versions: ['7.5.2'] } } }] }))
        }
        else if (/osv-scanner\.exe$/i.test(cmd)) {
            let out = argOut(args, '--output-file=')
            if (args.includes('--format=json')) fs.writeFileSync(out, JSON.stringify({ results: [{ packages: [{ package: { name: 'semver', version: '7.0.0', ecosystem: 'npm' }, vulnerabilities: [semverVuln] }] }] }))
            else fs.writeFileSync(out, '| OSV URL | CVSS | Ecosystem | Package | Version | Fixed Version | Source |\n| --- | --- | --- | --- | --- | --- | --- |\n| https://osv.dev/GHSA-c2qf-rxjj-qqgw | 5.3 | npm | semver | 7.0.0 | 7.5.2 | test/package-lock.json |\n')
        }
    }
    let fakeChildOk = () => {
        let c = new EventEmitter()
        c.pid = 0
        setImmediate(() => c.emit('exit', 0, null))
        return c
    }
    //掃描工具(以spawn啟動, scan.mjs runTool): 有stdout/stderr串流, 串流關閉後發出close
    let fakeToolOk = () => {
        let c = new EventEmitter()
        c.pid = 0
        c.stdout = new PassThrough()
        c.stderr = new PassThrough()
        setImmediate(() => {
            c.emit('exit', 0, null)
            c.stdout.end()
            c.stderr.end()
            c.emit('close', 0, null)
        })
        return c
    }
    let toolNameOf = (cmd) => ((/([^\\/]+)\.exe$/i.exec(cmd) || [])[1] || '').toLowerCase()

    let sha = (f) => (f.extract ? f.extract.sha256 : f.sha256)
    let cacheOf = (cacheRoot, name) => {
        let f = A.manifest.files.find((v) => v.name === name)
        return path.join(cacheRoot, 'w-scan-dep', sha(f), name)
    }

    //攔截
    let netCalls = []
    let calls = []
    let cfgCalls = []
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
        globalThis.fetch = (url, init) => {
            //本機迴圈位址(ex-sbom 就緒探測 probeTitle)照常;其餘一律禁止並記錄
            if (/^http:\/\/(127\.0\.0\.1|\[::1\]):/.test(String(url))) return fetchBak(url, init)
            netCalls.push(String(url))
            throw new Error(`network access is forbidden in tests: ${url}`)
        }
        spawnBak = cp.spawn
        spawnSyncBak = cp.spawnSync
        cp.spawnSync = (cmd, args, opt) => {
            let c = String(cmd)
            if (/(syft|grype|osv-scanner)\.exe$/i.test(c)) {
                calls.push({ kind: 'spawnSync', cmd: c })
                writeScanOutput(c, args)
                return { status: 0, stdout: '', stderr: '' }
            }
            return spawnSyncBak(cmd, args, opt) //netstat、netsh、npm ls等照常
        }
        cp.spawn = (cmd, ...rest) => {
            let c = String(cmd)
            //取呼叫端專案生效之 npm 倉庫設定(src/npmRegistry.mjs): 照常執行(真實 npm, 或 PATH 前端之替身 npm), 另記於 cfgCalls, 不計入 calls(呼叫序列斷言不變)
            if (/^npm config /.test(c)) {
                let opt = rest.find((v) => v && !Array.isArray(v) && typeof v === 'object')
                cfgCalls.push({ cmd: c, cwd: opt && opt.cwd })
                return spawnBak(cmd, ...rest)
            }
            if (/^npm install/.test(c)) {
                let opt = rest.find((v) => v && !Array.isArray(v) && typeof v === 'object')
                calls.push({ kind: 'npm', cmd: c, cwd: opt && opt.cwd, env: opt && opt.env, callerInclude: process.env.npm_config_include })
                return npmMode === 'real' ? spawnBak(cmd, ...rest) : fakeChildOk()
            }
            //playwright 之瀏覽器(ms-playwright 下之 chrome/headless_shell)經同一 child_process 啟動:照常、不記錄
            if (/ms-playwright/i.test(c)) return spawnBak(cmd, ...rest)
            let opt = rest[1]
            //掃描工具一律以spawn啟動(須有時限與樹狀結束, 見R-SCAN-TIMEOUT-01; 以spawnSync啟動者記為'spawnSync', 使下列呼叫序列之斷言失敗)
            if (/(syft|grype|osv-scanner)\.exe$/i.test(c)) {
                calls.push({ kind: 'tool', cmd: c })
                if (hangName === toolNameOf(c)) {
                    return spawnBak(process.execPath, [], { ...opt, env: { ...opt.env, NODE_OPTIONS: `--import=${pathToFileURL(hangTool).href}`, FAKE_HANG_PORT: String(hangPort) } })
                }
                writeScanOutput(c, rest[0])
                return fakeToolOk()
            }
            calls.push({ kind: 'spawn', cmd: c, cwd: opt && opt.cwd })
            if (exMode === 'crash' && /ex-sbom\.exe$/i.test(c)) return spawnBak(process.execPath, [fakeExSbom], opt)
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
        cfgCalls = []
        exMode = 'throw'
        npmMode = 'ok'
        hangName = null
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
        //上次掃描留下之截圖:本次截圖失敗時不得與本次結果並存
        fs.mkdirSync(path.join(out, 'pics'), { recursive: true })
        fs.writeFileSync(path.join(out, 'pics', 'topology-overview.png'), 'old')
        let r = await withEnv({ W_BIN_CACHE: cacheRoot, W_BIN_MIRROR: mirror, W_BIN_OFFLINE: '1' }, () => {
            return WScanDep(fpIn, out)
        })
        //流程進行到啟動ex-sbom(被攔截而拋錯);ex-sbom之失敗只作廢截圖(Gitea #24),結果照常寫出且標明截圖失敗與原因
        assert.strict.equal(r, 'ok')
        let j = JSON.parse(fs.readFileSync(path.join(out, 'result.json'), 'utf8'))
        assert.strict.equal(j.exsbom.ok, false)
        assert.strict.equal(j.exsbom.error.startsWith('intercepted spawn: '), true, j.exsbom.error)
        //啟動前已算出之剔除清單(syft之SBOM含循環)隨失敗一併列出; 上次之截圖已刪(此案不經ex-sbom行程, 不受本機TCP表影響)
        assert.strict.ok(Array.isArray(j.exsbom.removedRelationships), `removedRelationships: ${JSON.stringify(j.exsbom.removedRelationships)}`)
        assert.strict.deepStrictEqual(j.exsbom.removedRelationships.map((x) => `${x.from} ${x.relationshipType} ${x.to}`), ['string.prototype.trim@1.2.11 DEPENDENCY_OF es-abstract@1.24.2'])
        assert.strict.equal(fs.existsSync(path.join(out, 'pics')), false)

        assert.strict.deepStrictEqual(netCalls, []) //未使用全域fetch(回歸為直連GitHub時此處會有請求)
        //osv-scanner對markdown與json各跑一次(scan.mjs runOsv); 掃描工具皆以spawn啟動(kind為tool)
        assert.strict.deepStrictEqual(calls.map((v) => v.kind), ['npm', 'tool', 'tool', 'tool', 'tool', 'spawn'])
        //掃描範圍只算dependencies(Gitea #27): 隔離安裝只裝正式相依樹, 其餘旗標維持
        assert.strict.equal(calls[0].cmd, 'npm install --omit=dev --no-audit --no-fund')
        assert.strict.equal(calls[0].cwd, path.join(out, 'test'))
        assert.strict.equal(j.scope, 'dependencies')
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

    //建議w-scan-dep修正.md(Gitea #24)一建議 2、二(主控裁定 2、4):ex-sbom 於截圖期間結束時,只作廢截圖;
    //syft/grype/osv-scanner 之結果照常寫出,result.json 之截圖欄位標明失敗,原因含 ex-sbom.log 之 fatal error 及其後數行
    it(`should keep the syft, grype and osv-scanner results and mark only the screenshots failed with the reason from ex-sbom.log when ex-sbom ends during capture`, async function() {
        exMode = 'crash'
        let cacheRoot = path.join(fdt, 'cache-e')
        let out = path.join(fdt, 'out-e')
        //上次掃描留下之截圖:本次截圖失敗時不得與本次結果並存
        fs.mkdirSync(path.join(out, 'pics'), { recursive: true })
        fs.writeFileSync(path.join(out, 'pics', 'topology-overview.png'), 'old')
        let r = await withEnv({ W_BIN_CACHE: cacheRoot, W_BIN_MIRROR: mirror, W_BIN_OFFLINE: '1' }, () => WScanDep(fpIn, out))
        assert.strict.equal(r, 'ok')
        assert.strict.deepStrictEqual(calls.map((v) => v.kind), ['npm', 'tool', 'tool', 'tool', 'tool', 'spawn']) //ex-sbom 只啟動一次(就緒後結束,不換埠重試)
        let j = JSON.parse(fs.readFileSync(path.join(out, 'result.json'), 'utf8'))
        assert.strict.deepStrictEqual(Object.keys(j), ks)
        assert.strict.deepStrictEqual(Object.keys(j.exsbom), ksEx)
        assert.strict.equal(j.scope, 'dependencies') //掃描範圍欄位(Gitea #27): 截圖失敗時亦照寫
        //三種掃描結果照常寫出
        assert.strict.equal(fs.readFileSync(path.join(out, 'scan', 'syft.spdx.json'), 'utf8'), cycleSpdx)
        assert.strict.deepStrictEqual(j.grype.matches.map((m) => `${m.name}@${m.version} ${m.id}`), ['semver@7.0.0 GHSA-c2qf-rxjj-qqgw'])
        assert.strict.deepStrictEqual(j.osv.packages.map((p) => `${p.name}@${p.version}`), ['semver@7.0.0'])
        //截圖標為失敗,原因含離開碼與 log 之結束原因
        assert.strict.equal(j.exsbom.ok, false)
        assert.strict.match(j.exsbom.error, /於截圖期間意外結束\(離開碼 2\),本次截圖作廢/)
        assert.strict.ok(j.exsbom.error.includes('fatal error: stack overflow') && j.exsbom.error.includes('getSpdxDependencyDepthMap'), j.exsbom.error)
        assert.strict.equal(j.exsbom.overview, null)
        assert.strict.deepStrictEqual(j.exsbom.components, [])
        //上傳前已剔除之循環關係仍列出
        assert.strict.deepStrictEqual(j.exsbom.removedRelationships.map((x) => `${x.from} ${x.relationshipType} ${x.to}`), ['string.prototype.trim@1.2.11 DEPENDENCY_OF es-abstract@1.24.2'])
        //不留截圖(含上次者)與工作子夾;報告標明截圖失敗
        assert.strict.equal(fs.existsSync(path.join(out, 'pics')), false)
        assert.strict.equal(fs.existsSync(path.join(out, 'exsbom-work')), false)
        let md = fs.readFileSync(path.join(out, 'result.md'), 'utf8')
        assert.strict.ok(md.includes(scopeMd), md) //result.md 寫明掃描範圍(Gitea #27)
        assert.strict.ok(md.includes('ex-sbom 截圖失敗，本次無截圖') && !md.includes('](./pics/'), md)
        assert.strict.ok(md.includes('離開碼 2') && md.includes('fatal error: stack overflow'), md) //報告亦見結束原因
        assert.strict.ok(fs.readFileSync(path.join(out, '待更新套件.md'), 'utf8').includes('ex-sbom 截圖失敗，本清單只依 osv-scanner 與 grype'))
        assert.strict.deepStrictEqual(netCalls, [])
    })

    //建議w-scan-dep修正.md(Gitea #24)三(主控裁定 5):W_NPM_INSTALL_TIMEOUT 之時限確實用於 WScanDep 之 npm install
    it(`should stop npm install with a timeout error from W_NPM_INSTALL_TIMEOUT when the registry never responds, before scanning`, async function() {
        npmMode = 'real'
        let reg = await hangRegistry(8987)
        let cacheRoot = path.join(fdt, 'cache-f')
        let out = path.join(fdt, 'out-f')
        let prj = path.join(fdt, 'prj-dep', 'package.json')
        fs.mkdirSync(path.dirname(prj), { recursive: true })
        fs.writeFileSync(prj, JSON.stringify({ name: 'prj-dep', version: '1.0.0', dependencies: { 'is-number': '7.0.0' } }))
        let err
        let ms
        try {
            let t0 = Date.now()
            err = await withEnv({
                W_BIN_CACHE: cacheRoot,
                W_BIN_MIRROR: mirror,
                W_BIN_OFFLINE: '1',
                W_NPM_INSTALL_TIMEOUT: '5',
                npm_config_registry: reg.url,
                npm_config_cache: path.join(fdt, 'npm-cache'),
                npm_config_update_notifier: 'false',
            }, () => WScanDep(prj, out).then(() => null, (e) => e))
            ms = Date.now() - t0
            assert.strict.ok(await reg.allClosed(15000), `仍有 ${reg.open()} 條連線未關閉:npm 行程未結束`)
        }
        finally {
            await reg.close()
        }
        assert.strict.equal(err instanceof Error, true)
        assert.strict.match(err.message, /npm install 逾時\(超過 5 秒未完成\),已結束安裝子行程樹/)
        assert.strict.ok(ms >= 5000, String(ms))
        assert.strict.deepStrictEqual(calls.map((v) => v.kind), ['npm']) //未進入掃描
        assert.strict.equal(fs.existsSync(path.join(out, 'result.json')), false)
    })

    it(`should reject a W_NPM_INSTALL_TIMEOUT that is not a positive number before obtaining the tools or writing anything`, async function() {
        let cacheRoot = path.join(fdt, 'cache-g')
        let out = path.join(fdt, 'out-g')
        for (let v of ['0', 'abc']) {
            let err = await withEnv({ W_NPM_INSTALL_TIMEOUT: v, W_BIN_CACHE: cacheRoot, W_BIN_MIRROR: mirror, W_BIN_OFFLINE: '1' }, () => {
                return WScanDep(fpIn, out).then(() => null, (e) => e)
            })
            assert.strict.equal(err instanceof Error, true, v)
            assert.strict.equal(err.message.includes('W_NPM_INSTALL_TIMEOUT 須為正數'), true, err.message)
        }
        assert.strict.deepStrictEqual(calls, [])
        assert.strict.deepStrictEqual(netCalls, [])
        assert.strict.equal(fs.existsSync(out), false)
        assert.strict.equal(fs.existsSync(cacheRoot), false) //ensureBins 未執行
    })

    //建議w-scan-dep修正.md(Gitea #24)三之同類(主控裁定 2): syft、grype、osv-scanner 之時限各由 W_SYFT_TIMEOUT、W_GRYPE_TIMEOUT、W_OSV_SCANNER_TIMEOUT 決定,
    //逾時結束整個子行程樹並以含「逾時」與工具名之錯誤中止(不寫出 result.*; 其後之工具不啟動)
    let tools = [
        { name: 'syft', env: 'W_SYFT_TIMEOUT', before: ['tool'] },
        { name: 'grype', env: 'W_GRYPE_TIMEOUT', before: ['tool', 'tool'] },
        { name: 'osv-scanner', env: 'W_OSV_SCANNER_TIMEOUT', before: ['tool', 'tool', 'tool'] }, //osv-scanner 先跑 markdown(卡住), 不跑 json
    ]
    for (let t of tools) {
        it(`should stop with a timeout error naming ${t.name} from ${t.env} when ${t.name} never finishes, killing its whole process tree and not running the later tools`, async function() {
            this.timeout(40000) //時限 8 秒(須長於替身之根行程與孫行程兩個 node 啟動並連線所需之時間); 此上限只防懸置
            hangName = t.name
            let reg = await hangRegistry(hangPort)
            let cacheRoot = path.join(fdt, `cache-h-${t.name}`)
            let out = path.join(fdt, `out-h-${t.name}`)
            let err
            let ms
            try {
                let t0 = Date.now()
                err = await withEnv({ W_BIN_CACHE: cacheRoot, W_BIN_MIRROR: mirror, W_BIN_OFFLINE: '1', [t.env]: '8' }, () => WScanDep(fpIn, out).then(() => null, (e) => e))
                ms = Date.now() - t0
                //前提: 替身之根行程與孫行程皆已連線; 其後全數連線關閉=整個子行程樹已結束
                assert.strict.ok(reg.accepted() >= 2, `替身應已連線(根行程與孫行程), 收到 ${reg.accepted()} 條`)
                assert.strict.ok(await reg.allClosed(15000), `仍有 ${reg.open()} 條連線未關閉:子行程樹未全數結束`)
            }
            finally {
                await reg.close()
            }
            assert.strict.equal(err instanceof Error, true)
            assert.strict.equal(err.message, `${t.name} 逾時(超過 8 秒未完成),已結束 ${t.name} 子行程樹;可設環境變數 ${t.env}(秒)調整時限`)
            assert.strict.ok(ms >= 8000 - 50, String(ms))
            assert.strict.deepStrictEqual(calls.map((v) => v.kind), ['npm', ...t.before]) //逾時之工具為最後一個被啟動者
            assert.strict.equal(fs.existsSync(path.join(out, 'result.json')), false)
        })
    }

    it(`should reject a syft, grype or osv-scanner time limit that is not a positive number before obtaining the tools or writing anything`, async function() {
        let cacheRoot = path.join(fdt, 'cache-i')
        let out = path.join(fdt, 'out-i')
        for (let name of ['W_SYFT_TIMEOUT', 'W_GRYPE_TIMEOUT', 'W_OSV_SCANNER_TIMEOUT']) {
            for (let v of ['0', 'abc', '2147484']) {
                let err = await withEnv({ [name]: v, W_BIN_CACHE: cacheRoot, W_BIN_MIRROR: mirror, W_BIN_OFFLINE: '1' }, () => {
                    return WScanDep(fpIn, out).then(() => null, (e) => e)
                })
                assert.strict.equal(err instanceof Error, true, `${name}=${v}`)
                assert.strict.equal(err.message.includes(`環境變數 ${name} 須為正數`) && err.message.includes(`「${v}」`), true, err.message)
            }
        }
        assert.strict.deepStrictEqual(calls, [])
        assert.strict.deepStrictEqual(netCalls, [])
        assert.strict.equal(fs.existsSync(out), false)
        assert.strict.equal(fs.existsSync(cacheRoot), false) //ensureBins 未執行
    })

    //建議w-scan-dep調整.md(Gitea #27, 主控裁定 2、3、5): 掃描範圍只算 dependencies。真實 npm 對本機假 registry(夾具 test/tools/scopeFixture.mjs):
    //devDependencies 及其只在開發樹之相依不落地; 風險套件 semver 同時被正式套件與開發工具引入, 待更新清單(updateList)只剩正式路徑;
    //result.json 之 scope、result.md 與待更新套件.md 寫明範圍
    it(`should scan only the dependencies tree: devDependencies are not installed, the update list holds only the production paths, and the scope is stated in result.json, result.md and the update list (Gitea #27)`, async function() {
        npmMode = 'real'
        let reg = await fakeNpmRegistry(8998, scopePackages)
        let cacheRoot = path.join(fdt, 'cache-j')
        let out = path.join(fdt, 'out-j')
        let prj = path.join(fdt, 'prj-scope', 'package.json')
        fs.mkdirSync(path.dirname(prj), { recursive: true })
        fs.writeFileSync(prj, JSON.stringify(scopeProject))
        let r
        try {
            r = await withEnv({
                W_BIN_CACHE: cacheRoot,
                W_BIN_MIRROR: mirror,
                W_BIN_OFFLINE: '1',
                npm_config_registry: reg.url,
                npm_config_cache: path.join(fdt, 'npm-cache-j'),
                npm_config_update_notifier: 'false',
            }, () => WScanDep(prj, out))
        }
        finally {
            await reg.close()
        }
        assert.strict.equal(r, 'ok')
        assert.strict.deepStrictEqual(calls.map((v) => v.kind), ['npm', 'tool', 'tool', 'tool', 'tool', 'spawn'])
        //掃描目標(fdOut/test)只含正式相依樹
        let nm = path.join(out, 'test', 'node_modules')
        for (let name of scopeInstalled) {
            assert.strict.equal(fs.existsSync(path.join(nm, name, 'package.json')), true, `${name} 應被安裝`)
        }
        for (let name of scopeNotInstalled) {
            assert.strict.equal(fs.existsSync(path.join(nm, name)), false, `${name} 不應被安裝`)
        }
        let j = JSON.parse(fs.readFileSync(path.join(out, 'result.json'), 'utf8'))
        assert.strict.deepStrictEqual(Object.keys(j), ks)
        assert.strict.equal(j.scope, 'dependencies')
        //待更新清單: semver@7.0.0 之引入路徑只有正式套件 prod-mid, 無開發工具 dev-tool
        let items = j.updateList.origins.flatMap((o) => o.items.map((v) => `${v.depName}->${v.leafName}@${v.leafVersion}`))
        assert.strict.deepStrictEqual(items, ['prod-mid->semver@7.0.0'])
        assert.strict.deepStrictEqual(j.updateList.cascades.map((c) => `${c.leaf}|${c.chainStr}`), ['semver@7.0.0|主系統'])
        let md = fs.readFileSync(path.join(out, 'result.md'), 'utf8')
        assert.strict.ok(md.includes(scopeMd), md)
        let up = fs.readFileSync(path.join(out, '待更新套件.md'), 'utf8')
        assert.strict.ok(up.includes(scopeMd) && up.includes('prod-mid') && !up.includes('dev-tool'), up)
    })

    //建議w-scan-dep調整.md(Gitea #27, run02 裁定 1、3): result.json 之 scope: 'dependencies' 必須為真, 不受呼叫端 npm 設定影響。
    //呼叫端環境設了 npm_config_include=dev／npm_config_production=false(會抵消 --omit=dev)時, 入口照常完成且 dev 套件仍不落地;
    //交給安裝子行程之環境副本已移除該二項, 而呼叫端之 process.env 不變
    it(`should keep the dependencies scope true when the caller environment sets npm_config_include=dev and npm_config_production=false (Gitea #27, run02)`, async function() {
        npmMode = 'real'
        let reg = await fakeNpmRegistry(8998, scopePackages)
        let cacheRoot = path.join(fdt, 'cache-k')
        let out = path.join(fdt, 'out-k')
        let prj = path.join(fdt, 'prj-scope-env', 'package.json')
        fs.mkdirSync(path.dirname(prj), { recursive: true })
        fs.writeFileSync(prj, JSON.stringify(scopeProject))
        let r
        try {
            r = await withEnv({
                W_BIN_CACHE: cacheRoot,
                W_BIN_MIRROR: mirror,
                W_BIN_OFFLINE: '1',
                npm_config_registry: reg.url,
                npm_config_cache: path.join(fdt, 'npm-cache-k'),
                npm_config_update_notifier: 'false',
                npm_config_include: 'dev',
                npm_config_production: 'false',
            }, () => WScanDep(prj, out))
        }
        finally {
            await reg.close()
        }
        assert.strict.equal(r, 'ok')
        assert.strict.equal(calls[0].callerInclude, 'dev') //啟動安裝時呼叫端之 process.env 仍有該設定(只移除子行程副本)
        assert.strict.ok(calls[0].env && typeof calls[0].env === 'object', 'npm install 須明給子行程環境副本')
        assert.strict.deepStrictEqual(Object.keys(calls[0].env).filter((k) => /^npm_config_(include|production|dev|also)$/i.test(k)), [])
        assert.strict.equal(calls[0].env.npm_config_registry, reg.url) //其餘設定照傳
        let nm = path.join(out, 'test', 'node_modules')
        for (let name of scopeNotInstalled) {
            assert.strict.equal(fs.existsSync(path.join(nm, name)), false, `${name} 不應被安裝`)
        }
        for (let name of scopeInstalled) {
            assert.strict.equal(fs.existsSync(path.join(nm, name, 'package.json')), true, `${name} 應被安裝`)
        }
        let j = JSON.parse(fs.readFileSync(path.join(out, 'result.json'), 'utf8'))
        assert.strict.equal(j.scope, 'dependencies')
    })

    //run02 裁定 2: 安裝後驗證有 dev 套件落地(此處為使用者層設定檔 include[]=dev, 環境變數無從移除)即拋錯, 不得輸出 scope: 'dependencies'
    //此時未進入掃描(不啟動 syft／grype／osv-scanner／ex-sbom), 不寫出 result.json／result.md／待更新套件.md
    it(`should reject without writing any result when a dev package is installed in spite of --omit=dev (user-level include=dev), never stating scope dependencies (Gitea #27, run02)`, async function() {
        npmMode = 'real'
        let reg = await fakeNpmRegistry(8998, scopePackages)
        let cacheRoot = path.join(fdt, 'cache-l')
        let out = path.join(fdt, 'out-l')
        let prj = path.join(fdt, 'prj-scope-rc', 'package.json')
        let userrc = path.join(fdt, 'user-include-dev.npmrc')
        fs.mkdirSync(path.dirname(prj), { recursive: true })
        fs.writeFileSync(prj, JSON.stringify(scopeProject))
        fs.writeFileSync(userrc, 'include[]=dev\n')
        let err
        try {
            err = await withEnv({
                W_BIN_CACHE: cacheRoot,
                W_BIN_MIRROR: mirror,
                W_BIN_OFFLINE: '1',
                npm_config_registry: reg.url,
                npm_config_cache: path.join(fdt, 'npm-cache-l'),
                npm_config_update_notifier: 'false',
                npm_config_userconfig: userrc,
            }, () => WScanDep(prj, out).then(() => null, (e) => e))
        }
        finally {
            await reg.close()
        }
        assert.strict.ok(err instanceof Error, 'WScanDep 應 reject')
        assert.strict.match(err.message, /掃描範圍 dependencies 不成立/)
        assert.strict.ok(err.message.includes('dev-tool'), err.message)
        assert.strict.deepStrictEqual(calls.map((v) => v.kind), ['npm']) //未進入掃描
        for (let f of ['result.json', 'result.md', '待更新套件.md']) {
            assert.strict.equal(fs.existsSync(path.join(out, f)), false, `${f} 不應被寫出`)
        }
    })

    //主控裁定(隔離安裝沿用呼叫端專案之倉庫設定, 規則帳本 R-NPM-REGISTRY-01): 隔離安裝(fdOut/test)只複製 package.json, npm 之專案層 .npmrc 取自安裝目錄,
    //讀不到呼叫端專案層之 .npmrc。以下以真實 npm 對本機假 registry(A 埠 8975、B 埠 8976、scope 專用 S 埠 8977; 夾具 test/tools/scopeFixture.mjs)走 WScanDep 全流程(掃描工具為替身);
    //使用者層與全域設定檔以 npm_config_userconfig／globalconfig 指向本案暫存夾, npm_config_registry 清除, 不動使用者之 ~/.npmrc;
    //取得失敗各形態以替身 npm(test/tools/fakeNpm/, 置於 PATH 前端)模擬。npm 本身之輸出(stdio 繼承)不在 console 攔截範圍
    describe(`the registry settings of the calling project (R-NPM-REGISTRY-01)`, function() {
        let ports = { A: 8975, B: 8976, S: 8977 }
        let regs = {}
        let rseq = 0
        let emptyGlobal = ''
        let fakeNpmDir = path.resolve('./test/tools/fakeNpm')
        let pkgScoped = { ...scopeProject, dependencies: { ...scopeProject.dependencies, '@acme/lib': '1.0.0' } }
        let SEC = { projToken: 'PROJ-SECRET-TOKEN-91f3', projAuth: 'PROJ-SECRET-AUTH-77aa', projUser: 'proj-secret-user-5c2d', projPass: 'proj-secret-pass-0b8e', userToken: 'USER-SECRET-TOKEN-4e19', urlUser: 'leakuser', urlPass: 'leakpass', fakeNpm: 'FAKE-NPM-SECRET-d41d8cd9' }
        let b64 = (s) => Buffer.from(s).toString('base64')
        let secrets = Object.values(SEC).concat([b64(SEC.projAuth), b64(SEC.projPass)])
        let leaks = (text) => secrets.filter((v) => text.includes(v))

        let wr = (f, text) => {
            fs.mkdirSync(path.dirname(f), { recursive: true })
            fs.writeFileSync(f, text)
            return f
        }
        let pathWith = (dir) => {
            let k = Object.keys(process.env).find((x) => x.toLowerCase() === 'path') || 'PATH'
            return { [k]: dir + path.delimiter + (process.env[k] || '') }
        }
        let listFiles = (d) => fs.readdirSync(d, { recursive: true, withFileTypes: true }).filter((v) => v.isFile()).map((v) => path.join(v.parentPath, v.name))
        let installedNames = (d) => fs.readdirSync(d).filter((n) => !n.startsWith('.')).sort()

        //呼叫端專案(package.json 與專案層 .npmrc)、使用者層設定檔與一次執行所需之環境
        let setup = (pkg, projRc, userRc) => {
            let n = ++rseq
            let prj = wr(path.join(fdt, `prj-r${n}`, 'package.json'), JSON.stringify(pkg))
            if (projRc !== null) wr(path.join(fdt, `prj-r${n}`, '.npmrc'), projRc)
            return {
                prj,
                out: path.join(fdt, `out-r${n}`),
                env: {
                    W_BIN_CACHE: path.join(fdt, `cache-r${n}`),
                    W_BIN_MIRROR: mirror,
                    W_BIN_OFFLINE: '1',
                    npm_config_registry: undefined,
                    npm_config_userconfig: wr(path.join(fdt, `user-r${n}`, '.npmrc'), userRc),
                    npm_config_globalconfig: emptyGlobal,
                    npm_config_cache: path.join(fdt, `npm-cache-r${n}`),
                    npm_config_update_notifier: 'false',
                },
            }
        }
        //執行並攔截 console 輸出(log、錯誤訊息之認證值斷言用); 回傳 { r, err, logs }
        let run = async (c, extraEnv = {}) => {
            let logs = []
            let bak = [console.log, console.error, console.warn]
            console.log = console.error = console.warn = (...a) => {
                logs.push(a.map(String).join(' '))
            }
            let r = null
            let err = null
            try {
                r = await withEnv({ ...c.env, ...extraEnv }, () => WScanDep(c.prj, c.out))
            }
            catch (e) {
                err = e
            }
            finally {
                [console.log, console.error, console.warn] = bak
            }
            return { r, err, logs }
        }
        let head = /^無法取得呼叫端專案\(.+\)生效之 npm 倉庫設定,已中止/

        before(function() {
            emptyGlobal = wr(path.join(fdt, 'rg', 'empty-global.npmrc'), '\n')
        })
        beforeEach(async function() {
            regs.A = await fakeNpmRegistry(ports.A, scopePackages)
            regs.B = await fakeNpmRegistry(ports.B, {}) //解析不到任何套件
            regs.S = await fakeNpmRegistry(ports.S, { '@acme/lib': { '1.0.0': {} } })
            npmMode = 'real'
        })
        afterEach(async function() {
            for (let k of Object.keys(regs)) await regs[k].close()
            regs = {}
        })

        //spec 1、2(專案層 .npmrc 指 A、使用者層指 B → 由 A 安裝; 於呼叫端專案目錄取得): 修前由 B 解析而 npm install 失敗
        it(`should install from the registry of the calling project (A) rather than the user-level one (B), reading the settings in the folder of the package.json`, async function() {
            let c = setup(scopeProject, `registry=${regs.A.url}\n`, `registry=${regs.B.url}\n`)
            let { r, err } = await run(c)
            assert.strict.equal(err, null, err && err.message)
            assert.strict.equal(r, 'ok')
            assert.strict.deepStrictEqual(calls.map((v) => v.kind), ['npm', 'tool', 'tool', 'tool', 'tool', 'spawn'])
            assert.strict.deepStrictEqual(cfgCalls.map((v) => v.cwd), [path.dirname(c.prj)])
            assert.strict.deepStrictEqual(installedNames(path.join(c.out, 'test', 'node_modules')), scopeInstalled)
            assert.strict.ok(regs.A.requests().some((v) => v.endsWith('.tgz')), `套件應取自 A: ${regs.A.requests()}`)
            assert.strict.deepStrictEqual(regs.B.requests(), [])
            let rc = fs.readFileSync(path.join(c.out, 'test', '.npmrc'), 'utf8')
            assert.strict.ok(rc.includes(`registry="${regs.A.url}"`) && !rc.includes(regs.B.url), rc)
            assert.strict.equal(JSON.parse(fs.readFileSync(path.join(c.out, 'result.json'), 'utf8')).scope, 'dependencies')
            //不改呼叫端專案: 其資料夾內仍只有 package.json 與 .npmrc
            assert.strict.deepStrictEqual(fs.readdirSync(path.dirname(c.prj)).sort(), ['.npmrc', 'package.json'])
        })

        //spec 2(@scope:registry 只設在專案層 → 該 scope 由指定倉庫安裝)
        it(`should install the packages of a scope from the @scope:registry that only the calling project sets`, async function() {
            let c = setup(pkgScoped, `@acme:registry=${regs.S.url}\n`, `registry=${regs.A.url}\n`)
            let { r, err } = await run(c)
            assert.strict.equal(err, null, err && err.message)
            assert.strict.equal(r, 'ok')
            let nm = path.join(c.out, 'test', 'node_modules')
            assert.strict.deepStrictEqual(installedNames(nm), ['@acme', ...scopeInstalled])
            assert.strict.equal(fs.existsSync(path.join(nm, '@acme', 'lib', 'package.json')), true)
            assert.strict.ok(regs.S.requests().some((v) => v.includes('@acme')), `@acme/lib 應取自 S: ${regs.S.requests()}`)
            assert.strict.equal(regs.A.requests().some((v) => v.includes('@acme')), false)
            let rc = fs.readFileSync(path.join(c.out, 'test', '.npmrc'), 'utf8')
            assert.strict.ok(rc.includes(`@acme:registry="${regs.S.url}"`), rc)
        })

        //spec 3(專案層 .npmrc 含 include[]=dev 時仍不被帶入; dev 不落地、#27 驗證照常)
        it(`should not carry include[]=dev or any other setting but the registries from the calling project: devDependencies stay out and the scope stays true (Gitea #27)`, async function() {
            let c = setup(scopeProject, `registry=${regs.A.url}\ninclude[]=dev\nproduction=false\nomit[]=optional\nstrict-ssl=false\n`, `registry=${regs.B.url}\n`)
            let { r, err } = await run(c)
            assert.strict.equal(err, null, err && err.message)
            assert.strict.equal(r, 'ok')
            let nm = path.join(c.out, 'test', 'node_modules')
            for (let name of scopeNotInstalled) assert.strict.equal(fs.existsSync(path.join(nm, name)), false, `${name} 不應被安裝`)
            assert.strict.deepStrictEqual(installedNames(nm), scopeInstalled)
            let rc = fs.readFileSync(path.join(c.out, 'test', '.npmrc'), 'utf8')
            for (let k of ['include', 'production', 'omit', 'strict-ssl']) assert.strict.equal(rc.includes(k), false, `.npmrc 不應含 ${k}: ${rc}`)
            assert.strict.equal(JSON.parse(fs.readFileSync(path.join(c.out, 'result.json'), 'utf8')).scope, 'dependencies')
        })

        //spec 3(不得把任何認證值寫入 fdOut、log、錯誤訊息或結果檔)
        it(`should write no credential into fdOut or the log: not the host-keyed _authToken, _auth, username or _password of the project or the user level`, async function() {
            let projRc = [
                `registry=${regs.A.url}`,
                `//127.0.0.1:${ports.A}/:_authToken=${SEC.projToken}`,
                `//127.0.0.1:${ports.A}/:_auth=${b64(SEC.projAuth)}`,
                `//127.0.0.1:${ports.A}/:username=${SEC.projUser}`,
                `//127.0.0.1:${ports.A}/:_password=${b64(SEC.projPass)}`,
                `_authToken=${SEC.projToken}`,
                '',
            ].join('\n')
            let c = setup(scopeProject, projRc, `//127.0.0.1:${ports.B}/:_authToken=${SEC.userToken}\n`)
            let { r, err, logs } = await run(c)
            assert.strict.equal(err, null, err && err.message)
            assert.strict.equal(r, 'ok')
            //前提: 認證確在呼叫端設定內, 且 log 有記載沿用之倉庫(攔截有效)
            assert.strict.ok(fs.readFileSync(path.join(path.dirname(c.prj), '.npmrc'), 'utf8').includes(SEC.projToken))
            assert.strict.ok(logs.some((v) => v.includes('隔離安裝沿用呼叫端專案之倉庫設定')), logs.join('\n'))
            assert.strict.deepStrictEqual(leaks(logs.join('\n')), [])
            let files = listFiles(c.out)
            assert.strict.ok(files.some((f) => f.endsWith('result.json')) && files.some((f) => f.endsWith('.npmrc')), '應有 result.json 與 .npmrc')
            for (let f of files) assert.strict.deepStrictEqual(leaks(fs.readFileSync(f, 'latin1')), [], `${f} 含認證值`)
        })

        //spec 1(結果只取決於呼叫端專案之設定): fdOut/test 內上次或他處留下之 .npmrc(含 include[]=dev 與舊倉庫)不被沿用
        it(`should replace a stale .npmrc in fdOut/test instead of reusing it`, async function() {
            let c = setup(scopeProject, `registry=${regs.A.url}\n`, `registry=${regs.B.url}\n`)
            wr(path.join(c.out, 'test', '.npmrc'), `registry=http://127.0.0.1:${ports.B}/\ninclude[]=dev\n`)
            let { r, err } = await run(c)
            assert.strict.equal(err, null, err && err.message)
            assert.strict.equal(r, 'ok')
            let rc = fs.readFileSync(path.join(c.out, 'test', '.npmrc'), 'utf8')
            assert.strict.ok(rc.includes(`registry="${regs.A.url}"`) && !rc.includes('include') && !rc.includes(regs.B.url), rc)
            assert.strict.deepStrictEqual(installedNames(path.join(c.out, 'test', 'node_modules')), scopeInstalled)
        })

        //spec 4(取得生效設定失敗: 拋錯、不退回預設、寫明理由; 不含認證值; 未進入安裝與掃描、不寫 fdOut)
        for (let [title, mode, env, tail] of [
            ['npm config list exits with 1', 'exit1', {}, /npm config list --json 離開碼 1;請於該資料夾執行 npm config list 檢視原因$/],
            ['npm config list prints something that is not JSON', 'text', {}, /npm config list --json 之輸出不是 JSON 物件$/],
            ['npm config list never ends within W_NPM_CONFIG_TIMEOUT', 'hang', { W_NPM_CONFIG_TIMEOUT: '3' }, /npm config list --json 逾時\(超過 3 秒未完成\).*W_NPM_CONFIG_TIMEOUT/],
        ]) {
            it(`should reject before installing or writing anything when ${title}, without any credential in the message or the log`, async function() {
                let c = setup(scopeProject, `registry=${regs.A.url}\n`, `registry=${regs.B.url}\n`)
                let { r, err, logs } = await run(c, { ...pathWith(fakeNpmDir), FAKE_NPM_MODE: mode, FAKE_NPM_SECRET: SEC.fakeNpm, ...env })
                assert.strict.equal(r, null)
                assert.strict.ok(err instanceof Error, 'WScanDep 應 reject 而非改用預設倉庫')
                assert.strict.match(err.message, head)
                assert.strict.match(err.message, tail)
                assert.strict.deepStrictEqual(leaks(err.message + '\n' + logs.join('\n')), [])
                assert.strict.deepStrictEqual(calls, []) //未進入安裝與掃描
                assert.strict.deepStrictEqual(regs.A.requests().concat(regs.B.requests()), [])
                assert.strict.equal(fs.existsSync(c.out), false, 'fdOut 不應被建立')
            })
        }

        it(`should reject, naming how to fix it, when the registry of the calling project embeds credentials in its URL (npm lists no registry then)`, async function() {
            let c = setup(scopeProject, `registry=http://${SEC.urlUser}:${SEC.urlPass}@127.0.0.1:${ports.A}/\n`, `registry=${regs.B.url}\n`)
            let { r, err, logs } = await run(c)
            assert.strict.equal(r, null)
            assert.strict.ok(err instanceof Error)
            assert.strict.match(err.message, head)
            assert.strict.match(err.message, /未列出 registry/)
            assert.strict.deepStrictEqual(leaks(err.message + '\n' + logs.join('\n')), [])
            assert.strict.deepStrictEqual(calls, [])
            assert.strict.deepStrictEqual(regs.B.requests(), []) //未退回使用者層之 B
            assert.strict.equal(fs.existsSync(c.out), false)
        })

        it(`should reject a W_NPM_CONFIG_TIMEOUT that is not a positive number before obtaining the tools, reading the npm settings or writing anything`, async function() {
            let c = setup(scopeProject, `registry=${regs.A.url}\n`, `registry=${regs.B.url}\n`)
            for (let v of ['0', 'abc']) {
                let { r, err } = await run(c, { W_NPM_CONFIG_TIMEOUT: v })
                assert.strict.equal(r, null, v)
                assert.strict.ok(err instanceof Error, v)
                assert.strict.ok(err.message.includes('W_NPM_CONFIG_TIMEOUT 須為正數'), err.message)
            }
            assert.strict.deepStrictEqual(calls, [])
            assert.strict.deepStrictEqual(cfgCalls, [])
            assert.strict.deepStrictEqual(netCalls, [])
            assert.strict.equal(fs.existsSync(c.out), false)
            assert.strict.equal(fs.existsSync(c.env.W_BIN_CACHE), false) //ensureBins 未執行
        })

    })

})
