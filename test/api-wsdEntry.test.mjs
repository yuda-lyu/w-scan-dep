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
    let ks = ['date', 'source', 'outputDir', 'tools', 'osv', 'grype', 'exsbom', 'updateList']
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
            if (/^npm install/.test(c)) {
                let opt = rest.find((v) => v && !Array.isArray(v) && typeof v === 'object')
                calls.push({ kind: 'npm', cmd: c, cwd: opt && opt.cwd })
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

})
