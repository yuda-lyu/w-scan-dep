import fs from 'fs'
import path from 'path'
import assert from 'assert'
import { spawnSync } from 'child_process'
import { fileURLToPath } from 'url'
import fsEnsureBinsBudget from 'wsemi/src/fsEnsureBinsBudget.mjs'
import * as acq from './tools/binsAcquire.mjs'
import { parseTrace, judgeTrace } from './tools/binsTrace.mjs'
import { withEnv } from './tools/fakeBins.mjs'
import { ROOT as PKG_ROOT } from '../src/config.mjs'

//以命名空間取用: 取得工具缺少某匯出時, 只有用到它之案例個別轉紅(而非整檔無法載入)
const { BIN_MANIFEST, BIN_TOTAL_MS, BIN_PARALLEL_FACTOR, BIN_BUDGET_MS, BIN_HOOK_MS, binBudgetMs, binHookMs, readBinManifest, ensureTestBins, makeTraceSink } = acq


//規則帳本 R-BIN-ENSURE-01 規則 10: 測試取得外部執行檔(合計約170 MB)之方式——集中取得、時限取自 wsemi 之 fsEnsureBinsBudget(並行取兩倍)、跨程序只下載一次(wsemi 1.9.75 起之 fsEnsureBins 鎖)
//本檔不連網: 驗證取得工具之時限取得法、參數、事件記錄與判讀、各測試檔之接線, 以及實際執行之取得函式為帶鎖之 wsemi(跨程序只下載一次之行為, 與預算函式和鎖之持有上限之對照, 見 api-ensureBinsLock.test.mjs)
describe('test acquisition of the external executables (binsAcquire)', function() {
    this.timeout(60000)

    let ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..')
    let fdt = path.join(ROOT, 'test', '_tmp', 'binsAcquire')
    let rd = (...ps) => fs.readFileSync(path.join(ROOT, ...ps), 'utf8')
    let ver = (s) => String(s).replace(/^\^/, '').split('.').map(Number)
    let ge = (a, b) => {
        for (let i = 0; i < 3; i++) {
            if (a[i] !== b[i]) return a[i] > b[i]
        }
        return true
    }

    before(function() {
        fs.rmSync(fdt, { recursive: true, force: true })
        fs.mkdirSync(fdt, { recursive: true })
    })

    after(function() {
        fs.rmSync(fdt, { recursive: true, force: true, maxRetries: 5, retryDelay: 200 })
    })

    describe('the function that really runs is the wsemi with the cross-process lock and the budget function', function() {

        it(`should declare wsemi ^1.9.76 or later in package.json (the first version with fsEnsureBinsBudget; the lock is from 1.9.75)`, function() {
            let range = JSON.parse(rd('package.json')).dependencies.wsemi
            assert.strict.match(range, /^\^\d+\.\d+\.\d+$/, range)
            assert.strict.ok(ge(ver(range), [1, 9, 76]), range)
        })

        it(`should install wsemi 1.9.76 or later as the single copy that src/ensureBins.mjs and binsAcquire.mjs load from source, not through a dist`, function() {
            let installed = JSON.parse(rd('node_modules', 'wsemi', 'package.json')).version
            assert.strict.ok(ge(ver(installed), [1, 9, 76]), installed)
            //取得時限之預算函式亦自 node_modules 內之單一 wsemi 原始碼匯入(binsAcquire.mjs)
            let bsrc = rd('test', 'tools', 'binsAcquire.mjs')
            assert.strict.match(bsrc, /^import fsEnsureBinsBudget from 'wsemi\/src\/fsEnsureBinsBudget\.mjs'$/m)
            let urlB = import.meta.resolve('wsemi/src/fsEnsureBinsBudget.mjs')
            assert.strict.equal(fs.realpathSync(fileURLToPath(urlB)).toLowerCase(), fs.realpathSync(path.join(ROOT, 'node_modules', 'wsemi', 'src', 'fsEnsureBinsBudget.mjs')).toLowerCase())
            //src/ensureBins.mjs 匯入 wsemi/src/fsEnsureBins.mjs(原始碼, 非 dist 之 UMD: dist 內嵌其建置時之 wsemi, 升 wsemi 對其無效)
            let src = rd('src', 'ensureBins.mjs')
            assert.strict.match(src, /^import fsEnsureBins from 'wsemi\/src\/fsEnsureBins\.mjs'$/m)
            assert.strict.doesNotMatch(src, /wsemi\/dist|from 'wsemi'/)
            //該匯入實際解析到 node_modules 內之單一 wsemi(非巢狀或內嵌之他份)
            //(兩側皆取真實路徑: node_modules 為目錄連結之臨時副本亦同)
            let url = import.meta.resolve('wsemi/src/fsEnsureBins.mjs')
            let fp = fs.realpathSync(fileURLToPath(url))
            let want = fs.realpathSync(path.join(ROOT, 'node_modules', 'wsemi', 'src', 'fsEnsureBins.mjs'))
            assert.strict.equal(fp.toLowerCase(), want.toLowerCase())
        })

        it(`should load a fsEnsureBinsCore that has the lock (events lock-wait, lock-takeover, error E_LOCK_TIMEOUT); that the lock limit is the value of fsEnsureBinsBudget is checked by behaviour in api-ensureBinsLock.test.mjs (limitMs of the lock file)`, function() {
            let core = rd('node_modules', 'wsemi', 'src', 'fsEnsureBinsCore.mjs')
            for (let s of ['lock-wait', 'lock-takeover', 'E_LOCK_TIMEOUT']) {
                assert.strict.ok(core.includes(s), s)
            }
        })
    })

    describe('the time limit comes from wsemi fsEnsureBinsBudget (no own formula) and covers parallel acquisition, not the 180 seconds of mocha', function() {

        //規格 外部執行檔之存放下載校驗與離線(制式規格) §6 E5-3: 使用端測試之首次取得時限以 fsEnsureBinsBudget 求得、不自寫算式; 並行時最壞約為兩倍, before 時限取兩倍
        it(`should take BIN_BUDGET_MS from fsEnsureBinsBudget over this package's bin/manifest.json with the explicit totalMs 600000 (the wsemi default, not shortened), and BIN_HOOK_MS as 2 times of it (parallel acquisition)`, function() {
            let at = (o) => fsEnsureBinsBudget('bin/manifest.json', { pkgRoot: PKG_ROOT, ...o })
            let want = at({ totalMs: 600000, mirror: '', offline: false })
            assert.strict.equal(BIN_MANIFEST, 'bin/manifest.json')
            assert.strict.equal(BIN_TOTAL_MS, 600000)
            assert.strict.equal(BIN_PARALLEL_FACTOR, 2)
            assert.strict.equal(BIN_BUDGET_MS, want)
            assert.strict.equal(BIN_HOOK_MS, 2 * want)
            assert.strict.equal(binBudgetMs({ mirror: '', offline: false }), want)
            assert.strict.equal(binHookMs({ mirror: '', offline: false }), 2 * want)
            //totalMs 即 wsemi 預設(不縮短): 不給 totalMs 時預算相同; 縮短則預算變小(前提: 此式對 totalMs 敏感, 上列相等才有鑑別力)
            assert.strict.equal(at({ mirror: '', offline: false }), want)
            assert.strict.ok(at({ totalMs: 300000, mirror: '', offline: false }) < want)
            assert.strict.ok(BIN_HOOK_MS > 180000 * 10, 'mocha 之 180 秒遠低於下載預算')
        })

        it(`should leave the mirror and offline choice to the environment variables W_BIN_MIRROR and W_BIN_OFFLINE as fsEnsureBins does (a mirror tries each source twice, offline skips the trunk manifest fetch)`, async function() {
            let at = (o) => fsEnsureBinsBudget('bin/manifest.json', { pkgRoot: PKG_ROOT, totalMs: 600000, ...o })
            let online = at({ mirror: '', offline: false })
            let withMirror = at({ mirror: 'C:\\somewhere', offline: false })
            let offline = at({ mirror: '', offline: true })
            assert.strict.ok(withMirror > online && offline < online, '前提: 三值相異才有鑑別力')
            let env = (mirror, off) => ({ W_BIN_MIRROR: mirror, W_BIN_OFFLINE: off })
            assert.strict.equal(await withEnv(env(undefined, undefined), () => binBudgetMs()), online)
            assert.strict.equal(await withEnv(env('C:\\somewhere', undefined), () => binBudgetMs()), withMirror)
            assert.strict.equal(await withEnv(env(undefined, '1'), () => binBudgetMs()), offline)
            assert.strict.equal(await withEnv(env('C:\\somewhere', undefined), () => binHookMs()), 2 * withMirror)
        })

        it(`should let an error of the budget function through, not guess a number (the budget function validates the manifest and options itself)`, function() {
            let boom = Object.assign(new Error('boom'), { code: 'E_MANIFEST' })
            let thrower = () => {
                throw boom
            }
            assert.strict.throws(() => binBudgetMs({}, thrower), (e) => e === boom)
            assert.strict.throws(() => binHookMs({}, thrower), (e) => e === boom)
        })

        it(`should keep no own copy of the budget formula on the test side (the only source is fsEnsureBinsBudget imported from the wsemi source), and use the same manifest as src/ensureBins.mjs`, function() {
            //自寫算式之特徵: 持鎖/下載預算之組成項、舊函式名與常數(註解行不算)
            let own = /KILL_WAIT|SLACK_MS|STALL_MS|Math\.min\(\s*\w*[tT]otalMs|Math\.min\([^)]*,\s*60000\s*\)|calcBinBudgetMs|lockBudget\(|unitBudget\(/
            let codeOf = (src) => src.split(/\r?\n/).filter((v) => !/^\s*\/\//.test(v)).join('\n')
            let hits = []
            let self = 'unit-binsAcquire.test.mjs'
            for (let f of fs.readdirSync(path.join(ROOT, 'test')).filter((v) => /\.test\.mjs$/.test(v) && v !== self)) {
                if (own.test(codeOf(rd('test', f)))) hits.push(`test/${f}`)
            }
            for (let f of fs.readdirSync(path.join(ROOT, 'test', 'tools')).filter((v) => /\.mjs$/.test(v))) {
                if (own.test(codeOf(rd('test', 'tools', f)))) hits.push(`test/tools/${f}`)
            }
            assert.strict.deepStrictEqual(hits, [])
            let bsrc = rd('test', 'tools', 'binsAcquire.mjs')
            assert.strict.match(bsrc, /^import fsEnsureBinsBudget from 'wsemi\/src\/fsEnsureBinsBudget\.mjs'$/m)
            assert.strict.match(codeOf(bsrc), /budget\(BIN_MANIFEST,/)
            //清單: 預算與取得(src/ensureBins.mjs 交給 fsEnsureBins 者)為同一份
            assert.strict.ok(rd('src', 'ensureBins.mjs').includes(`fsEnsureBins('${BIN_MANIFEST}'`), 'src/ensureBins.mjs 取得之清單須即 BIN_MANIFEST')
            assert.strict.deepStrictEqual(readBinManifest().files.map((f) => f.name), ['syft.exe', 'grype.exe', 'osv-scanner.exe', 'ex-sbom.exe'])
        })
    })

    describe('ensureTestBins', function() {

        //替身 ensure: 記錄收到之選項; 不連網
        let mkStub = (ret) => {
            let calls = []
            let ensure = async (o) => {
                calls.push(o)
                if (ret instanceof Error) throw ret
                return ret
            }
            return { ensure, calls }
        }
        let mkCtx = () => {
            let ts = []
            return { timeout: (n) => ts.push(n), ts }
        }
        //替身 budget(取代 fsEnsureBinsBudget): 記錄收到之 [清單, 選項], 回傳固定值(或拋錯)
        let mkBudget = (ret) => {
            let calls = []
            let budget = (manifest, o) => {
                calls.push([manifest, o])
                if (ret instanceof Error) throw ret
                return ret
            }
            return { budget, calls }
        }
        let clean = { WSD_TEST_BINS_TRACE: undefined, W_BIN_MIRROR: undefined, W_BIN_OFFLINE: undefined }

        it(`should set the hook time limit to 2 times of what the budget function returns, ask it with the same manifest, package root and totalMs as the acquisition, pass totalMs only to ensure, and return the paths`, async function() {
            let paths = { 'syft.exe': 'C:\\x\\syft.exe' }
            let { ensure: ensure0, calls } = mkStub(paths)
            let b = mkBudget(123456) //固定值: 時限須由它推得(非自行另算)
            let ctx = mkCtx()
            let setBeforeEnsure = []
            let ensure = async (o) => {
                setBeforeEnsure.push(ctx.ts.length) //開始取得時, hook 時限已設定幾次
                return ensure0(o)
            }
            let r = await withEnv(clean, () => ensureTestBins(ctx, { ensure, budget: b.budget }))
            assert.strict.deepStrictEqual(ctx.ts, [2 * 123456]) //並行取兩倍
            assert.strict.deepStrictEqual(setBeforeEnsure, [1]) //時限須於開始取得之前設定(取得進行中才設則無效)
            assert.strict.equal(r, paths)
            //只傳 totalMs: 不覆寫 names(一次取齊)、cacheDir、mirror、offline(環境變數 W_BIN_* 照常生效)
            assert.strict.deepStrictEqual(calls, [{ totalMs: BIN_TOTAL_MS }])
            //預算函式之引數: 清單為 bin/manifest.json、套件根即 src/ensureBins.mjs 所用者(config.mjs 之 ROOT)、totalMs 與取得者同值; 不另給 mirror、offline(由環境變數決定, 同取得)
            assert.strict.equal(b.calls.length, 1)
            assert.strict.equal(b.calls[0][0], 'bin/manifest.json')
            assert.strict.deepStrictEqual(Object.keys(b.calls[0][1]).sort(), ['pkgRoot', 'totalMs'])
            assert.strict.equal(path.resolve(b.calls[0][1].pkgRoot).toLowerCase(), path.resolve(PKG_ROOT).toLowerCase())
            assert.strict.equal(b.calls[0][1].totalMs, calls[0].totalMs)
        })

        it(`should use the real fsEnsureBinsBudget by default: the hook limit is BIN_HOOK_MS, and with a mirror (W_BIN_MIRROR) 2 times of the budget with the mirror`, async function() {
            let { ensure } = mkStub({})
            let c1 = mkCtx()
            await withEnv(clean, () => ensureTestBins(c1, { ensure }))
            assert.strict.deepStrictEqual(c1.ts, [BIN_HOOK_MS])
            let c2 = mkCtx()
            await withEnv({ ...clean, W_BIN_MIRROR: 'C:\\somewhere' }, () => ensureTestBins(c2, { ensure }))
            let want = fsEnsureBinsBudget('bin/manifest.json', { pkgRoot: PKG_ROOT, totalMs: 600000, mirror: 'C:\\somewhere', offline: false })
            assert.strict.deepStrictEqual(c2.ts, [2 * want])
            assert.strict.ok(c2.ts[0] > BIN_HOOK_MS, '有鏡像時每個來源多試鏡像, 預算較大')
        })

        it(`should work without a mocha context (the budget is still asked, so an invalid manifest fails before any download), and let the ensure error and the budget error through`, async function() {
            let { ensure } = mkStub({ ok: 1 })
            let b = mkBudget(1000)
            assert.strict.deepStrictEqual(await withEnv(clean, () => ensureTestBins(null, { ensure, budget: b.budget })), { ok: 1 })
            assert.strict.equal(b.calls.length, 1)
            let err = Object.assign(new Error('boom'), { code: 'E_X' })
            let s2 = mkStub(err)
            await assert.rejects(withEnv(clean, () => ensureTestBins(mkCtx(), { ensure: s2.ensure })), (e) => e === err)
            //預算函式拋錯(清單或選項無效): 不開始取得, 不改時限
            let bErr = Object.assign(new Error('bad manifest'), { code: 'E_MANIFEST' })
            let s3 = mkStub({})
            let c3 = mkCtx()
            await assert.rejects(withEnv(clean, () => ensureTestBins(c3, { ensure: s3.ensure, budget: mkBudget(bErr).budget })), (e) => e === bErr)
            assert.strict.deepStrictEqual([s3.calls.length, c3.ts.length], [0, 0])
        })

        it(`should pass onTrace only when WSD_TEST_BINS_TRACE is set, and write one JSON line per event with the pid`, async function() {
            let fp = path.join(fdt, 'trace.jsonl')
            let { ensure, calls } = mkStub({})
            await withEnv({ WSD_TEST_BINS_TRACE: fp }, () => ensureTestBins(mkCtx(), { ensure }))
            assert.strict.equal(typeof calls[0].onTrace, 'function')
            calls[0].onTrace(Object.freeze({ type: 'download', name: 'syft.exe', file: 'a' }))
            calls[0].onTrace(Object.freeze({ type: 'lock-wait', name: 'grype.exe', phase: 'start', hit: null }))
            let evs = parseTrace(fs.readFileSync(fp, 'utf8'))
            assert.strict.deepStrictEqual(evs.map((v) => [v.type, v.name, v.pid]), [['download', 'syft.exe', process.pid], ['lock-wait', 'grype.exe', process.pid]])
            assert.strict.equal(makeTraceSink(''), null)
            assert.strict.equal(await withEnv({ WSD_TEST_BINS_TRACE: undefined }, () => makeTraceSink()), null) //環境變數未設:不記錄
            assert.strict.equal(typeof await withEnv({ WSD_TEST_BINS_TRACE: fp }, () => makeTraceSink()), 'function')
            //記錄失敗(路徑不可寫)不影響取得: 不拋錯
            let bad = makeTraceSink(path.join(fdt, 'no-such-dir', 'x.jsonl'))
            assert.strict.doesNotThrow(() => bad({ type: 'download', name: 'a' }))
        })
    })

    describe('trace judgement (download exactly once per tool)', function() {
        let names = ['syft.exe', 'grype.exe', 'osv-scanner.exe', 'ex-sbom.exe']
        let ev = (type, name, o = {}) => ({ pid: 100, t: 1, type, name, ...o })
        let cold1 = () => names.map((n) => ev('download', n))

        it(`should pass a cold cache where each tool is downloaded once (waiting processes may appear)`, function() {
            let evs = [...cold1(), ev('lock-wait', 'syft.exe', { pid: 101, phase: 'start' }), ev('lock-wait', 'syft.exe', { pid: 101, phase: 'end', hit: true })]
            let r = judgeTrace(evs, { names })
            assert.strict.equal(r.ok, true, r.reasons.join(';'))
            assert.strict.equal(r.perName['syft.exe'].lockWait, 1)
            assert.strict.deepStrictEqual(r.pids.sort(), [100, 101])
        })

        it(`should reject a tool downloaded twice (even by different processes), a tool not downloaded in a cold run, a failure, a wait timeout and a skipped lock`, function() {
            let dup = [...cold1(), ev('download', 'syft.exe', { pid: 200 })]
            let r1 = judgeTrace(dup, { names })
            assert.strict.equal(r1.ok, false)
            assert.strict.match(r1.reasons[0], /syft\.exe: download 2 times by 2 process/)
            assert.strict.equal(judgeTrace(cold1().slice(1), { names }).ok, false) //冷快取少一個
            assert.strict.equal(judgeTrace([...cold1(), ev('fail', 'grype.exe', { code: 'E_HTTP' })], { names }).ok, false)
            assert.strict.equal(judgeTrace([...cold1(), ev('lock-wait', 'grype.exe', { phase: 'timeout' })], { names }).ok, false)
            assert.strict.equal(judgeTrace([...cold1(), ev('lock-skip', 'grype.exe', { why: 'fail' })], { names }).ok, false)
        })

        it(`should require zero downloads when the cache is warm`, function() {
            let warm = [ev('cache', 'syft.exe', { hit: true })]
            assert.strict.equal(judgeTrace(warm, { names, cold: false }).ok, true)
            assert.strict.equal(judgeTrace(cold1(), { names, cold: false }).ok, false)
        })

        it(`should parse the trace file strictly, and the command line should exit 0, 1 and 2`, function() {
            assert.strict.throws(() => parseTrace('{"type":"a"}\nnot json'), /line 2 is not JSON/)
            assert.strict.throws(() => parseTrace('{"x":1}'), /line 1 has no type/)
            assert.strict.deepStrictEqual(parseTrace('\n{"type":"a"}\n\n'), [{ type: 'a' }])
            let cli = (args) => spawnSync(process.execPath, [path.join(ROOT, 'test', 'tools', 'binsTrace.mjs'), ...args], { encoding: 'utf8', windowsHide: true })
            let ok = path.join(fdt, 'ok.jsonl')
            let ng = path.join(fdt, 'ng.jsonl')
            let em = path.join(fdt, 'empty.jsonl')
            fs.writeFileSync(ok, cold1().map((v) => JSON.stringify(v)).join('\n'))
            fs.writeFileSync(ng, [...cold1(), ev('download', 'syft.exe', { pid: 200 })].map((v) => JSON.stringify(v)).join('\n'))
            fs.writeFileSync(em, '')
            let r0 = cli([ok])
            assert.strict.equal(r0.status, 0, r0.stdout + r0.stderr)
            assert.strict.match(r0.stdout, /syft\.exe: download 1 \(processes 1\)/)
            assert.strict.equal(cli([ng]).status, 1)
            //名單取自 bin/manifest.json 之全部工具: 最後一個(ex-sbom)重複下載、或缺少,亦判不通過
            let ng2 = path.join(fdt, 'ng2.jsonl')
            fs.writeFileSync(ng2, [...cold1(), ev('download', 'ex-sbom.exe', { pid: 200 })].map((v) => JSON.stringify(v)).join('\n'))
            assert.strict.equal(cli([ng2]).status, 1)
            let ng3 = path.join(fdt, 'ng3.jsonl')
            fs.writeFileSync(ng3, cold1().filter((v) => v.name !== 'ex-sbom.exe').map((v) => JSON.stringify(v)).join('\n'))
            assert.strict.equal(cli([ng3]).status, 1)
            assert.strict.equal(cli([ok, '--warm']).status, 1)
            assert.strict.equal(cli([em]).status, 2)
            assert.strict.equal(cli([path.join(fdt, 'none.jsonl')]).status, 2)
            assert.strict.equal(cli([]).status, 2)
        })
    })

    describe('wiring: every test that needs the real tools gets them through the one acquisition point, in a before hook', function() {
        let tests = () => fs.readdirSync(path.join(ROOT, 'test')).filter((v) => /\.test\.mjs$/.test(v))
        let tools = () => fs.readdirSync(path.join(ROOT, 'test', 'tools')).filter((v) => /\.mjs$/.test(v))
        //首個 describe 區塊(含)起, 取 describe 名稱為 name 之區塊文字(到下一個頂層 describe 前)
        let blockOf = (src, name) => {
            let i = src.indexOf(`describe('${name}'`)
            assert.strict.ok(i >= 0, name)
            let j = src.indexOf('\ndescribe(', i + 1)
            return src.slice(i, j < 0 ? src.length : j)
        }
        let beforeBeforeFirstIt = (block) => {
            let b = block.search(/before\(async function\(\) \{\s*(?:\S[^\n]*=\s*)?\(?await ensureTestBins\(this\)/)
            let t = block.search(/\n\s*it\(/)
            return b >= 0 && t >= 0 && b < t
        }

        it(`should have no test or tool importing src/ensureBins.mjs statically except the acquisition point (the cache of the real package root is reached only through it)`, function() {
            let re = /from\s+['"](?:\.\.\/)+src\/ensureBins\.mjs['"]/
            let hits = []
            for (let f of tests()) {
                if (re.test(rd('test', f))) hits.push(`test/${f}`)
            }
            for (let f of tools()) {
                if (re.test(rd('test', 'tools', f))) hits.push(`test/tools/${f}`)
            }
            assert.strict.deepStrictEqual(hits, ['test/tools/binsAcquire.mjs'])
        })

        it(`should get the tools in WScanDep.test.mjs before the first case of both describes (the implicit acquisition inside wsd, and captureExSbom)`, function() {
            let src = rd('test', 'WScanDep.test.mjs')
            assert.strict.match(src, /^import \{ ensureTestBins \} from '\.\/tools\/binsAcquire\.mjs'$/m)
            assert.strict.equal((src.match(/ensureTestBins\(this\)/g) || []).length, 2)
            assert.strict.equal(beforeBeforeFirstIt(blockOf(src, 'WScanDep')), true, 'describe WScanDep')
            assert.strict.equal(beforeBeforeFirstIt(blockOf(src, 'captureExSbom')), true, 'describe captureExSbom')
            assert.strict.equal(/\.skip\(\)/.test(src), false, '取得失敗不得以略過掩蓋')
        })

        it(`should get the tools in api-scanScope.test.mjs in a before hook of its own (its time limit is the download budget)`, function() {
            let src = rd('test', 'api-scanScope.test.mjs')
            assert.strict.match(src, /^import \{ ensureTestBins \} from '\.\/tools\/binsAcquire\.mjs'$/m)
            assert.strict.equal((src.match(/ensureTestBins\(this\)/g) || []).length, 1)
            assert.strict.equal(beforeBeforeFirstIt(blockOf(src, 'scan scope (real syft over the dependencies-only install)')), true)
            assert.strict.match(src, /before\(async function\(\) \{\s*bins = await ensureTestBins\(this\)[^\n]*\n\s*\}\)/) //該 before 只取得, 不含 npm install 與掃描
        })

        it(`should get the real osv-scanner in unit-runOsv.test.mjs in a before hook of its own describe (not by looking for a leftover path and skipping when absent)`, function() {
            let src = rd('test', 'unit-runOsv.test.mjs')
            assert.strict.match(src, /^import \{ ensureTestBins \} from '\.\/tools\/binsAcquire\.mjs'$/m)
            assert.strict.equal((src.match(/ensureTestBins\(this\)/g) || []).length, 1)
            assert.strict.equal(beforeBeforeFirstIt(blockOf(src, 'with the real osv-scanner')), true)
        })

        it(`should have no test that skips for a missing tool or looks for a tool at a leftover path (a silent skip hides that the real tool was never run)`, function() {
            let hits = []
            for (let f of tests()) {
                let code = rd('test', f).split(/\r?\n/).filter((v) => !/^\s*\/\//.test(v)).join('\n') //註解行不算
                if (/\.skip\(\)/.test(code) || /output[\\/]+tools/.test(code)) hits.push(f)
            }
            assert.strict.deepStrictEqual(hits, [])
        })

        it(`should keep the real npm install in the integration tests (core function: scanning the installed dependencies), and say so in the README and the rulebook`, function() {
            assert.strict.match(rd('test', 'api-scanScope.test.mjs'), /await npmInstall\(prj\)/)
            assert.strict.match(rd('README.md'), /測試之網路需求/)
            assert.strict.match(rd('sgud', 'rule', 'rulebook.md'), /網路不穩時會紅/)
        })
    })

})
