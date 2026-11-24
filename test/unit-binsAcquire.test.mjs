import fs from 'fs'
import path from 'path'
import assert from 'assert'
import { spawnSync } from 'child_process'
import { fileURLToPath } from 'url'
import { BIN_TOTAL_MS, BIN_BUDGET_MS, calcBinBudgetMs, readBinManifest, ensureTestBins, makeTraceSink } from './tools/binsAcquire.mjs'
import { parseTrace, judgeTrace } from './tools/binsTrace.mjs'
import { withEnv } from './tools/fakeBins.mjs'


//規則帳本 R-BIN-ENSURE-01 規則 10: 測試取得外部執行檔(合計約170 MB)之方式——集中取得、時限對齊下載預算、跨程序只下載一次(wsemi 1.9.75 起之 fsEnsureBins 鎖)
//本檔不連網: 驗證取得工具之時限推算、參數、事件記錄與判讀、各測試檔之接線, 以及實際執行之取得函式為帶鎖之 wsemi(跨程序只下載一次之行為見 api-ensureBinsLock.test.mjs)
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

    describe('the function that really runs is the wsemi with the cross-process lock', function() {

        it(`should declare wsemi ^1.9.75 or later in package.json (the first version with the lock)`, function() {
            let range = JSON.parse(rd('package.json')).dependencies.wsemi
            assert.strict.match(range, /^\^\d+\.\d+\.\d+$/, range)
            assert.strict.ok(ge(ver(range), [1, 9, 75]), range)
        })

        it(`should install wsemi 1.9.75 or later as the single copy that src/ensureBins.mjs loads from source, not through a dist`, function() {
            let installed = JSON.parse(rd('node_modules', 'wsemi', 'package.json')).version
            assert.strict.ok(ge(ver(installed), [1, 9, 75]), installed)
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

        it(`should load a fsEnsureBinsCore that has the lock (events lock-wait, lock-takeover, error E_LOCK_TIMEOUT); the budget formula it uses is checked by behaviour in api-ensureBinsLock.test.mjs (limitMs of the lock file)`, function() {
            let core = rd('node_modules', 'wsemi', 'src', 'fsEnsureBinsCore.mjs')
            for (let s of ['lock-wait', 'lock-takeover', 'E_LOCK_TIMEOUT']) {
                assert.strict.ok(core.includes(s), s)
            }
        })
    })

    describe('the time limit is the download budget, not the 180 seconds of mocha', function() {

        it(`should derive BIN_BUDGET_MS from the manifest: 2 zip tools and 2 direct tools at totalMs ${BIN_TOTAL_MS} (the wsemi default, not shortened) = 3880000 ms`, function() {
            let m = readBinManifest()
            assert.strict.deepStrictEqual(m.files.map((f) => `${f.name}:${f.extract ? 'zip' : 'direct'}`), ['syft.exe:zip', 'grype.exe:zip', 'osv-scanner.exe:direct', 'ex-sbom.exe:direct'])
            assert.strict.equal(BIN_TOTAL_MS, 600000)
            //手算: 取主幹清單 30000 + 2×壓縮檔(下載1次 600000 + 解壓1批 600000+5000 + 寬裕 60000) + 2×直接檔(下載1次 600000 + 寬裕 60000)
            assert.strict.equal(30000 + 2 * (600000 + 600000 + 5000 + 60000) + 2 * (600000 + 60000), 3880000)
            assert.strict.equal(BIN_BUDGET_MS, 3880000)
            assert.strict.equal(calcBinBudgetMs(m), BIN_BUDGET_MS)
            assert.strict.ok(BIN_BUDGET_MS > 180000 * 10, 'mocha 之 180 秒遠低於下載預算')
        })

        it(`should count the mirror attempts when a mirror is set: each source tries the mirror first`, function() {
            let m = readBinManifest()
            //壓縮檔: 下載次數 1(鏡像最終檔)+2(鏡像壓縮檔、廠商網址) = 3; 直接檔: 2
            let want = 30000 + 2 * (3 * 600000 + 600000 + 5000 + 60000) + 2 * (2 * 600000 + 60000)
            assert.strict.equal(want, 7480000)
            assert.strict.equal(calcBinBudgetMs(m, { mirror: true }), want)
            assert.strict.ok(calcBinBudgetMs(m, { mirror: true }) > calcBinBudgetMs(m))
        })

        it(`should follow totalMs and the entry shapes (one direct file, one zip member)`, function() {
            let d = { name: 'a.exe', url: 'https://x/a.exe', sha256: '0'.repeat(64), size: 1 }
            let z = { ...d, extract: { type: 'zip', member: 'a.exe', sha256: '1'.repeat(64), size: 2 } }
            assert.strict.equal(calcBinBudgetMs({ files: [d] }), 30000 + 600000 + 60000)
            assert.strict.equal(calcBinBudgetMs({ files: [z] }), 30000 + 600000 + 600000 + 5000 + 60000)
            assert.strict.equal(calcBinBudgetMs({ files: [d] }, { totalMs: 1000 }), 30000 + 1000 + 1000) //寬裕為 min(totalMs, 60000)
            assert.strict.equal(calcBinBudgetMs({ files: [d, z] }), calcBinBudgetMs({ files: [d] }) + calcBinBudgetMs({ files: [z] }) - 30000) //各檔逐一取得, 預算相加
        })

        it(`should refuse (not underestimate) manifest shapes the formula does not cover`, function() {
            let d = { name: 'a.exe', url: 'https://x/a.exe', sha256: '0'.repeat(64), size: 1 }
            assert.strict.throws(() => calcBinBudgetMs({ files: [d], bundles: [{ id: 'b' }] }), /unsupported manifest key \[bundles\]/)
            assert.strict.throws(() => calcBinBudgetMs({ files: [{ ...d, parts: [{ url: 'https://x/a.001' }] }] }), /unsupported manifest entry key/)
            assert.strict.throws(() => calcBinBudgetMs({ files: [{ ...d, extract: { type: 'zip', member: 'a', sha256: 'x', size: 1, members: ['a', 'b'] } }] }), /unsupported manifest extract key/)
            assert.strict.throws(() => calcBinBudgetMs({ files: [] }), /non-empty array/)
            assert.strict.throws(() => calcBinBudgetMs(null), /non-empty array/)
            assert.strict.throws(() => calcBinBudgetMs({}), /non-empty array/)
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

        it(`should set the hook time limit to the budget, pass totalMs only, and return the paths of the ensure function`, async function() {
            let paths = { 'syft.exe': 'C:\\x\\syft.exe' }
            let { ensure, calls } = mkStub(paths)
            let ctx = mkCtx()
            let r = await withEnv({ WSD_TEST_BINS_TRACE: undefined, W_BIN_MIRROR: undefined }, () => ensureTestBins(ctx, { ensure }))
            assert.strict.deepStrictEqual(ctx.ts, [BIN_BUDGET_MS])
            assert.strict.equal(r, paths)
            //只傳 totalMs: 不覆寫 names(一次取齊)、cacheDir、mirror、offline(環境變數 W_BIN_* 照常生效)
            assert.strict.deepStrictEqual(calls, [{ totalMs: BIN_TOTAL_MS }])
        })

        it(`should use the mirror budget when W_BIN_MIRROR is set`, async function() {
            let { ensure } = mkStub({})
            let ctx = mkCtx()
            await withEnv({ WSD_TEST_BINS_TRACE: undefined, W_BIN_MIRROR: 'C:\\somewhere' }, () => ensureTestBins(ctx, { ensure }))
            assert.strict.deepStrictEqual(ctx.ts, [calcBinBudgetMs(readBinManifest(), { mirror: true })])
        })

        it(`should work without a mocha context, and let the ensure error through`, async function() {
            let { ensure } = mkStub({ ok: 1 })
            assert.strict.deepStrictEqual(await withEnv({ WSD_TEST_BINS_TRACE: undefined }, () => ensureTestBins(null, { ensure })), { ok: 1 })
            let err = Object.assign(new Error('boom'), { code: 'E_X' })
            let s2 = mkStub(err)
            await assert.rejects(withEnv({ WSD_TEST_BINS_TRACE: undefined }, () => ensureTestBins(mkCtx(), { ensure: s2.ensure })), (e) => e === err)
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
