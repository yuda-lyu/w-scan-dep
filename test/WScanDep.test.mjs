import assert from 'assert'
import fs from 'fs'
import path from 'path'
import http from 'http'
import { spawn, spawnSync } from 'child_process'
import wsd from '../src/WScanDep.mjs'
import { captureExSbom, listeningPorts, excludedPorts, pickPort } from '../src/exsbom.mjs'


describe('WScanDep', function() {
    this.timeout(1800000) //首次執行須下載掃描工具與npm install,耗時較久

    let fpIn = './test/prj/package.json'
    let fdOut = './test/output'
    let ks = ['date', 'source', 'outputDir', 'tools', 'osv', 'grype', 'exsbom', 'updateList']

    it('test', async function() {
        let r = await wsd(fpIn, fdOut)
        assert.strict.strictEqual(r, 'ok')

        //result.json之欄位
        let j = JSON.parse(fs.readFileSync(`${fdOut}/result.json`, 'utf8'))
        assert.strict.deepEqual(Object.keys(j), ks)

        //各報告檔案存在
        assert.strict.ok(fs.existsSync(`${fdOut}/result.md`))
        assert.strict.ok(fs.existsSync(`${fdOut}/待更新套件.md`))
        assert.strict.ok(fs.existsSync(`${fdOut}/pics`))
    })

    //opt.fdTools 不可位於 fdOut/test(syft 掃描目標)內,於任何寫入前拒絕
    it('opt.fdTools 位於 fdOut/test 內時拒絕,且不建立 fdOut', async function() {
        let out = './test/_tmp/WScanDep-guard/out'
        await assert.rejects(wsd(fpIn, out, { fdTools: `${out}/test/tools` }), /opt\.fdTools 不可位於輸出資料夾之 test 內/)
        assert.strict.ok(!fs.existsSync(out))
    })

    //opt.fdTools:同一 fdTools 對兩個不同輸出資料夾各掃描一次,第二次不再下載工具;
    //有給 fdTools 時輸出資料夾不產出 tools
    it('opt.fdTools 共用工具資料夾:第二個輸出資料夾不再下載工具,且不產出 tools', async function() {
        //沿用上一案例之 test/output/tools,不以新路徑執行 ex-sbom(Windows 防火牆對新執行檔路徑會再詢問)
        let fdTools = './test/output/tools'
        let root = './test/_tmp/WScanDep-fdTools'
        fs.rmSync(root, { recursive: true, force: true })
        try {
            assert.strict.strictEqual(await wsd(fpIn, `${root}/a`, { fdTools }), 'ok')

            let logs = []
            let log0 = console.log
            console.log = (...args) => {
                logs.push(args.join(' '))
                log0(...args)
            }
            let r
            try {
                r = await wsd(fpIn, `${root}/b`, { fdTools })
            }
            finally {
                console.log = log0
            }
            assert.strict.strictEqual(r, 'ok')

            //第二次:四項工具皆沿用快取,無下載
            for (let k of ['syft', 'grype', 'osv-scanner', 'ex-sbom']) {
                assert.strict.ok(logs.some((m) => m.startsWith(`[${k}] 已有最新版`)), `${k} 應沿用快取`)
                assert.strict.ok(!logs.some((m) => m.startsWith(`[${k}] 下載`)), `${k} 不應下載`)
            }
            assert.strict.ok(logs.some((m) => m.includes(`工具資料夾：${path.resolve(fdTools)}(opt.fdTools 共用)`)))

            //兩個輸出資料夾皆有報告、皆不產出 tools,所用工具版本相同
            for (let d of ['a', 'b']) {
                assert.strict.ok(fs.existsSync(`${root}/${d}/result.md`))
                assert.strict.ok(!fs.existsSync(`${root}/${d}/tools`))
            }
            let ja = JSON.parse(fs.readFileSync(`${root}/a/result.json`, 'utf8'))
            let jb = JSON.parse(fs.readFileSync(`${root}/b/result.json`, 'utf8'))
            assert.strict.deepEqual(jb.tools, ja.tools)
        }
        finally {
            fs.rmSync(root, { recursive: true, force: true })
        }
    })

})


//建議w-scan-dep修正.md:ex-sbom 之工作目錄改為 fdOut 內專用子夾、服務埠自動選用且以監聽 PID 確認為本次子程序。
//只用 test/output/tools 之 ex-sbom(已有防火牆規則,改埠不再詢問);假服務只綁 127.0.0.1(不觸發詢問)
describe('captureExSbom', function() {
    this.timeout(600000)

    let root = path.resolve('./test/_tmp/captureExSbom')
    let work = path.join(root, 'work')
    let pics = path.join(root, 'pics')
    let vuln = path.resolve('./test/fixtures/vuln.spdx.json') //semver 7.0.0(GHSA-c2qf-rxjj-qqgw)
    let clean = path.resolve('./test/fixtures/clean.spdx.json') //is-number 7.0.0
    let quiet = () => {}
    let exe = null

    let findExe = () => {
        let fd = path.resolve('./test/output/tools/ex-sbom')
        if (!fs.existsSync(fd)) return null
        for (let v of fs.readdirSync(fd)) {
            let p = path.join(fd, v, 'ex-sbom.exe')
            if (fs.existsSync(p)) return p
        }
        return null
    }
    let exPids = () => {
        let r = spawnSync(path.join(process.env.SystemRoot, 'System32', 'tasklist.exe'), ['/FI', 'IMAGENAME eq ex-sbom.exe', '/FO', 'CSV', '/NH'], { encoding: 'latin1' })
        return new Set((r.stdout || '').split(/\r?\n/).map((l) => l.match(/^"[^"]*","(\d+)"/)).filter(Boolean).map((m) => Number(m[1])))
    }
    let names = (r) => r.componentShots.map((c) => `${c.name}@${c.version}`)
    let freeBase = (from) => pickPort(listeningPorts(), excludedPorts(), from, 18180)
    let pids0

    before(function() {
        exe = findExe()
        if (!exe) this.skip() //尚未完整掃描過、無已下載之 ex-sbom
    })

    beforeEach(function() {
        fs.rmSync(root, { recursive: true, force: true })
        fs.mkdirSync(root, { recursive: true })
        pids0 = exPids()
    })

    afterEach(function() {
        //每案結束後不得留下本案啟動之 ex-sbom
        let left = [...exPids()].filter((p) => !pids0.has(p))
        assert.strict.deepEqual(left, [], `殘留 ex-sbom PID:${left}`)
    })

    after(function() {
        fs.rmSync(root, { recursive: true, force: true })
    })

    it('呼叫端已設 PORT、工作目錄已有同名檔時皆不受影響,副本寫在專用子夾且結束後刪除', async function() {
        let caller = path.join(root, 'caller')
        let sentinel = path.join(caller, 'vuln.spdx.json') //與上傳檔名相同:舊行為會覆寫或刪除之
        fs.mkdirSync(caller, { recursive: true })
        fs.writeFileSync(sentinel, 'SENTINEL')
        let mtime0 = fs.statSync(sentinel).mtimeMs
        let cwd0 = process.cwd()
        let port0 = process.env.PORT
        let r
        process.chdir(caller)
        process.env.PORT = '9'
        try {
            r = await captureExSbom(exe, vuln, pics, quiet, { workRoot: work })
        }
        finally {
            process.chdir(cwd0)
            if (port0 === undefined) delete process.env.PORT
            else process.env.PORT = port0
        }
        //呼叫端 cwd 之同名檔未被覆寫或刪除,且未新增任何檔案
        assert.strict.strictEqual(fs.readFileSync(sentinel, 'utf8'), 'SENTINEL')
        assert.strict.strictEqual(fs.statSync(sentinel).mtimeMs, mtime0)
        assert.strict.deepEqual(fs.readdirSync(caller), ['vuln.spdx.json'])
        //ex-sbom 實際讀取之副本位於本次專用子夾內;結束後子夾與空的根皆已刪
        assert.strict.ok(r.scannedPath.toLowerCase().startsWith(work.toLowerCase() + path.sep), r.scannedPath)
        assert.strict.ok(!fs.existsSync(work))
        //呼叫端 PORT=9 不影響:改用自動選定之埠
        assert.strict.ok(r.port >= 18080 && r.port <= 18180, String(r.port))
        assert.strict.ok(names(r).includes('semver@7.0.0'), names(r).join(','))
    })

    it('只綁 127.0.0.1 之服務占用選定之埠(未出現在選埠快照)時,不連到它並改用他埠', async function() {
        let hits = []
        let fake = http.createServer((req, res) => {
            hits.push(req.url)
            res.end('<html><head><title>ex-sbom</title></head></html>') //冒用標題
        })
        let base = freeBase(18100)
        await new Promise((resolve) => fake.listen(base, '127.0.0.1', resolve))
        let r
        try {
            //快照注入為空:迫使第一次選到假服務之埠,只能靠「監聽 PID 恰為本子程序」擋下
            r = await captureExSbom(exe, vuln, pics, quiet, { workRoot: work, snapshot: () => new Map(), first: base, last: base + 20 })
        }
        finally {
            await new Promise((resolve) => fake.close(resolve))
        }
        assert.strict.notStrictEqual(r.port, base)
        assert.strict.deepEqual(hits.filter((u) => u !== '/'), [], `假服務收到:${hits}`)
        assert.strict.ok(names(r).includes('semver@7.0.0'), names(r).join(','))
    })

    it('兩個同時執行且選到同一埠時,輸者換埠,兩者結果各自正確', async function() {
        let base = freeBase(18120)
        let opt = (w) => ({ workRoot: path.join(root, w), snapshot: () => new Map(), first: base, last: base + 20 })
        let [a, b] = await Promise.all([
            captureExSbom(exe, vuln, path.join(root, 'pics-a'), quiet, opt('work-a')),
            captureExSbom(exe, clean, path.join(root, 'pics-b'), quiet, opt('work-b')),
        ])
        assert.strict.notStrictEqual(a.port, b.port)
        assert.strict.ok([a.port, b.port].includes(base))
        assert.strict.ok(names(a).includes('semver@7.0.0'), names(a).join(','))
        assert.strict.deepEqual(names(b), [])
    })

    it('清除前次殘留之工作子夾:只清建立者已不存在且名稱相符者,被占用者略過並照常完成', async function() {
        let dead = 4000000
        while ((() => {
            try {
                process.kill(dead, 0)
                return true
            }
            catch {
                return false
            }
        })()) dead += 4
        let stale = path.join(work, `${dead}-abcdef`)
        let locked = path.join(work, `${dead}-ghijkl`)
        let foreign = path.join(work, 'keep-me')
        for (let d of [stale, locked, foreign]) {
            fs.mkdirSync(d, { recursive: true })
            fs.writeFileSync(path.join(d, 'x.txt'), 'x')
        }
        //Windows 下行程之工作目錄無法刪除:以子行程停在其內模擬被占用
        let holder = spawn(process.execPath, ['-e', 'setTimeout(()=>{},120000)'], { cwd: locked, stdio: 'ignore' })
        let logs = []
        let r
        try {
            r = await captureExSbom(exe, clean, pics, (m) => logs.push(m), { workRoot: work })
        }
        finally {
            holder.kill()
            await new Promise((resolve) => holder.exitCode !== null ? resolve() : holder.once('exit', resolve))
        }
        assert.strict.deepEqual(names(r), [])
        assert.strict.ok(!fs.existsSync(stale))
        assert.strict.ok(fs.existsSync(locked))
        assert.strict.ok(logs.some((m) => m.includes('無法清除前次殘留之工作子夾') && m.includes(locked)), logs.join('\n'))
        assert.strict.ok(fs.existsSync(path.join(foreign, 'x.txt')))
    })

    it('就緒後 ex-sbom 結束時立即中止,不以殘缺結果交付', async function() {
        let t0 = Date.now()
        await assert.rejects(captureExSbom(exe, vuln, pics, quiet, { workRoot: work, onReady: (ex) => ex.child.kill() }), /意外結束/)
        assert.strict.ok(Date.now() - t0 < 60000)
        assert.strict.ok(!fs.existsSync(work))
    })

    it('候選埠全被占用時不啟動即拋錯,且不刪除上次之截圖', async function() {
        let busy = new Map()
        for (let p = 18080; p <= 18180; p++) busy.set(p, new Set([4]))
        fs.mkdirSync(pics, { recursive: true })
        fs.writeFileSync(path.join(pics, 'topology-overview.png'), 'old')
        await assert.rejects(captureExSbom(exe, vuln, pics, quiet, { workRoot: work, snapshot: () => busy }), /無可用之埠/)
        assert.strict.ok(!fs.existsSync(work))
        assert.strict.strictEqual(fs.readFileSync(path.join(pics, 'topology-overview.png'), 'utf8'), 'old')
    })

    it('執行檔無法啟動時,逐次換埠後以含執行檔與工作目錄之訊息拋錯', async function() {
        let missing = path.join(root, 'no-such', 'ex-sbom.exe')
        await assert.rejects(captureExSbom(missing, vuln, pics, quiet, { workRoot: work }), (err) => {
            assert.strict.match(err.message, /連續 5 次啟動失敗/)
            assert.strict.ok(err.message.includes('無法啟動') && err.message.includes(missing), err.message)
            return true
        })
        assert.strict.ok(!fs.existsSync(work))
    })

})
