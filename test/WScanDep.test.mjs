import assert from 'assert'
import fs from 'fs'
import path from 'path'
import http from 'http'
import { spawnSync } from 'child_process'
import wsd from '../src/WScanDep.mjs'
import ensureBins from '../src/ensureBins.mjs'
import { captureExSbom, listeningPorts, excludedPorts, pickPort } from '../src/exsbom.mjs'
import { holdDir } from './tools/holdDir.mjs'


//完整掃描(連網): 經 ensureBins 取得掃描工具(首次自 GitHub 下載並校驗, 存於 bin-cache/ 或 W_BIN_CACHE),
//另需 npm registry 與 grype/osv 漏洞資料庫。ex-sbom 自快取路徑啟動, Windows 防火牆對新路徑會詢問一次(選「取消」即可)。
//無網路之 ensureBins 行為見 api-ensureBins.test.mjs、api-wsdEntry.test.mjs(假廠商檔與本機伺服器)
describe('WScanDep', function() {
    this.timeout(1800000) //首次執行須下載掃描工具與npm install,耗時較久

    let fpIn = './test/prj/package.json'
    let fdOut = './test/output'
    let ks = ['date', 'source', 'outputDir', 'scope', 'tools', 'osv', 'grype', 'exsbom', 'updateList']

    it('test', async function() {
        let r = await wsd(fpIn, fdOut)
        assert.strict.strictEqual(r, 'ok')

        //result.json之欄位
        let j = JSON.parse(fs.readFileSync(`${fdOut}/result.json`, 'utf8'))
        assert.strict.deepEqual(Object.keys(j), ks)

        //掃描範圍只算 dependencies(Gitea #27): result.json 之範圍欄位、result.md 之說明句; 隔離安裝不含 devDependencies(test/prj 之 package.json 無 devDependencies, 此處只驗欄位與說明)
        assert.strict.strictEqual(j.scope, 'dependencies')
        assert.strict.ok(fs.readFileSync(`${fdOut}/result.md`, 'utf8').includes('- 掃描範圍：僅 dependencies（正式相依樹，含其所附之執行檔）'))

        //各報告檔案存在
        assert.strict.ok(fs.existsSync(`${fdOut}/result.md`))
        assert.strict.ok(fs.existsSync(`${fdOut}/待更新套件.md`))
        assert.strict.ok(fs.existsSync(`${fdOut}/pics`))

        //截圖欄位(Gitea #24):ex-sbom 之失敗不再使 WScanDep reject,故須斷言截圖成功;含成敗、原因與上傳前剔除之循環關係
        assert.strict.deepEqual(Object.keys(j.exsbom), ['ok', 'error', 'overview', 'components', 'levelSummary', 'removedRelationships'])
        assert.strict.strictEqual(j.exsbom.ok, true, j.exsbom.error)
        assert.strict.strictEqual(j.exsbom.error, null)
        assert.strict.ok(fs.existsSync(path.join(fdOut, j.exsbom.overview)), j.exsbom.overview)
        assert.strict.ok(Array.isArray(j.exsbom.removedRelationships))

        //result.json 記各工具之版本標籤(取自清單網址, 由 ensureBins 取得之檔推得)
        assert.strict.deepEqual(Object.keys(j.tools), ['syft', 'grype', 'osv-scanner', 'ex-sbom'])
        for (let v of Object.values(j.tools)) {
            assert.strict.match(v, /^v\d+\.\d+\.\d+$/)
        }
    })

    //第三參數(原 opt.fdTools)已移除:明確拒絕, 且於任何寫入前
    it('第三參數(原 opt.fdTools)已移除:拒絕,且不建立 fdOut', async function() {
        let out = './test/_tmp/WScanDep-guard/out'
        await assert.rejects(wsd(fpIn, out, { fdTools: `${out}/test/tools` }), /不接受第三參數/)
        assert.strict.ok(!fs.existsSync(out))
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
    let cycle = path.resolve('./test/fixtures/cycle.spdx.json') //semver 7.0.0 + es-abstract ⇄ string.prototype.trim(has-symbols 自入度 0 走到循環)
    let quiet = () => {}
    let exe = null

    //ex-sbom 取自 ensureBins 之快取(離線, 須已校驗; 完整掃描過一次即有); 否則沿用舊版遺留之 test/output/tools(該路徑已有 Windows 防火牆規則, 不以新路徑啟動)
    let findExe = async () => {
        try {
            return (await ensureBins({ offline: true, names: 'ex-sbom.exe' }))['ex-sbom.exe']
        }
        catch { /* 快取尚無 */ }
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

    before(async function() {
        exe = await findExe()
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
        //Windows 下行程之工作目錄無法刪除:以子行程停在其內模擬被占用。待其確被持有才往下(不以延時同步, 見 test/tools/holdDir.mjs;
        //清除邏輯本身之確定性測試見 unit-exsbom.test.mjs〈exsbom cleanStaleWork〉, 本案另驗經 captureExSbom 仍照常完成)
        let holder = await holdDir(locked)
        let logs = []
        let r
        try {
            r = await captureExSbom(exe, clean, pics, (m) => logs.push(m), { workRoot: work })
        }
        finally {
            await holder.stop()
        }
        assert.strict.deepEqual(names(r), [])
        assert.strict.ok(!fs.existsSync(stale))
        assert.strict.ok(fs.existsSync(locked))
        assert.strict.ok(logs.some((m) => m.includes('無法清除前次殘留之工作子夾') && m.includes(locked)), logs.join('\n'))
        assert.strict.ok(fs.existsSync(path.join(foreign, 'x.txt')))
    })

    it('就緒後 ex-sbom 結束時立即中止,不以殘缺結果交付', async function() {
        let t0 = Date.now()
        await assert.rejects(captureExSbom(exe, vuln, pics, quiet, { workRoot: work, onReady: (ex) => ex.child.kill() }), /意外結束\((離開碼|訊號) [^)]+\),本次截圖作廢/)
        assert.strict.ok(Date.now() - t0 < 60000)
        assert.strict.ok(!fs.existsSync(work))
    })

    //建議w-scan-dep修正.md(Gitea #24)一建議 1(主控裁定 2):ex-sbom v0.2.0 對相依循環無限遞迴;上傳前剔除構成循環之關係,使含循環者能產出截圖,並回傳剔除者
    it('含相依循環之 SBOM:上傳前剔除構成循環之關係,ex-sbom 不再意外結束而產出截圖,結果列出剔除之關係,原檔不動', async function() {
        let text0 = fs.readFileSync(cycle, 'utf8')
        let r = await captureExSbom(exe, cycle, pics, quiet, { workRoot: work })
        assert.strict.ok(fs.existsSync(r.overviewShot), r.overviewShot)
        assert.strict.ok(names(r).includes('semver@7.0.0'), names(r).join(','))
        assert.strict.ok(r.summary.length >= 1) //拓撲各層摘要(ex-sbom 完成分析)
        assert.strict.deepEqual(r.removedRelationships.map((x) => `${x.from} ${x.relationshipType} ${x.to}`), ['string.prototype.trim@1.2.11 DEPENDENCY_OF es-abstract@1.24.2'])
        assert.strict.strictEqual(fs.readFileSync(cycle, 'utf8'), text0)
        assert.strict.ok(!fs.existsSync(work))
    })

    it('SBOM 無法解析時於啟動 ex-sbom 前即拋錯(不啟動、不刪上次之截圖、工作子夾已刪)', async function() {
        let bad = path.join(root, 'bad', 'syft.spdx.json')
        fs.mkdirSync(path.dirname(bad), { recursive: true })
        fs.writeFileSync(bad, '{ not json')
        fs.mkdirSync(pics, { recursive: true })
        fs.writeFileSync(path.join(pics, 'topology-overview.png'), 'old')
        let logs = []
        await assert.rejects(captureExSbom(exe, bad, pics, (m) => logs.push(m), { workRoot: work }), /無法讀取或解析 SBOM/)
        assert.strict.ok(!logs.some((m) => m.includes('啟動服務')), logs.join('\n'))
        assert.strict.strictEqual(fs.readFileSync(path.join(pics, 'topology-overview.png'), 'utf8'), 'old')
        assert.strict.ok(!fs.existsSync(work))
    })

    it('無循環之 SBOM 不剔除任何關係(removedRelationships 為空陣列)', async function() {
        let r = await captureExSbom(exe, clean, pics, quiet, { workRoot: work })
        assert.strict.deepEqual(r.removedRelationships, [])
    })

    //建議w-scan-dep修正.md(Gitea #24)二(主控裁定 4):截圖期間意外結束時,錯誤訊息附 ex-sbom.log 之 fatal error 及其後數行(長度設上限)。
    //以不剔除循環(opt.breakCycles: false)重現 ex-sbom 真實之 stack overflow
    it('ex-sbom 於截圖期間因 stack overflow 結束:錯誤訊息含離開碼與 ex-sbom.log 之結束原因,長度有上限,工作子夾仍刪除', async function() {
        let err = await captureExSbom(exe, cycle, pics, quiet, { workRoot: work, breakCycles: false }).then(() => null, (e) => e)
        assert.strict.ok(err instanceof Error, '應以錯誤結束')
        assert.strict.match(err.message, /於截圖期間意外結束\(離開碼 2\),本次截圖作廢;ex-sbom\.log 摘錄:\n/)
        assert.strict.ok(err.message.includes('fatal error: stack overflow'), err.message)
        assert.strict.ok(err.message.includes('getSpdxDependencyDepthMap'), err.message)
        assert.strict.ok(err.message.length < 2000, String(err.message.length))
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
