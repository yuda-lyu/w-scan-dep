import fs from 'fs'
import path from 'path'
import http from 'http'
import assert from 'assert'
import { spawn } from 'child_process'
import { makeRelease, makeFakePkg } from './tools/fakeBins.mjs'
import { calcBinBudgetMs, BIN_STALL_MS } from './tools/binsAcquire.mjs'


//規格: 外部執行檔之存放下載校驗與離線(制式規格) §6 E5、§8 T9(跨程序只下載一次); 規則帳本 R-BIN-ENSURE-01 規則 10
//mocha --parallel 之各worker為不同行程, 空快取下多個行程同時取得同一批外部執行檔時, 只可下載一次(wsemi 1.9.75起fsEnsureBins之跨程序鎖), 他方等候後讀快取。
//本案經本套件之src/ensureBins.mjs(原樣複製於假套件根, 實際載入node_modules之wsemi/src/fsEnsureBins.mjs), 以多個真行程與本機HTTP伺服器(扮廠商發布, 計各資產之被請求次數)驗證,
//wsemi低於1.9.75或測試經內嵌舊版wsemi之dist取得時, 各行程各自下載而本案轉紅(全綠不證明只下載一次, 故以伺服器端之請求次數為準)。
//同步以事件而非延時: 伺服器扣住所有資產回應, 直到(N-1)個行程回報'lock-wait'(開始等候他方持有之鎖)才放行; 鎖不存在時永遠等不到事件, 逾上限(GATE_CAP_MS)才放行並使斷言轉紅
describe(`ensureBins across processes (only one download per tool)`, function() {
    this.timeout(180000)

    let N = 4 //同時取得之行程數
    let GATE_CAP_MS = 60000 //放行上限(僅在無鎖而等不到事件時才用到, 防止測試懸置; 有鎖時於收到事件即放行, 不影響耗時, 取大以免高負載下行程晚到而誤紅)
    let TOTAL_MS = 450000 //傳給子行程之 totalMs(非預設值: 鎖檔之持鎖上限 limitMs 須隨之改變, 對照 binsAcquire.mjs 之預算算式)
    let fdt = path.resolve('./test/_tmp/ensureBinsLock')
    let fdWork = path.join(fdt, 'work')
    let fdPkg = path.join(fdt, 'pkg')
    let fpChild = path.resolve('./test/tools/ensureBinsLockChild.mjs')
    let TRUNK = '/yuda-lyu/w-scan-dep/master/bin/manifest.json'
    let names = ['syft.exe', 'grype.exe', 'osv-scanner.exe', 'ex-sbom.exe']

    let A = null
    let srv = null
    let port = 0
    let assetHits = {} //資產網址路徑 → 被請求次數
    let limits = new Set() //各資產請求到達時, 快取夾內所有鎖檔 owner.json 之 limitMs(持鎖上限, 即 wsemi 之 lockBudget)之聯集(等候者於持有者釋放鎖之前即可命中快取而進入下一檔, 瞬間可同時有兩個鎖, 故不逐檔對應, 只比對值集合)
    let curCache = '' //本案使用之快取資料夾
    let gate = null //{ open(by), by, promise }
    let seq = 0

    let mkGate = () => {
        let g = { by: '', waiters: 0 }
        g.promise = new Promise((resolve) => {
            g.open = (by) => {
                if (g.by === '') {
                    g.by = by
                    resolve()
                }
            }
        })
        g.timer = setTimeout(() => g.open('cap'), GATE_CAP_MS)
        return g
    }

    before(async function() {
        fs.rmSync(fdt, { recursive: true, force: true })
        fs.mkdirSync(fdWork, { recursive: true })
        A = makeRelease(fdWork, { 'syft': '9.9.9', 'grype': '8.8.8', 'osv-scanner': '7.7.7', 'ex-sbom': '0.2.0' })
        makeFakePkg(fdPkg, A.manifest)
        srv = http.createServer(async (req, res) => {
            if (req.url === TRUNK) {
                let b = Buffer.from(JSON.stringify(A.manifest))
                res.writeHead(200, { 'content-length': String(b.length) })
                res.end(b)
                return
            }
            let b = A.files[req.url]
            if (b === undefined) {
                res.writeHead(404, { 'content-length': '0' })
                res.end()
                return
            }
            assetHits[req.url] = (assetHits[req.url] || 0) + 1
            //請求於持鎖期間發出: 此刻快取夾內只有持有者之一個鎖(各行程依清單順序逐檔取得), 讀其 limitMs
            let locks = fs.existsSync(curCache) ? fs.readdirSync(curCache).filter((v) => /^\.lock-[0-9a-f]{32}$/.test(v)) : [] //鎖為 .lock-<32 碼十六進位鍵>; 他行程建鎖時之暫存夾(.lock-<鍵>.new-…)不算
            for (let l of locks) {
                try {
                    limits.add(JSON.parse(fs.readFileSync(path.join(curCache, l, 'owner.json'), 'utf8')).limitMs)
                }
                catch (err) {
                    //該鎖剛被釋放: 略過(本請求之持有者之鎖必在, 其值已於各請求到達時記入)
                }
            }
            await gate.promise //扣住資產回應直到放行
            res.writeHead(200, { 'content-length': String(b.length) })
            res.end(b)
        })
        await new Promise((resolve, reject) => {
            srv.once('error', reject)
            srv.listen(0, '127.0.0.1', resolve) //作業系統配發埠
        })
        port = srv.address().port
    })

    after(async function() {
        if (gate) {
            clearTimeout(gate.timer)
            gate.open('after')
        }
        if (srv) {
            await new Promise((resolve) => srv.close(resolve))
        }
        fs.rmSync(fdt, { recursive: true, force: true, maxRetries: 5, retryDelay: 200 })
    })

    beforeEach(function() {
        assetHits = {}
        limits = new Set()
        gate = mkGate()
    })

    afterEach(function() {
        clearTimeout(gate.timer)
        gate.open('afterEach')
    })

    //啟動一個子行程取得全部工具; 回傳 { events, result, code }
    let runChild = (cacheDir) => {
        return new Promise((resolve, reject) => {
            let env = { ...process.env }
            for (let k of Object.keys(env)) {
                if (k.startsWith('W_BIN_')) {
                    delete env[k]
                }
            }
            let child = spawn(process.execPath, [fpChild, path.join(fdPkg, 'src/ensureBins.mjs'), cacheDir, String(port), String(TOTAL_MS)], { env, windowsHide: true, stdio: ['ignore', 'pipe', 'pipe'] })
            child.stdout.setEncoding('utf8') //多位元組字元(路徑含中文)不被 chunk 切斷
            child.stderr.setEncoding('utf8')
            let events = []
            let result = null
            let buf = ''
            let err = ''
            child.stdout.on('data', (d) => {
                buf += d
                let lines = buf.split('\n')
                buf = lines.pop()
                for (let s of lines) {
                    if (s.trim() === '') {
                        continue
                    }
                    let o = JSON.parse(s)
                    if (o.ev) {
                        events.push({ pid: child.pid, ...o.ev })
                        //(N-1)個行程回報開始等候syft.exe之鎖 ⇒ 放行
                        if (o.ev.type === 'lock-wait' && o.ev.phase === 'start' && o.ev.name === 'syft.exe') {
                            gate.waiters++
                            if (gate.waiters >= N - 1) {
                                gate.open('events')
                            }
                        }
                    }
                    else {
                        result = o
                    }
                }
            })
            child.stderr.on('data', (d) => {
                err += d
            })
            child.once('error', reject)
            child.once('close', (code) => {
                resolve({ events, result, code, err })
            })
        })
    }

    let assetPaths = () => Object.keys(A.files)

    it(`should download each tool exactly once when ${N} processes get them into the same empty cache at the same time, the others wait for the lock and read the cache (E5, T9)`, async function() {
        let cacheDir = path.join(fdt, `cache-${++seq}`)
        curCache = cacheDir
        let rs = await Promise.all(Array.from({ length: N }, () => runChild(cacheDir)))

        //各行程皆成功, 取得同一組路徑(快取內之最終檔, 位元組即最終檔)
        for (let r of rs) {
            assert.strict.equal(r.code, 0, r.err)
            assert.strict.ok(r.result && r.result.error === undefined, JSON.stringify(r.result))
        }
        let want = rs[0].result.paths
        assert.strict.deepStrictEqual(Object.keys(want).sort(), [...names].sort())
        for (let r of rs) {
            assert.strict.deepStrictEqual(r.result.paths, want)
        }
        for (let n of names) {
            assert.strict.equal(fs.readFileSync(want[n]).equals(A.finals[n]), true, n)
        }

        //伺服器端: 每個資產只被請求1次(鎖不存在時為N次)
        assert.strict.deepStrictEqual(assetPaths().map((p) => `${p}:${assetHits[p] || 0}`), assetPaths().map((p) => `${p}:1`))

        //持鎖上限即 binsAcquire.mjs 之預算算式(去掉取主幹清單之 stallMs): 持有者鎖檔 owner.json 之 limitMs 為 wsemi 實際用之 lockBudget(壓縮檔與直接檔各一形狀、totalMs 非預設值)
        //(各檔之持鎖者之鎖於其資產請求到達時必在, 故值集合 = 各檔預期值之集合: 壓縮檔 2×totalMs+5000+60000、直接檔 totalMs+60000; 不逐檔對應, 見 limits 之說明)
        let wantLimits = [...new Set(A.manifest.files.map((f) => calcBinBudgetMs({ files: [f] }, { totalMs: TOTAL_MS }) - BIN_STALL_MS))].sort((a, b) => a - b)
        assert.strict.deepStrictEqual(wantLimits, [TOTAL_MS + 60000, 2 * TOTAL_MS + 5000 + 60000]) //前提: 兩種形狀之值相異(才有鑑別力)
        assert.strict.deepStrictEqual([...limits].sort((a, b) => a - b), wantLimits, '鎖檔 limitMs 之集合')

        //同步是由事件放行而非逾時放行: 至少(N-1)個行程曾等候syft.exe之鎖
        assert.strict.equal(gate.by, 'events', `放行方式 ${gate.by}(cap 表示未收到足夠之 lock-wait 事件, 即鎖未生效)`)
        let ev = rs.flatMap((r) => r.events)
        assert.strict.ok(ev.filter((v) => v.type === 'lock-wait' && v.phase === 'start' && v.name === 'syft.exe').length >= N - 1)

        //事件端: 各工具之download事件恰1次、他方等候後'lock-wait'結束且命中快取、無lock-skip與逾時
        for (let n of names) {
            assert.strict.equal(ev.filter((v) => v.type === 'download' && v.name === n).length, 1, `${n} download events`)
        }
        assert.strict.equal(ev.filter((v) => v.type === 'lock-skip').length, 0)
        assert.strict.equal(ev.filter((v) => v.type === 'lock-wait' && v.phase === 'timeout').length, 0)
        assert.strict.ok(ev.filter((v) => v.type === 'lock-wait' && v.phase === 'end' && v.hit === true).length >= 1)

        //全部釋放: 快取夾內不留鎖與暫存夾(.lock-*、.work-*)
        let left = fs.readdirSync(cacheDir).filter((v) => v.startsWith('.'))
        assert.strict.deepStrictEqual(left, [])

        //快取已備妥後再取一次(兩個行程同時): 不再下載
        let hits0 = JSON.stringify(assetHits)
        let rs2 = await Promise.all([runChild(cacheDir), runChild(cacheDir)])
        for (let r of rs2) {
            assert.strict.equal(r.code, 0, r.err)
            assert.strict.deepStrictEqual(r.result.paths, want)
            assert.strict.equal(r.events.filter((v) => v.type === 'download').length, 0)
        }
        assert.strict.equal(JSON.stringify(assetHits), hits0)
    })

})
