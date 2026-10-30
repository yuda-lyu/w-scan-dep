import assert from 'assert'
import fs from 'fs'
import net from 'net'
import path from 'path'
import cp from 'child_process'
import { pathToFileURL } from 'url'
import { syncBuiltinESMExports } from 'module'
import { portListeners, ownsPort, startExSbom } from '../src/exsbom.mjs'


//埠之監聽者之身分確認(2026-10-30, Gitea #24 之 TCP 表異常)之真實環境案: 真實之 netstat、Get-NetTCPConnection 與真實之監聽行程, 不以替身代替系統查詢
//(替身案見 unit-exsbom.test.mjs〈exsbom portListeners 與 ownsPort〉)。Windows 11 26300(KB5127936)之系統 TCP 狀態值錯誤,
//netstat 會整列漏列新起之監聽(本機實測新起之監聽約半數不在 netstat 輸出中), 修前以 netstat 全表判定之 ownsPort 因而隨機誤判。
//埠固定且 ≥ 8000(不隨機): 本檔 8991~8996, 他檔已用 8985、8987~8989(hangRegistry)、18080~18180(ex-sbom)。只綁本機迴圈位址, 不觸發防火牆詢問
describe('exsbom 埠之監聽者之身分確認(真實環境)', function() {
    this.timeout(180000)

    let root = path.resolve('./test/_tmp/exsbomPort')
    let holdPort = path.resolve('./test/tools/holdPort.mjs')
    let fakeExSbom = path.resolve('./test/tools/fakeExSbom.mjs') //扮 ex-sbom: 讀 PORT, 只綁 127.0.0.1, 標題為 ex-sbom
    let procs = []
    let servers = []

    //起一個占用 port 之子程序, 待其印出 listening(事件)才回傳
    let hold = async (port, host = '127.0.0.1') => {
        let child = cp.spawn(process.execPath, [holdPort, String(port), host], { windowsHide: true, stdio: ['ignore', 'pipe', 'pipe'] })
        procs.push(child)
        let err = ''
        child.stderr.on('data', (d) => {
            err += d
        })
        await new Promise((resolve, reject) => {
            child.stdout.once('data', resolve)
            child.once('exit', (code) => reject(new Error(`holdPort exited ${code}: ${err}`)))
        })
        return child
    }
    let exited = (child) => (child.exitCode !== null || child.signalCode !== null ? Promise.resolve() : new Promise((resolve) => child.once('exit', resolve)))
    let stop = async (child) => {
        child.kill()
        await exited(child)
    }
    let refused = (port) => new Promise((resolve) => {
        let s = net.connect(port, '127.0.0.1')
        s.once('connect', () => {
            s.destroy()
            resolve(false)
        })
        s.once('error', () => resolve(true))
    })

    beforeEach(function() {
        fs.rmSync(root, { recursive: true, force: true })
        fs.mkdirSync(root, { recursive: true })
    })

    afterEach(async function() {
        for (let c of procs.splice(0)) {
            await stop(c)
        }
        for (let s of servers.splice(0)) {
            await new Promise((resolve) => s.close(resolve))
        }
    })

    after(function() {
        fs.rmSync(root, { recursive: true, force: true, maxRetries: 5, retryDelay: 200 })
    })

    //規格: 該埠之監聽 PID 集合恰為 {本次子程序} 才算身分確認; 結束後 → 查無(空集合, 非失敗)
    it('真實監聽之子程序:認得其 PID(集合恰為 {PID});其結束後查得空集合而不 ok', async function() {
        let child = await hold(8991)
        let r = ownsPort(8991, child.pid)
        assert.strict.strictEqual(r.ok, true, `set=${[...r.set]}`)
        assert.strict.deepEqual([...r.set], [child.pid])
        assert.strict.deepEqual(portListeners(8991), [child.pid])
        await stop(child)
        let g = ownsPort(8991, child.pid)
        assert.strict.strictEqual(g.ok, false)
        assert.strict.strictEqual(g.set.size, 0)
    })

    //規格: 同埠並存之他服務(各綁不同之本機迴圈位址)須被看見 → 不 ok(修前漏列任一者即誤判為「恰為本次」或「已非本次」)
    it('同埠並存之他監聽者(本行程綁 127.0.0.2,子程序綁 127.0.0.1):集合含兩者,不 ok', async function() {
        let child = await hold(8992, '127.0.0.1')
        let own = net.createServer((s) => s.destroy())
        servers.push(own)
        await new Promise((resolve, reject) => {
            own.once('error', reject)
            own.listen(8992, '127.0.0.2', resolve)
        })
        let r = ownsPort(8992, child.pid)
        assert.strict.strictEqual(r.ok, false)
        assert.strict.deepEqual([...r.set].sort((a, b) => a - b), [child.pid, process.pid].sort((a, b) => a - b))
        //以本行程為本次者同理不 ok(子程序亦為他監聽者)
        assert.strict.strictEqual(ownsPort(8992, process.pid).ok, false)
    })

    //規格: 「已確認無人」不是失敗: 空集合、不拋錯
    it('無人監聽之埠:空集合、不 ok、不拋錯', function() {
        assert.strict.deepEqual(portListeners(8993), [])
        let r = ownsPort(8993, process.pid)
        assert.strict.strictEqual(r.ok, false)
        assert.strict.strictEqual(r.set.size, 0)
    })

    //規格: startExSbom 以「該埠之監聽 PID 恰為本次子程序」為就緒條件。以 node 之 --import 預載 fakeExSbom 扮 ex-sbom 執行檔(自 process.env 之 NODE_OPTIONS 繼承)
    //startExSbom 啟動之子程序一律記入 procs(攔截 cp.spawn,須 syncBuiltinESMExports 才對以具名匯入取用 spawn 之 exsbom.mjs 生效),
    //缺陷時(例如不結束本次子程序)由 afterEach 結束之, 不留殘留而使 mocha 無法結束; 結束後還原並再同步一次
    let withFake = async (fn) => {
        let bakEnv = process.env.NODE_OPTIONS
        let bakSpawn = cp.spawn
        process.env.NODE_OPTIONS = `--import=${pathToFileURL(fakeExSbom).href}`
        cp.spawn = (...a) => {
            let c = bakSpawn(...a)
            procs.push(c)
            return c
        }
        syncBuiltinESMExports()
        try {
            return await fn()
        }
        finally {
            cp.spawn = bakSpawn
            syncBuiltinESMExports()
            if (bakEnv === undefined) delete process.env.NODE_OPTIONS
            else process.env.NODE_OPTIONS = bakEnv
        }
    }

    it('startExSbom:新起之監聽經真實查詢確認為本次子程序後就緒(修前隨系統 TCP 表之漏列而逾時換埠)', async function() {
        let ex = await withFake(() => startExSbom(process.execPath, root, () => {}, { snapshot: () => new Map(), first: 8994, last: 8994 }))
        assert.strict.strictEqual(ex.port, 8994)
        assert.strict.deepEqual([...ownsPort(8994, ex.child.pid).set], [ex.child.pid])
        assert.strict.strictEqual(ownsPort(8994, ex.child.pid).ok, true)
    })

    //規格(維持「查詢失敗即拋錯」): 查詢埠之監聽者失敗時 startExSbom 拋出、不當成「沒人占用」而繼續,且不留下本次子程序
    //在真實之 child_process 接縫注入失敗(wsemi 之預設執行函數經 cp.spawnSync): netstat.exe 與 powershell.exe 皆無法執行
    it('startExSbom:查詢埠之監聽者失敗即拋錯並結束本次子程序(不留下占埠之子程序)', async function() {
        let bak = cp.spawnSync
        let hits = []
        cp.spawnSync = (cmd, args, opt) => {
            if (/(netstat|powershell)\.exe$/i.test(String(cmd))) {
                hits.push(path.basename(String(cmd)).toLowerCase())
                let e = new Error(`spawnSync ${cmd} ENOENT`)
                e.code = 'ENOENT'
                return { status: null, stdout: '', stderr: '', error: e }
            }
            return bak(cmd, args, opt)
        }
        let ex = null
        let err = null
        try {
            ex = await withFake(() => startExSbom(process.execPath, root, () => {}, { snapshot: () => new Map(), first: 8995, last: 8995 }))
        }
        catch (e) {
            err = e
        }
        finally {
            cp.spawnSync = bak
            syncBuiltinESMExports() //exsbom.mjs 以具名匯入取用 spawnSync: 還原後須再同步, 免後續測試取得攔截版
        }
        assert.strict.ok(ex === null, 'startExSbom 不應回傳(查詢失敗須拋錯)')
        assert.strict.ok(err, 'startExSbom 應因查詢失敗而拋錯, 而非當成沒人占用繼續')
        assert.strict.match(err.message, /^查詢埠 8995 之監聽者失敗:.*netstat error\[ENOENT\].*powershell error\[ENOENT\]/)
        assert.strict.deepEqual([...new Set(hits)].sort(), ['netstat.exe', 'powershell.exe']) //兩個資料來源皆被查過(useBoth)
        assert.strict.strictEqual(await refused(8995), true, '拋錯後 8995 不應仍有占埠之子程序')
    })

})
