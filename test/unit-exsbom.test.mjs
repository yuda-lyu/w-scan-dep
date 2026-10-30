import assert from 'assert'
import fs from 'fs'
import path from 'path'
import { parseNetstat, parseExcluded, pickPort, classifyExSbomLog, breakDependencyCycles, exitReasonFromLog, cleanStaleWork, portListeners, ownsPort } from '../src/exsbom.mjs'
import { holdDir } from './tools/holdDir.mjs'
import { row, ns, ps, ok, err, fakeExec } from './tools/portExecKit.mjs'


//ex-sbom 服務埠自動選用與身分確認之純函式(2026-10-03 修正,見 建議w-scan-dep修正.md)
describe('exsbom 選埠與 log 分類', function() {

    let netstat = [
        '',
        '作用中的連線',
        '',
        '  協定   本機位址               外部位址               狀態           PID',
        '  TCP    0.0.0.0:135            0.0.0.0:0              LISTENING       1196',
        '  TCP    0.0.0.0:18080          0.0.0.0:0              LISTENING       5336',
        '  TCP    127.0.0.1:18090        0.0.0.0:0              LISTENING       14844',
        '  TCP    127.0.0.1:52000        127.0.0.1:18080        ESTABLISHED     9000',
        '  TCP    192.168.1.5:50001      20.1.2.3:443           TIME_WAIT       0',
        '  TCP    [::]:18080             [::]:0                 LISTENING       5336',
        '  TCP    [::]:18090             [::]:0                 接聽中          17072',
        '  UDP    0.0.0.0:5353           *:*                                    2000',
    ].join('\r\n')

    it('parseNetstat 只取 TCP 監聽列(含 IPv6、在地化狀態字),同埠多 PID 皆收', function() {
        let m = parseNetstat(netstat)
        assert.strict.deepEqual([...m.keys()].sort((a, b) => a - b), [135, 18080, 18090])
        assert.strict.deepEqual([...m.get(18080)], [5336])
        //只綁 127.0.0.1 之服務與 ex-sbom([::])同埠並存:兩個 PID 都要看得到
        assert.strict.deepEqual([...m.get(18090)].sort(), [14844, 17072])
        //連線中、TIME_WAIT 與 UDP 不算監聽
        assert.strict.ok(!m.has(52000) && !m.has(50001) && !m.has(5353))
    })

    //Windows 11 26300(KB5127936)之 TCP 狀態值錯誤:對外連線可被列為 LISTENING(外部位址非 0)。選埠之全表快照不可把它當監聽(方向安全之修正:不再以 LISTENING 為或條件)
    it('parseNetstat 不因狀態欄為 LISTENING 而收錄:外部位址非萬用位址者(對外連線反列 LISTENING)不算監聽', function() {
        let text = [
            row('TCP', '192.168.1.5:18085', '20.1.2.3:443', 'LISTENING', '9100'),
            row('TCP', '127.0.0.1:18086', '127.0.0.1:18087', 'LISTENING', '9101'),
            row('TCP', '[::1]:18088', '[::1]:52000', 'LISTENING', '9102'),
        ].join('\r\n')
        assert.strict.strictEqual(parseNetstat(text).size, 0, [...parseNetstat(text).keys()].join(','))
    })

    it('parseNetstat 狀態欄錯誤之真監聽(外部位址為萬用位址,如本機實測之 CLOSED、FIN_WAIT_1)仍收錄:選埠只會因而多迴避,方向安全', function() {
        let text = [
            row('TCP', '0.0.0.0:18090', '0.0.0.0:0', 'CLOSED', '4'),
            row('TCP', '0.0.0.0:18091', '0.0.0.0:0', 'FIN_WAIT_1', '1356'),
            row('TCP', '[::]:18092', '[::]:0', 'ESTABLISHED', '17072'),
        ].join('\r\n')
        let m = parseNetstat(text)
        assert.strict.deepEqual([...m.keys()].sort((a, b) => a - b), [18090, 18091, 18092])
        assert.strict.deepEqual([...m.get(18092)], [17072])
    })

    it('parseExcluded 解析系統保留埠段(含中文標頭與 * 標記)', function() {
        let text = [
            '',
            '通訊協定 tcp 連接埠排除範圍',
            '',
            '開始連接埠    結束連接埠',
            '----------    --------',
            '      5357        5357',
            '     50000       50059     *',
            '',
            '* - 管理的連接埠排除。',
        ].join('\r\n')
        assert.strict.deepEqual(parseExcluded(text), [[5357, 5357], [50000, 50059]])
    })

    it('pickPort 自起點依序取第一個未被監聽、非保留、未試過之埠;無則 null', function() {
        let busy = new Map([[18080, new Set([1])], [18082, new Set([2])]])
        assert.strict.strictEqual(pickPort(new Map(), [], 18080, 18180), 18080)
        assert.strict.strictEqual(pickPort(busy, [], 18080, 18180), 18081)
        assert.strict.strictEqual(pickPort(busy, [], 18080, 18180, new Set([18081])), 18083)
        assert.strict.strictEqual(pickPort(busy, [[18081, 18090]], 18080, 18180), 18091)
        assert.strict.strictEqual(pickPort(busy, [], 18080, 18080), null)
        assert.strict.strictEqual(pickPort(new Map(), [[18000, 18200]], 18080, 18180), null)
    })

    it('classifyExSbomLog:分析失敗為 fatal,不影響漏洞判定者為 warn,並取出副本實際路徑', function() {
        let ok = [
            '2026/10/03 12:46:55 INFO Scanned C:\\x\\exsbom-work\\123-abcdef\\syft.spdx.json file and found 33 packages',
            '2026/10/03 12:46:56 ERROR failed to get lev info error="no CVEs provided"',
            '2026/10/03 12:46:56 INFO SBOM created name=syft.spdx.json type=1',
        ].join('\n')
        let r = classifyExSbomLog(ok)
        assert.strict.deepEqual(r.fatal, [])
        assert.strict.deepEqual(r.warn, []) //無 CVE 時之 lev 錯誤屬正常
        assert.strict.strictEqual(r.scannedPath, 'C:\\x\\exsbom-work\\123-abcdef\\syft.spdx.json')

        let bad = [
            'ERROR failed to copy and create file error="open syft.spdx.json: Access is denied."',
            'ERROR failed to get scan result error="osv.dev unreachable"',
            'ERROR Failed to process SPDX SBOM error=x',
            'ERROR failed to get lev info error="dial tcp: timeout"',
            'ERROR failed to get scan result error="no packages found in scan"',
        ].join('\n')
        let b = classifyExSbomLog(bad)
        assert.strict.strictEqual(b.fatal.length, 3)
        assert.strict.strictEqual(b.warn.length, 2)
        assert.strict.strictEqual(b.scannedPath, '')
    })

})


//建議w-scan-dep修正.md(Gitea #24)一:ex-sbom v0.2.0 之 getSpdxDependencyDepthMap 對相依循環無限遞迴。
//其建圖(上游 spdx_sbom.go):每筆 relationships 為 spdxElementId → relatedSpdxElement 之邊、不看類型,略過 DOCUMENT/DocumentRoot-*/File-*;
//交給 ex-sbom 前須剔除構成循環之關係,使該圖無循環,並列出剔除者(主控裁定 2)
describe('exsbom breakDependencyCycles', function() {

    //獨立之循環判定(Kahn 拓撲排序,與被測之深度優先不同演算法),依 ex-sbom 之建圖
    let key = (id) => (id.startsWith('SPDXRef-') ? id.slice(8) : id)
    let gen = (k) => k === 'DOCUMENT' || k.startsWith('DocumentRoot-') || k.startsWith('File-')
    let hasCycle = (doc) => {
        let out = new Map()
        let indeg = new Map()
        let add = (k) => {
            if (!out.has(k)) {
                out.set(k, [])
                indeg.set(k, 0)
            }
        }
        for (let r of doc.relationships) {
            let a = key(r.spdxElementId)
            let b = key(r.relatedSpdxElement)
            if (gen(a) || gen(b)) continue
            add(a)
            add(b)
            out.get(a).push(b)
            indeg.set(b, indeg.get(b) + 1)
        }
        let q = [...indeg.keys()].filter((k) => indeg.get(k) === 0)
        let seen = 0
        while (q.length) {
            let k = q.pop()
            seen++
            for (let b of out.get(k)) {
                indeg.set(b, indeg.get(b) - 1)
                if (indeg.get(b) === 0) q.push(b)
            }
        }
        return seen < out.size
    }
    let pk = (name, version) => ({ name, versionInfo: version, SPDXID: `SPDXRef-Package-npm-${name}` })
    let dep = (a, b, t = 'DEPENDENCY_OF') => ({ spdxElementId: `SPDXRef-Package-npm-${a}`, relatedSpdxElement: `SPDXRef-Package-npm-${b}`, relationshipType: t })
    let doc = (packages, relationships) => ({ spdxVersion: 'SPDX-2.3', SPDXID: 'SPDXRef-DOCUMENT', packages, relationships })

    it('含 a→b→a 之 SBOM(es-abstract ⇄ string.prototype.trim):剔除一筆使之無循環,列出剔除者,其餘關係與順序不變,原物件不動', function() {
        let text = fs.readFileSync('./test/fixtures/cycle.spdx.json', 'utf8')
        let d = JSON.parse(text)
        assert.strict.ok(hasCycle(d)) //前提:fixture 確含循環
        let r = breakDependencyCycles(d)
        //剔除者:自入度 0 之 has-symbols 走到 es-abstract → string.prototype.trim,回指 es-abstract 之一筆為回邊
        assert.strict.deepEqual(r.removed, [{
            from: 'string.prototype.trim@1.2.11',
            to: 'es-abstract@1.24.2',
            relationshipType: 'DEPENDENCY_OF',
            spdxElementId: 'SPDXRef-Package-npm-string.prototype.trim-7e4a2c9b1d3f5a60',
            relatedSpdxElement: 'SPDXRef-Package-npm-es-abstract-3c1d9a7e5b2f4086',
        }])
        assert.strict.ok(!hasCycle(r.doc))
        //只少剔除之一筆,其餘依原順序;packages 等其他欄位不變
        assert.strict.deepEqual(r.doc.relationships, d.relationships.filter((_, i) => i !== 3))
        assert.strict.deepEqual(r.doc.packages, d.packages)
        //原物件未被改動
        assert.strict.deepEqual(d, JSON.parse(text))
    })

    it('無循環之 SBOM:不剔除,回傳原物件', function() {
        let d = JSON.parse(fs.readFileSync('./test/fixtures/vuln.spdx.json', 'utf8'))
        let r = breakDependencyCycles(d)
        assert.strict.deepEqual(r.removed, [])
        assert.strict.strictEqual(r.doc, d)
    })

    it('自我循環、三節點循環(提出端之 es-abstract → typed-array-byte-offset → reflect.getprototypeof)、重複之同向關係皆剔除;不看關係類型', function() {
        let d = doc(
            [pk('root', '1.0.0'), pk('has-symbols', '1.1.0'), pk('es-abstract', '1.24.2'), pk('typed-array-byte-offset', '1.0.5'), pk('reflect.getprototypeof', '1.0.10'), pk('self', '1.0.0')],
            [
                dep('has-symbols', 'es-abstract'),
                dep('es-abstract', 'typed-array-byte-offset'),
                dep('typed-array-byte-offset', 'reflect.getprototypeof'),
                dep('reflect.getprototypeof', 'es-abstract'),
                dep('reflect.getprototypeof', 'es-abstract', 'DEPENDS_ON'), //同一對節點另一筆(ex-sbom 不看類型,亦構成循環)
                dep('root', 'self', 'CONTAINS'),
                dep('self', 'self'),
            ],
        )
        assert.strict.ok(hasCycle(d))
        let r = breakDependencyCycles(d)
        assert.strict.ok(!hasCycle(r.doc))
        assert.strict.deepEqual(r.removed.map((x) => `${x.from} ${x.relationshipType} ${x.to}`), [
            'reflect.getprototypeof@1.0.10 DEPENDENCY_OF es-abstract@1.24.2',
            'reflect.getprototypeof@1.0.10 DEPENDS_ON es-abstract@1.24.2',
            'self@1.0.0 DEPENDENCY_OF self@1.0.0',
        ])
        assert.strict.strictEqual(r.doc.relationships.length, d.relationships.length - 3)
    })

    it('經 DOCUMENT、DocumentRoot-*、File-* 之環不算(ex-sbom 略過之),不剔除', function() {
        let d = doc([pk('a', '1'), pk('b', '1')], [
            { spdxElementId: 'SPDXRef-Package-npm-a', relatedSpdxElement: 'SPDXRef-File-package-lock.json-x', relationshipType: 'OTHER' },
            { spdxElementId: 'SPDXRef-File-package-lock.json-x', relatedSpdxElement: 'SPDXRef-Package-npm-a', relationshipType: 'OTHER' },
            { spdxElementId: 'SPDXRef-DocumentRoot-Directory-x', relatedSpdxElement: 'SPDXRef-Package-npm-b', relationshipType: 'CONTAINS' },
            { spdxElementId: 'SPDXRef-Package-npm-b', relatedSpdxElement: 'SPDXRef-DocumentRoot-Directory-x', relationshipType: 'OTHER' },
            { spdxElementId: 'SPDXRef-DOCUMENT', relatedSpdxElement: 'SPDXRef-DocumentRoot-Directory-x', relationshipType: 'DESCRIBES' },
            dep('a', 'b'),
        ])
        let r = breakDependencyCycles(d)
        assert.strict.deepEqual(r.removed, [])
        assert.strict.strictEqual(r.doc, d)
    })

    it('無入度 0 之節點可達之循環亦剔除;套件清單查無者以識別碼標示', function() {
        let d = doc([pk('x', '2.0.0')], [dep('x', 'y'), dep('y', 'x')])
        let r = breakDependencyCycles(d)
        assert.strict.ok(!hasCycle(r.doc))
        assert.strict.deepEqual(r.removed.map((x) => [x.from, x.to]), [['SPDXRef-Package-npm-y', 'x@2.0.0']])
    })

    it('深度 5 萬之相依鏈加一筆回指:只剔除該筆,不受呼叫堆疊限制', function() {
        let n = 50000
        let rels = []
        for (let i = 0; i < n - 1; i++) rels.push(dep(`p${i}`, `p${i + 1}`))
        rels.push(dep(`p${n - 1}`, 'p1'))
        let r = breakDependencyCycles(doc([], rels))
        assert.strict.deepEqual(r.removed.map((x) => [x.from, x.to]), [[`SPDXRef-Package-npm-p${n - 1}`, 'SPDXRef-Package-npm-p1']])
        assert.strict.strictEqual(r.doc.relationships.length, n - 1)
    })

})


//建議w-scan-dep修正.md(Gitea #24)二:ex-sbom 意外結束時,錯誤訊息附 log 中 fatal error/panic 及其後數行(長度設上限)(主控裁定 4)
describe('exsbom exitReasonFromLog', function() {

    let goStackOverflow = [
        'runtime: goroutine stack exceeds 1000000000-byte limit',
        'runtime: sp=0xc0205e0398 stack=[0xc0205e0000, 0xc0405e0000]',
        'fatal error: stack overflow',
        '',
        'runtime stack:',
        'runtime.throw({0x1b2c5e1?, 0x0?})',
        'runtime.newstack()',
        '',
        'goroutine 52 gp=0xc000602fc0 m=8 mp=0xc000500008 [running]:',
        'ex-sbom/internal/service/sbom.getSpdxDependencyDepthMap.func1({0xc0001b4f00, 0x2c}, 0x1e8479)',
        'ex-sbom/internal/service/sbom.getSpdxDependencyDepthMap.func1({0xc0001b4f30, 0x2b}, 0x1e8478)',
    ]

    it('取本次嘗試之 fatal error 行(含其前之 runtime: 說明)及其後數行,不含此前之一般 log', function() {
        let text = [
            '=== port 18080 2026-10-29T13:44:00.000Z ===',
            '[GIN-debug] Listening and serving HTTP on :18080',
            '2026/10/29 21:44:10 INFO SBOM created name=syft.spdx.json type=1',
            ...goStackOverflow,
        ].join('\r\n')
        let s = exitReasonFromLog(text)
        let lines = s.split('\n')
        assert.strict.strictEqual(lines[0], 'runtime: goroutine stack exceeds 1000000000-byte limit')
        assert.strict.strictEqual(lines[2], 'fatal error: stack overflow')
        assert.strict.ok(s.includes('getSpdxDependencyDepthMap'), s) //結束原因之所在函數
        assert.strict.ok(!s.includes('SBOM created') && !s.includes('GIN-debug'), s)
    })

    it('panic 亦取之;未見 fatal error/panic 時取末 3 個非空行', function() {
        let p = exitReasonFromLog(['INFO a', 'panic: runtime error: invalid memory address or nil pointer dereference', '[signal 0xc0000005 code=0x0 addr=0x0 pc=0x0]', '', 'goroutine 1 [running]:', 'main.main()'].join('\n'))
        assert.strict.ok(p.startsWith('panic: runtime error'), p)
        assert.strict.ok(p.includes('main.main()'), p)
        assert.strict.strictEqual(exitReasonFromLog('a\nb\n\nc\nd\n\n'), 'b\nc\nd')
        assert.strict.strictEqual(exitReasonFromLog(''), '')
    })

    it('同一區段有多個行首 panic/fatal error 時取最後一個(結束時之輸出);縮排之巢狀 panic 不另起', function() {
        let text = ['panic: logged earlier and recovered', 'INFO continue', 'panic: first [recovered]', '\tpanic: second', '', 'goroutine 1 [running]:'].join('\n')
        let s = exitReasonFromLog(text)
        assert.strict.ok(s.startsWith('panic: first [recovered]\n\tpanic: second'), s)
        assert.strict.ok(!s.includes('logged earlier'), s)
    })

    it('只看最後一次嘗試之區段:前次嘗試之 fatal error 不誤列', function() {
        let text = ['=== port 18080 x ===', ...goStackOverflow, '=== port 18081 y ===', 'line1', 'line2'].join('\n')
        assert.strict.strictEqual(exitReasonFromLog(text), 'line1\nline2')
    })

    it('長度上限:每行至多 300 字、總長至多 maxChars,其後之堆疊行數至多 after 行', function() {
        let long = 'x'.repeat(1000)
        let text = ['fatal error: stack overflow', ...Array(40).fill(long)].join('\n')
        let s = exitReasonFromLog(text)
        assert.strict.ok(s.length <= 1501, String(s.length))
        assert.strict.ok(s.split('\n').every((l) => l.length <= 301))
        let few = exitReasonFromLog(['fatal error: x', ...Array(40).fill('y')].join('\n'), { after: 5, maxChars: 100000 })
        assert.strict.strictEqual(few.split('\n').length, 6)
    })

})


//ex-sbom 工作目錄根之殘留清除(2026-10-03 修正; 2026-10-30 時序修正, 主控裁定③):只清建立者(PID)已不存在且名稱符合 <pid>-<6 碼> 者,
//被占用(Windows 下行程之工作目錄無法刪除)者略過並記警告, 其他夾不動。占用者以 test/tools/holdDir.mjs 模擬:
//待占用者確被持有才呼叫被測函數, 不以延時同步; delayMs 案證明測試不依賴「spawn 回傳即已持有」(WScanDep.test.mjs 之同名案經真 ex-sbom, 受本機 TCP 表異常影響)
describe('exsbom cleanStaleWork', function() {
    this.timeout(60000)

    let root = path.resolve('./test/_tmp/cleanStaleWork')
    let deadPid = () => {
        let pid = 4000000
        while ((() => {
            try {
                process.kill(pid, 0)
                return true
            }
            catch {
                return false
            }
        })()) pid += 4
        return pid
    }

    beforeEach(function() {
        fs.rmSync(root, { recursive: true, force: true })
        fs.mkdirSync(root, { recursive: true })
    })

    after(function() {
        fs.rmSync(root, { recursive: true, force: true, maxRetries: 5, retryDelay: 200 })
    })

    for (let delayMs of [0, 1500]) {
        it(`只清建立者已不存在且名稱相符者, 被占用者(${delayMs > 0 ? `占用者啟動後 ${delayMs} 毫秒才進入該目錄` : '以該目錄為工作目錄啟動'})略過並記警告, 其他夾不動`, async function() {
            let dead = deadPid()
            let stale = path.join(root, `${dead}-abcdef`)
            let locked = path.join(root, `${dead}-ghijkl`)
            let foreign = path.join(root, 'keep-me')
            let alive = path.join(root, `${process.pid}-mnopqr`) //建立者(本行程)仍存在: 進行中之他掃描不動
            for (let d of [stale, locked, foreign, alive]) {
                fs.mkdirSync(d, { recursive: true })
                fs.writeFileSync(path.join(d, 'x.txt'), 'x')
            }
            let holder = await holdDir(locked, { delayMs })
            let logs = []
            try {
                await cleanStaleWork(root, (m) => logs.push(m))
            }
            finally {
                await holder.stop()
            }
            assert.strict.ok(!fs.existsSync(stale), '建立者已不存在之子夾應被清除')
            assert.strict.ok(fs.existsSync(locked), '被占用者應保留')
            assert.strict.ok(logs.some((m) => m.includes('無法清除前次殘留之工作子夾') && m.includes(locked)), logs.join('\n'))
            assert.strict.ok(fs.existsSync(path.join(foreign, 'x.txt')), '名稱不符者不動')
            assert.strict.ok(fs.existsSync(path.join(alive, 'x.txt')), '建立者仍存在者不動')
        })
    }

    it('工作目錄根不存在時直接返回', async function() {
        await cleanStaleWork(path.join(root, 'not-exist'), () => {})
    })

})


//埠之監聽者之身分確認(2026-10-30, Gitea #24 之 TCP 表異常):改用 wsemi execProcessPortPidsSync(useBoth),不自行解析 netstat。
//Windows 11 26300(KB5127936)之系統 TCP 狀態值錯誤:netstat 整列漏列新起之監聽、對外連線反列 LISTENING。
//替身為 spawnSync 形之 opt.exec(test/tools/portExecKit.mjs),以資料來源(netstat、powershell)分派固定輸出;真實環境案見 api-exsbomPort.test.mjs
describe('exsbom portListeners 與 ownsPort(身分確認)', function() {
    let PORT = 8080
    let ME = 1111 //本次子程序
    let OTHER = 2222 //他服務
    let mine = (state = 'LISTENING') => row('TCP', `0.0.0.0:${PORT}`, '0.0.0.0:0', state, String(ME))
    //PowerShell 腳本之輸出列為 [本地埠, 遠端位址, 遠端埠, PID];監聽列之遠端位址為萬用位址、遠端埠為 0(不含本地位址)
    let psMine = [PORT, '0.0.0.0', 0, ME]
    let psOther = [PORT, '0.0.0.0', 0, OTHER]

    //規格: 該埠之監聽 PID 集合恰為 {本次子程序} 才算身分確認
    it('netstat 與 Get-NetTCPConnection 皆只有本次子程序 → ok,集合為 {PID}(PID 為數字)', function() {
        let calls = []
        let r = ownsPort(PORT, ME, { exec: fakeExec({ netstat: ok(ns([mine()])), powershell: ok(ps([psMine])) }, calls) })
        assert.strict.strictEqual(r.ok, true)
        assert.strict.deepEqual([...r.set], [ME])
        assert.strict.strictEqual(typeof [...r.set][0], 'number')
        assert.strict.deepEqual(calls, ['netstat', 'powershell']) //useBoth: netstat 有查到時仍查 Get-NetTCPConnection
    })

    //本機實測:netstat 整列漏列新起之監聽(列有他埠、獨缺該埠),修前以 netstat 全表判定即「監聽者已非本次 ex-sbom」
    it('netstat 漏列該埠之監聽列而 Get-NetTCPConnection 有 → 仍認得本次子程序(修前之 listeningPorts().get(port) 為 undefined)', function() {
        let r = ownsPort(PORT, ME, { exec: fakeExec({ netstat: ok(ns([])), powershell: ok(ps([psMine])) }) })
        assert.strict.strictEqual(r.ok, true)
        assert.strict.deepEqual([...r.set], [ME])
        //同形:netstat 之輸出完全無法解析(亂碼)亦轉查
        let g = ownsPort(PORT, ME, { exec: fakeExec({ netstat: ok('garbage \u0000ÿ output'), powershell: ok(ps([psMine])) }) })
        assert.strict.strictEqual(g.ok, true)
    })

    //useBoth 之必要:netstat 有列出時預設不查 PowerShell,會漏掉同埠並存之他服務(只綁 127.0.0.1 者),使「恰為本次」誤判為真
    it('他服務只在 Get-NetTCPConnection 出現(netstat 僅列本次子程序)→ 聯集含兩者,不 ok', function() {
        let r = ownsPort(PORT, ME, { exec: fakeExec({ netstat: ok(ns([mine()])), powershell: ok(ps([psMine, psOther])) }) })
        assert.strict.strictEqual(r.ok, false)
        assert.strict.deepEqual([...r.set].sort((a, b) => a - b), [ME, OTHER])
    })

    it('他服務只在 netstat 出現(Get-NetTCPConnection 僅列本次子程序)→ 聯集含兩者,不 ok', function() {
        let other = row('TCP', `127.0.0.1:${PORT}`, '0.0.0.0:0', 'LISTENING', String(OTHER))
        let r = ownsPort(PORT, ME, { exec: fakeExec({ netstat: ok(ns([other])), powershell: ok(ps([psMine])) }) })
        assert.strict.strictEqual(r.ok, false)
        assert.strict.deepEqual([...r.set].sort((a, b) => a - b), [ME, OTHER])
    })

    it('只有他服務(本次子程序未在監聽)→ 不 ok,集合為 {他服務}', function() {
        let r = ownsPort(PORT, ME, { exec: fakeExec({ netstat: ok(ns([])), powershell: ok(ps([psOther])) }) })
        assert.strict.strictEqual(r.ok, false)
        assert.strict.deepEqual([...r.set], [OTHER])
    })

    //規格: 「已確認無人」與「查詢失敗」嚴格分開;無人 → 空集合且不 ok,不拋錯
    it('兩者皆查無 → 空集合、不 ok、不拋錯(已確認無人)', function() {
        let r = ownsPort(PORT, ME, { exec: fakeExec({ netstat: ok(ns([])), powershell: ok(ps([])) }) })
        assert.strict.strictEqual(r.ok, false)
        assert.strict.strictEqual(r.set.size, 0)
        assert.strict.deepEqual(portListeners(PORT, { exec: fakeExec({ netstat: ok(ns([])), powershell: ok(ps([])) }) }), [])
    })

    //規格(Gitea #24 之 TCP 狀態值錯誤): 判定不依狀態欄
    it('不依狀態欄:本次子程序之監聽列被標為 FIN_WAIT_1/CLOSED 仍認得;對外連線反列 LISTENING 者不算監聽者', function() {
        for (let state of ['FIN_WAIT_1', 'CLOSED', 'ESTABLISHED', 'LISTENING']) {
            let r = ownsPort(PORT, ME, { exec: fakeExec({ netstat: ok(ns([mine(state)])), powershell: ok(ps([psMine])) }) })
            assert.strict.strictEqual(r.ok, true, state)
        }
        //該埠上之「對外連線」(外部位址非萬用)被列為 LISTENING:不是監聽者,故本次子程序仍為唯一
        let outbound = row('TCP', `192.168.1.5:${PORT}`, '20.1.2.3:443', 'LISTENING', String(OTHER))
        let r = ownsPort(PORT, ME, { exec: fakeExec({ netstat: ok(ns([mine(), outbound])), powershell: ok(ps([psMine])) }) })
        assert.strict.strictEqual(r.ok, true)
        assert.strict.deepEqual([...r.set], [ME])
    })

    it('同一 PID 於兩個來源與 IPv4/IPv6 重複出現只算一次', function() {
        let v6 = row('TCP', `[::]:${PORT}`, '[::]:0', 'LISTENING', String(ME))
        let r = ownsPort(PORT, ME, { exec: fakeExec({ netstat: ok(ns([mine(), v6])), powershell: ok(ps([psMine, [PORT, '::', 0, ME]])) }) })
        assert.strict.strictEqual(r.ok, true)
        assert.strict.deepEqual([...r.set], [ME])
    })

    it('他埠之列不混入(前綴/後綴相同之埠)', function() {
        let near = [
            row('TCP', `0.0.0.0:1${PORT}`, '0.0.0.0:0', 'LISTENING', '3001'), //後綴相同(18080)
            row('TCP', `0.0.0.0:${PORT}0`, '0.0.0.0:0', 'LISTENING', '3002'), //前綴相同(80800)
            row('TCP', `0.0.0.0:${PORT + 1}`, '0.0.0.0:0', 'LISTENING', '3003'),
        ]
        let r = ownsPort(PORT, ME, { exec: fakeExec({ netstat: ok(ns([mine(), ...near])), powershell: ok(ps([psMine])) }) })
        assert.strict.strictEqual(r.ok, true)
        assert.strict.deepEqual([...r.set], [ME])
    })

    it('useBoth 不可被呼叫端之 opt 蓋掉(身分確認須完整集合)', function() {
        let calls = []
        let r = ownsPort(PORT, ME, { useBoth: false, exec: fakeExec({ netstat: ok(ns([mine()])), powershell: ok(ps([psMine, psOther])) }, calls) })
        assert.strict.strictEqual(r.ok, false)
        assert.strict.deepEqual(calls, ['netstat', 'powershell'])
    })

    //規格(維持「查詢失敗即拋錯」): 失敗不得以空集合或部分結果代替
    describe('查詢失敗即拋錯(含失敗原因),不以空集合代替', function() {
        let FAILS = [
            { name: 'netstat 與 powershell 皆無法執行', outs: { netstat: err('ENOENT'), powershell: err('ENOENT') }, why: /netstat error\[ENOENT\].*powershell error\[ENOENT\]/ },
            { name: 'netstat 查無而 powershell 逾時', outs: { netstat: ok(ns([])), powershell: err('ETIMEDOUT') }, why: /powershell timeout\[\d+ms\]/ },
            { name: 'netstat 查無而 powershell 離開碼非 0', outs: { netstat: ok(ns([])), powershell: ok('', 3) }, why: /powershell code\[3\]/ },
            { name: 'netstat 有列出而 powershell 逾時(useBoth 不以 netstat 之部分結果代替)', outs: { netstat: ok(ns([mine()])), powershell: err('ETIMEDOUT') }, why: /powershell timeout/ },
            { name: 'powershell 輸出無法解析', outs: { netstat: ok(ns([])), powershell: ok('') }, why: /powershell unparseable output/ },
        ]
        for (let f of FAILS) {
            it(f.name, function() {
                for (let call of [() => ownsPort(PORT, ME, { exec: fakeExec(f.outs) }), () => portListeners(PORT, { exec: fakeExec(f.outs) })]) {
                    assert.throws(call, (e) => {
                        assert.strict.ok(e instanceof Error)
                        assert.strict.ok(e.message.startsWith(`查詢埠 ${PORT} 之監聽者失敗:`), e.message)
                        assert.strict.match(e.message, f.why)
                        return true
                    })
                }
            })
        }
        it('注入之執行函數拋錯亦為失敗(拋錯,不回傳空集合)', function() {
            let boom = () => {
                throw new Error('boom')
            }
            assert.throws(() => ownsPort(PORT, ME, { exec: boom }), /查詢埠 8080 之監聽者失敗:.*boom/)
        })
        it('埠號不合法為失敗(拋錯)', function() {
            assert.throws(() => portListeners(0, { exec: fakeExec({}) }), /查詢埠 0 之監聽者失敗:.*port is not an integer between 1 and 65535/)
        })
    })

})
