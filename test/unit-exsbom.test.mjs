import assert from 'assert'
import { parseNetstat, parseExcluded, pickPort, classifyExSbomLog } from '../src/exsbom.mjs'


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
