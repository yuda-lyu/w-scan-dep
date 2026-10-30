import assert from 'assert'
import { EventEmitter } from 'events'
import { runTool, timeoutMsFromEnv, fmtMs, within, waitChild, killNote } from '../src/proc.mjs'


//外部指令之時限執行(src/proc.mjs): runTool收集輸出並回傳離開碼, 不因非0離開碼拋錯(osv-scanner有漏洞時回1), 無法啟動與輸出超量拋「執行錯誤」;
//逾時(含樹狀結束)需要真實卡住之行程, 見api-scanTimeout.test.mjs
describe('proc', function() {
    this.timeout(60000)

    let node = process.execPath
    let opt = { label: 'tool', timeoutMs: 30000, envName: 'W_TOOL_TIMEOUT' }

    describe('timeoutMsFromEnv', function() {

        it('未設或空白為預設秒數(換算為毫秒), 正數(含小數、指數)換算為毫秒', function() {
            assert.strict.strictEqual(timeoutMsFromEnv('W_X', 600, {}), 600000)
            assert.strict.strictEqual(timeoutMsFromEnv('W_X', 600, { W_X: '' }), 600000)
            assert.strict.strictEqual(timeoutMsFromEnv('W_X', 600, { W_X: '  ' }), 600000)
            assert.strict.strictEqual(timeoutMsFromEnv('W_X', 600, { W_X: '90' }), 90000)
            assert.strict.strictEqual(timeoutMsFromEnv('W_X', 600, { W_X: '0.5' }), 500)
            assert.strict.strictEqual(timeoutMsFromEnv('W_X', 600, { W_X: '1e3' }), 1000000)
            assert.strict.strictEqual(timeoutMsFromEnv('W_X', 600, { W_X: '2147483' }), 2147483000)
        })

        it('非正數、非十進位數字、不足 1 毫秒或超過計時器上限(2147483 秒)即拋錯, 訊息含變數名與原值', function() {
            //超過 2^31-1 毫秒時 setTimeout 會改為 1 毫秒, 工具將立即被判逾時; 不足 1 毫秒者同樣被改為 1 毫秒; 0x10 等進位寫法 Number() 會收下(16 秒), 但非「正數秒」之本意
            for (let v of ['0', '-5', 'abc', '20m', 'Infinity', 'NaN', '2147484', '0x10', '0b11', '1e-7', '1_0']) {
                assert.strict.throws(() => timeoutMsFromEnv('W_X', 600, { W_X: v }), (err) => {
                    assert.strict.ok(err.message.includes('環境變數 W_X 須為正數') && err.message.includes(`「${v}」`), err.message)
                    return true
                })
            }
        })

    })

    describe('fmtMs, within', function() {

        it('整分鐘以「N 分鐘」, 其餘以「N 秒」表示', function() {
            assert.strict.strictEqual(fmtMs(600000), '10 分鐘')
            assert.strict.strictEqual(fmtMs(90000), '90 秒')
            assert.strict.strictEqual(fmtMs(6000), '6 秒')
            assert.strict.strictEqual(fmtMs(500), '0.5 秒')
        })

        it('within: 先解決者回 true, 到期回 false', async function() {
            assert.strict.strictEqual(await within(Promise.resolve(1), 60000), true)
            assert.strict.strictEqual(await within(new Promise(() => {}), 20), false)
        })

        it('within 與 runTool 於先解決時清除計時器(不拖住呼叫端結束)', async function() {
            await null //mocha 於 async 案回傳 promise 後才建立其逾時計時器, 先讓出再取基準, 前後同一狀態
            let timers = () => process.getActiveResourcesInfo().filter((v) => v === 'Timeout').length
            let n0 = timers()
            await within(Promise.resolve(1), 600000)
            assert.strict.strictEqual(timers(), n0, 'within 之計時器未清除')
            await runTool(node, ['-e', ''], { ...opt, timeoutMs: 600000 })
            assert.strict.strictEqual(timers(), n0, 'runTool 之計時器未清除')
        })

    })

    describe('waitChild, killNote', function() {

        //不存在之 PID(taskkill 回 128「找不到行程」); 取一個目前沒有行程的值, 以免誤殺他人之行程
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

        it('時限邊界上子行程剛好自行結束(taskkill 找不到該行程, 其 exit 事件稍後才到)視為正常結束, 不報逾時', async function() {
            let c = new EventEmitter()
            c.pid = deadPid()
            c.kill = () => c.emit('exit', 7) //exit 事件於 taskkill 之後才被處理
            let r = await waitChild(c, 20, 'exit')
            assert.strict.deepStrictEqual(r, { timedOut: false, code: 7, error: null })
        })

        it('killNote: 已確認結束時寫「已結束…子行程樹」, 否則寫「未確認成功」與 taskkill 離開碼', function() {
            assert.strict.strictEqual(killNote({ gone: true, killStatus: 0, pid: 5 }, '安裝'), '已結束安裝子行程樹')
            assert.strict.strictEqual(killNote({ gone: true, killStatus: 0, pid: 5 }, ' syft '), '已結束 syft 子行程樹')
            assert.strict.strictEqual(killNote({ gone: false, killStatus: 0, pid: 5 }, ' syft '), '結束 syft 子行程樹(PID 5)未確認成功(taskkill 離開碼 0)')
            assert.strict.strictEqual(killNote({ gone: true, killStatus: 1, pid: 5 }, '安裝'), '結束安裝子行程樹(PID 5)未確認成功(taskkill 離開碼 1)')
        })

    })

    describe('runTool', function() {

        it('收集 stdout 與 stderr(utf8, 多位元組字元被切成兩段輸出亦完整)並回傳離開碼, 非 0 不拋錯', async function() {
            //「中」= e4 b8 ad; 逐位元組分 60 次寫出(間隔 3 毫秒, 僅為製造分段: 父行程每次讀到的塊落在字元中間的機會極高, 斷言與分段時機無關, 合併成一塊只會使本案較不嚴格、不會假紅)
            let code = [
                'let bytes = Buffer.from("中".repeat(20))',
                'let i = 0',
                'let tick = () => { if (i < bytes.length) { process.stdout.write(bytes.subarray(i, i + 1)); i++; setTimeout(tick, 3) } else { process.stderr.write("err 錯誤"); process.exitCode = 3 } }',
                'tick()',
            ].join(';')
            let r = await runTool(node, ['-e', code], opt)
            assert.strict.strictEqual(r.status, 3)
            assert.strict.strictEqual(r.stdout, '中'.repeat(20))
            assert.strict.strictEqual(r.stderr, 'err 錯誤')
        })

        it('離開碼 0 回傳 status 0', async function() {
            let r = await runTool(node, ['-e', ''], opt)
            assert.strict.strictEqual(r.status, 0)
            assert.strict.strictEqual(r.stdout, '')
        })

        it('傳入之 env 為子行程之環境(scan.mjs 以此傳 NO_COLOR 關閉 grype 之色碼)', async function() {
            assert.strict.strictEqual(process.env.W_FROM_TEST, undefined)
            let r = await runTool(node, ['-e', 'process.stdout.write(String(process.env.W_FROM_TEST))'], { ...opt, env: { ...process.env, W_FROM_TEST: 'yes' } })
            assert.strict.strictEqual(r.stdout, 'yes')
        })

        it('執行檔不存在時拋「<label> 執行錯誤」', async function() {
            let err = await runTool('C:\\w-scan-dep-not-exist\\tool.exe', [], opt).then(() => null, (e) => e)
            assert.strict.ok(err instanceof Error)
            assert.strict.match(err.message, /^tool 執行錯誤: /)
        })

        it('輸出超過 maxBuffer 即結束子行程並拋「執行錯誤」(子行程確已結束才拋)', async function() {
            //子行程輸出 10000 位元組後續跑(若未被結束, 防殘留 60 秒後自行結束); 拋錯時機為 close, 故拋錯即代表子行程已結束
            let code = 'process.stdout.write("x".repeat(10000)); setInterval(() => {}, 1e9); setTimeout(() => process.exit(0), 60000).unref()'
            let err = await runTool(node, ['-e', code], { ...opt, maxBuffer: 100 }).then(() => null, (e) => e)
            assert.strict.ok(err instanceof Error)
            assert.strict.match(err.message, /^tool 執行錯誤: 輸出超過 100 位元組$/)
        })

    })

})
