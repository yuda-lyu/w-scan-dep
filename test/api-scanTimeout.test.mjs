import assert from 'assert'
import fs from 'fs'
import path from 'path'
import { pathToFileURL } from 'url'
import { runSyft, runGrype, runScan, SCAN_TIMEOUTS } from '../src/scan.mjs'
import { withEnv } from './tools/fakeBins.mjs'
import { hangRegistry } from './tools/hangRegistry.mjs'


//建議w-scan-dep修正.md(Gitea #24)三之同類(主控裁定 2): syft、grype、osv-scanner 亦須有時限,
//可由環境變數各自調整(秒), 逾時須結束整個子行程樹並拋出含「逾時」與工具名之錯誤。
//以「連上無回應之服務後永遠等待」之替身執行檔(test/tools/hangTool.mjs, 以node.exe加NODE_OPTIONS=--import扮演, 另啟一個detached孫行程)真實執行,
//時限用短值(8秒, 須長於「替身之根行程與孫行程兩個node啟動並連線」所需之時間); 以替身之連線全數被關閉判定「整個子行程樹已結束」(只結束根行程時孫行程之連線仍在)
//osv-scanner不在本檔: 其第一個參數為-L, node.exe視為不認得之選項而於載入NODE_OPTIONS之preload前以離開碼9結束(unit-runOsv即依此事實),
//替身無法接住; osv-scanner之逾時由api-wsdEntry.test.mjs(攔截spawn、以空參數啟動替身)驗證
describe('scan tool timeout', function() {
    this.timeout(40000) //各案時限 5～8 秒; 此上限只防懸置(缺陷版不結束卡住之工具時以此兜底)

    let root = path.resolve('./test/_tmp/scanTimeout')
    let port = 8988
    let reg = null
    let hangTool = path.resolve('./test/tools/hangTool.mjs')
    let limitSec = 8
    let log = () => {}

    //替身之環境: 所有以node.exe啟動之行程先載入hangTool.mjs而卡住
    let standIn = (more) => ({
        NODE_OPTIONS: `--import=${pathToFileURL(hangTool).href}`,
        FAKE_HANG_PORT: String(port),
        ...more,
    })
    let cdx = path.join(root, 'syft.cdx.json')
    let target = path.join(root, 'target')

    before(async function() {
        fs.rmSync(root, { recursive: true, force: true })
        fs.mkdirSync(target, { recursive: true })
        fs.writeFileSync(cdx, '{}')
        reg = await hangRegistry(port)
    })

    after(async function() {
        if (reg) await reg.close()
        fs.rmSync(root, { recursive: true, force: true, maxRetries: 5, retryDelay: 200 })
    })

    //各工具: 其時限環境變數、呼叫方式(替身執行檔為node.exe, 第一個參數非選項〔scan、sbom:…〕者, 不論其後傳入何種參數皆卡住)
    let cases = [
        { label: 'syft', run: () => runSyft(process.execPath, target, root, log) },
        { label: 'grype', run: () => runGrype(process.execPath, cdx, root, log) },
    ]

    for (let c of cases) {
        let envName = SCAN_TIMEOUTS[c.label].envName

        it(`${c.label}: 卡住時於 ${envName} 指定之時限到即以含「逾時」與工具名之錯誤結束, 且整個子行程樹已結束`, async function() {
            let a0 = reg.accepted()
            let t0 = Date.now()
            let err = await withEnv(standIn({ [envName]: String(limitSec) }), () => c.run().then(() => null, (e) => e))
            let ms = Date.now() - t0
            //逾時以錯誤結束, 訊息含工具名、時限、樹狀結束與調整方式(環境變數名)
            assert.strict.ok(err instanceof Error, `${c.label} 應以錯誤結束`)
            assert.strict.strictEqual(err.message, `${c.label} 逾時(超過 ${limitSec} 秒未完成),已結束 ${c.label} 子行程樹;可設環境變數 ${envName}(秒)調整時限`)
            //不早於時限結束(上限由 mocha 之 timeout 兜底, 只防懸置)
            assert.strict.ok(ms >= limitSec * 1000 - 50, String(ms))
            //前提: 根行程與其孫行程皆已連上無回應之服務(卡住之原因即該服務); 時限內未連上則本案前提不成立
            assert.strict.ok(reg.accepted() - a0 >= 2, `替身之根行程與孫行程應皆已連線, 本案收到 ${reg.accepted() - a0} 條`)
            //整個子行程樹已結束: 行程結束時其連線由作業系統關閉; 只結束根行程時孫行程續跑、連線仍在
            assert.strict.ok(await reg.allClosed(15000), `仍有 ${reg.open()} 條連線未關閉:子行程樹未全數結束`)
        })
    }

    it('時限只由各工具自己的環境變數決定(syft 之時限不影響 grype)', async function() {
        //W_SYFT_TIMEOUT 設為不合法值時 grype 不受影響(grype 之時限仍取自 W_GRYPE_TIMEOUT); 反之亦然
        let a0 = reg.accepted()
        let err = await withEnv(standIn({ W_SYFT_TIMEOUT: 'abc', W_GRYPE_TIMEOUT: String(limitSec) }), () => runGrype(process.execPath, cdx, root, log).then(() => null, (e) => e))
        assert.strict.ok(err.message.startsWith(`grype 逾時(超過 ${limitSec} 秒未完成)`), err.message)
        assert.strict.ok(reg.accepted() - a0 >= 1)
        assert.strict.ok(await reg.allClosed(15000), `仍有 ${reg.open()} 條連線未關閉`)
    })

    it('runScan 以傳入之 timeouts 為準(WScanDep 先驗證環境變數後傳入); syft 逾時即中止, 不啟動 grype 與 osv-scanner', async function() {
        let a0 = reg.accepted()
        let tools = {
            'syft': { exePath: process.execPath },
            'grype': { exePath: path.join(root, 'must-not-run-grype.exe') },
            'osv-scanner': { exePath: path.join(root, 'must-not-run-osv.exe') },
        }
        let err = await withEnv(standIn(), () => {
            return runScan(tools, target, root, log, { 'syft': 5000, 'grype': 1800000, 'osv-scanner': 1800000 }).then(() => null, (e) => e)
        })
        assert.strict.match(err.message, /^syft 逾時\(超過 5 秒未完成\),已結束 syft 子行程樹/)
        assert.strict.ok(reg.accepted() - a0 >= 1)
        assert.strict.ok(await reg.allClosed(15000), `仍有 ${reg.open()} 條連線未關閉`)
    })

})
