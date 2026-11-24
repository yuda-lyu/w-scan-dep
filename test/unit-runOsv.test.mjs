import assert from 'assert'
import fs from 'fs'
import path from 'path'
import { runOsv } from '../src/scan.mjs'
import { ensureTestBins } from './tools/binsAcquire.mjs'


//重跑同一 fdOut 時,osv-scanner 未寫出本次結果者不得讀到上一次之 report(osv).md / osv.json
//真實 osv-scanner 由 ensureTestBins 於 before 取得(唯一取得點,R-BIN-ENSURE-01 規則 10);原先只找舊版遺留之 test/output/tools 並於找不到時略過,乾淨環境(如發布包解開之目錄)靜默不跑該案
describe('runOsv', function() {
    this.timeout(60000)

    let root = path.resolve('./test/_tmp/runOsv')
    let mdPath = path.join(root, 'report(osv).md')
    let jsonPath = path.join(root, 'osv.json')
    let cdxPath = path.join(root, 'empty.cdx.json')
    let staleMd = '| https://osv.dev/GHSA-stale | 5.9 | npm | nodemailer | 9.1.1 | 10.0.0 |'
    let staleJson = JSON.stringify({ results: [{ packages: [{ package: { name: 'nodemailer', version: '9.1.1', ecosystem: 'npm' }, vulnerabilities: [{ id: 'GHSA-stale' }] }] }] })
    let log = () => {}

    beforeEach(function() {
        fs.rmSync(root, { recursive: true, force: true })
        fs.mkdirSync(root, { recursive: true })
        fs.writeFileSync(mdPath, staleMd, 'utf8')
        fs.writeFileSync(jsonPath, staleJson, 'utf8')
        fs.writeFileSync(cdxPath, JSON.stringify({ bomFormat: 'CycloneDX', specVersion: '1.6', version: 1, components: [] }), 'utf8')
    })

    after(function() {
        fs.rmSync(root, { recursive: true, force: true })
    })

    it('osv-scanner 執行錯誤(非 0/1/128)時拋錯,且不留上一次之輸出', async function() {
        //以 node.exe 冒充:不認得 -L 參數,exit 9 且不寫輸出檔
        await assert.rejects(runOsv(process.execPath, cdxPath, root, log), /osv-scanner 失敗 \(code 9\)/)
        assert.strict.ok(!fs.existsSync(mdPath))
        assert.strict.ok(!fs.existsSync(jsonPath))
    })

    describe('with the real osv-scanner', function() {
        let osvExe = null

        before(async function() {
            osvExe = (await ensureTestBins(this))['osv-scanner.exe']
        })

        it('SBOM 無套件(exit 128,不寫輸出檔)時視為無漏洞,不讀到上一次之結果', async function() {
            let r = await runOsv(osvExe, cdxPath, root, log)
            assert.strict.strictEqual(r.mdText, '')
            assert.strict.deepEqual(r.packages, [])
        })
    })

})
