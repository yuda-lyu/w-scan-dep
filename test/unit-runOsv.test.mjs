import assert from 'assert'
import fs from 'fs'
import path from 'path'
import { runOsv } from '../src/scan.mjs'


//重跑同一 fdOut 時,osv-scanner 未寫出本次結果者不得讀到上一次之 report(osv).md / osv.json
describe('runOsv', function() {
    this.timeout(60000)

    let root = path.resolve('./test/_tmp/runOsv')
    let mdPath = path.join(root, 'report(osv).md')
    let jsonPath = path.join(root, 'osv.json')
    let cdxPath = path.join(root, 'empty.cdx.json')
    let staleMd = '| https://osv.dev/GHSA-stale | 5.9 | npm | nodemailer | 9.1.1 | 10.0.0 |'
    let staleJson = JSON.stringify({ results: [{ packages: [{ package: { name: 'nodemailer', version: '9.1.1', ecosystem: 'npm' }, vulnerabilities: [{ id: 'GHSA-stale' }] }] }] })
    let log = () => {}

    //已下載之 osv-scanner(由完整掃描產生於 test/output/tools)
    let findOsv = () => {
        let fd = path.resolve('./test/output/tools/osv-scanner')
        if (!fs.existsSync(fd)) return null
        for (let v of fs.readdirSync(fd)) {
            let p = path.join(fd, v, 'osv-scanner.exe')
            if (fs.existsSync(p)) return p
        }
        return null
    }

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

    it('SBOM 無套件(exit 128,不寫輸出檔)時視為無漏洞,不讀到上一次之結果', async function() {
        let osvExe = findOsv()
        if (!osvExe) this.skip() //尚未完整掃描過、無已下載之 osv-scanner
        let r = await runOsv(osvExe, cdxPath, root, log)
        assert.strict.strictEqual(r.mdText, '')
        assert.strict.deepEqual(r.packages, [])
    })

})
