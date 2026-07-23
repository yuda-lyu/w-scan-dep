import assert from 'assert'
import fs from 'fs'
import wsm from '../src/WScanDep.mjs'


describe('WScanDep', function() {
    this.timeout(1800000) //首次執行須下載掃描工具與npm install,耗時較久

    let fpIn = './test/prj/package.json'
    let fdOut = './test/output'
    let ks = ['date', 'source', 'outputDir', 'tools', 'osv', 'grype', 'exsbom', 'updateList']

    it('test', async function() {
        let r = await wsm(fpIn, fdOut, { install: true })
        assert.strict.strictEqual(r, 'ok')

        //result.json之欄位
        let j = JSON.parse(fs.readFileSync(`${fdOut}/result.json`, 'utf8'))
        assert.strict.deepEqual(Object.keys(j), ks)

        //各報告檔案存在
        assert.strict.ok(fs.existsSync(`${fdOut}/result.md`))
        assert.strict.ok(fs.existsSync(`${fdOut}/待更新套件.md`))
        assert.strict.ok(fs.existsSync(`${fdOut}/pics`))
    })

})
