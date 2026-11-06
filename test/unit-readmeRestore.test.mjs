import assert from 'assert'
import fs from 'fs'
import vm from 'vm'
import { buildReport } from '../src/report.mjs'
import { parseWsdOpt } from '../src/scanOpt.mjs'
import * as fx from './tools/reportFixture.mjs'


//2026-11-06 sd330: README〈還原成升版前那份報告之措辭〉之範例必須可行——取出範例(README 內 restore-example 標記之間),
//把代稱「某系統」代換為中立假名「範例系統」後, 通過 opt 檢測, 且報告逐字等於修前 HEAD 之產出(golden, 見 unit-reportOpt.test.mjs)
describe('README restore example (報告用語)', function() {

    let readme = fs.readFileSync('./README.md', 'utf8')
    let fence = /<!-- restore-example:start -->\s*```js\n([\s\S]*?)\n```\s*<!-- restore-example:end -->/.exec(readme)
    let lit = fence && /const opt = (\{[\s\S]*?\n\})\n/.exec(fence[1])
    //範例為物件字面值(只含字串、陣列 join、物件), 於隔離之 vm 環境取值
    let opt = lit ? vm.runInNewContext(`(${lit[1]})`) : null
    let swap = (v) => {
        if (typeof v === 'string') return v.split('某系統').join('範例系統')
        if (Array.isArray(v)) return v.map(swap)
        if (v && typeof v === 'object') return Object.fromEntries(Object.entries(v).map(([k, x]) => [k, swap(x)]))
        return v
    }
    let golden = (k) => fs.readFileSync(`./test/fixtures/report-restored-${k}.golden.md`, 'utf8')

    it('README 內找得到範例, 且範例以「某系統」代稱(不寫真實系統名)', function() {
        assert.strict.ok(fence, 'restore-example 標記或程式碼區塊不存在')
        assert.strict.ok(lit, '範例內找不到 const opt = {…}')
        assert.strict.equal(opt.systemName, '某系統')
        assert.strict.deepStrictEqual(Object.keys(opt.packageNotes), ['vue'])
        assert.strict.ok(fence[1].includes('let r = await wsd(fpIn, fdOut, opt)'))
    })

    it('範例通過 opt 檢測(WScanDep 不會 reject), 且各項皆被採用', function() {
        let r = parseWsdOpt(opt)
        assert.strict.equal(r.systemName, '某系統')
        assert.strict.deepStrictEqual(Object.keys(r.packageNotes), ['vue'])
        assert.strict.equal(r.packageNotes.vue.heading, '【vue 套件/框架說明】')
    })

    it('範例(代換為中立假名)產出之報告逐字等於現版產出: 截圖成功與失敗兩種', function() {
        let o = swap(opt)
        assert.strict.equal(buildReport({ ...fx.base, exsbom: fx.exsbomOk, ...o }), golden('ok'))
        assert.strict.equal(buildReport({ ...fx.base, exsbom: fx.exsbomNg, ...o }), golden('ng'))
    })

})
