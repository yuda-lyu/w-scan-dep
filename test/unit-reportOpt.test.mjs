import assert from 'assert'
import fs from 'fs'
import { buildReport } from '../src/report.mjs'
import { PACKAGE_NOTES } from '../src/config.mjs'
import * as fx from './tools/reportFixture.mjs'


//2026-11-06 sd330: 公開套件之報告預設文字不得寫死使用端之系統名與現況;系統名(systemName)與套件說明(packageNotes)由呼叫端傳入
//規格(派工書): ①未給選項時報告與套件說明不提任何特定系統; ②systemName 代入報告內文兩處,未給用中立說法;
//③packageNotes 能新增與覆寫某套件之說明; ④給了與原本等價之選項時報告逐字等於現版產出(golden 取自修前 HEAD 之產出,系統名以中立假名「範例系統」代換);
//⑤輸入檢測依 dspec〈輸入參數之檢測機制〉K3:選項給了而非預期者視為未給、改用預設,不報錯
describe('buildReport (systemName and packageNotes)', function() {

    let build = (extra, exsbom) => buildReport({ ...fx.base, exsbom: exsbom || fx.exsbomOk, ...extra })
    let defaultMd = build({})
    let sys = 'XYZ範例系統'

    class WithVue {
        constructor() {
            this.vue = { body: 'x' }
        }
    }

    function boom(msg) {
        throw new Error(msg)
    }

    //原本之 vue 說明(使用端之現況與規劃,由呼叫端自行傳入以還原), 系統名以中立假名代換
    let restoredVue = {
        heading: '【vue 套件/框架說明】',
        body: [
            '目前範例系統都使用 vue（2.7.16），此為 vue2 最新版。其被提報之漏洞主要是中低風險漏洞，詳情如下表 1：',
            '',
            '表 1 Vue2 已知漏洞',
            '',
            '| 漏洞 | 觸發條件 | 情境 |',
            '| --- | --- | --- |',
            '| **ReDoS**<br>CVSS：3.7（Low） | 攻擊者需能注入惡意 Vue 模板 | **幾乎不受影響**：模板是開發者寫的，使用者無法控制 |',
            '| **XSS via prototype pollution**<br>CVSS：4.2（Medium） | 需先有 prototype pollution 入口 | **風險低**：除非其他依賴有 prototype pollution 漏洞可串聯 |',
            '',
            '若欲修復此 2 漏洞，仍須待之後進行大規模之底層重構，才有辦法讓範例系統由 vue2 升 vue3 版。',
        ].join('\n'),
    }

    describe('predefined text is neutral (spec ①)', function() {

        it('未給選項: 兩處系統名句為中立說法, 且整份報告不含任何「系統」字樣(任何系統名皆會帶此詞)', function() {
            for (let md of [defaultMd, build({}, fx.exsbomNg)]) {
                assert.strict.ok(md.includes('基於「SBOM 開源工具使用說明」所提及之工具進行依賴套件掃描：\n'), md)
                assert.strict.ok(md.includes('\n1. 使用 syft 掃描已安裝之依賴\n'), md)
                assert.strict.ok(!md.includes('系統'), md)
            }
        })

        //全文釘住: 預設報告與修前產出(golden, 系統名已代換為「範例系統」)之差異, 只有這幾行(白名單); 其餘文字一字不差, 任何額外或遺漏之改動都會失敗
        it('未給選項: 與現版產出之差異恰為系統名兩句、vue 說明中使用端之現況句與規劃句(其餘逐字相同)', function() {
            let golden = fs.readFileSync('./test/fixtures/report-restored-ok.golden.md', 'utf8').split('\n')
            let now = defaultMd.split('\n')
            assert.strict.deepStrictEqual(golden.filter((l) => !now.includes(l)), [
                '基於「SBOM 開源工具使用說明」所提及之工具進行範例系統之依賴套件掃描：',
                '1. 使用 syft 掃描範例系統安裝依賴',
                '目前範例系統都使用 vue（2.7.16），此為 vue2 最新版。其被提報之漏洞主要是中低風險漏洞，詳情如下表 1：',
                '若欲修復此 2 漏洞，仍須待之後進行大規模之底層重構，才有辦法讓範例系統由 vue2 升 vue3 版。',
            ])
            assert.strict.deepStrictEqual(now.filter((l) => !golden.includes(l)), [
                '基於「SBOM 開源工具使用說明」所提及之工具進行依賴套件掃描：',
                '1. 使用 syft 掃描已安裝之依賴',
                'vue2 最新版為 2.7.16，其被提報之漏洞主要是中低風險漏洞，詳情如下表 1：',
            ])
            assert.strict.equal(now.length, golden.length - 2) //少了規劃句及其前之空行
        })

        it('預設 vue 說明不含使用端之現況與規劃(目前使用之版本、升版之前提), 保留通用事實(Vue2 已知漏洞表)', function() {
            let body = PACKAGE_NOTES.vue.body
            assert.strict.ok(!/系統|目前|大規模之底層重構|才有辦法讓/.test(body), body)
            //通用事實: 漏洞名稱、CVSS、觸發條件、情境
            for (let s of ['表 1 Vue2 已知漏洞', '**ReDoS**<br>CVSS：3.7（Low）', '攻擊者需能注入惡意 Vue 模板', '**XSS via prototype pollution**<br>CVSS：4.2（Medium）', '需先有 prototype pollution 入口']) {
                assert.strict.ok(body.includes(s), s)
            }
            assert.strict.ok(defaultMd.includes('【vue 套件/框架說明】') && defaultMd.includes(body), defaultMd)
        })

        it('預設之全部套件說明(PACKAGE_NOTES)與報告皆不含特定系統字樣', function() {
            for (let [k, v] of Object.entries(PACKAGE_NOTES)) {
                assert.strict.ok(!v.heading.includes('系統') && !v.body.includes('系統'), k)
            }
        })

        it('章節結構與現版相同(各級標題、順序)', function() {
            let heads = (md) => md.split('\n').filter((l) => /^#{1,3} /.test(l))
            let golden = fs.readFileSync('./test/fixtures/report-restored-ok.golden.md', 'utf8')
            assert.strict.deepStrictEqual(heads(defaultMd), heads(golden))
            assert.strict.deepStrictEqual(heads(defaultMd), ['# 依賴套件掃描報告', '## 掃描資訊', '## 一、依賴套件掃描技術', '## 二、掃描結果'])
        })

    })

    describe('systemName (spec ②)', function() {

        it('給了 systemName: 代入「進行…之依賴套件掃描」與「使用 syft 掃描…安裝依賴」兩處, 其餘不變', function() {
            let md = build({ systemName: sys })
            assert.strict.ok(md.includes(`基於「SBOM 開源工具使用說明」所提及之工具進行${sys}之依賴套件掃描：\n`), md)
            assert.strict.ok(md.includes(`\n1. 使用 syft 掃描${sys}安裝依賴\n`), md)
            assert.strict.equal(md.split(sys).length - 1, 2, md)
            //代回中立說法後與未給時逐字相同(只有這兩處不同)
            assert.strict.equal(md.replace(`進行${sys}之依賴`, '進行依賴').replace(`掃描${sys}安裝依賴`, '掃描已安裝之依賴'), defaultMd)
        })

        it('截圖失敗之報告同樣代入', function() {
            let md = build({ systemName: sys }, fx.exsbomNg)
            assert.strict.equal(md.split(sys).length - 1, 2, md)
        })

        it('前後空白去除後代入', function() {
            let md = build({ systemName: `  ${sys}\t` })
            assert.strict.ok(md.includes(`進行${sys}之依賴套件掃描`) && md.includes(`掃描${sys}安裝依賴`), md)
        })

        //K3: 給了而非預期者(非字串、空白、含換行、包裝物件)視為未給, 改用中立說法, 不報錯
        for (let [label, v] of [['undefined', undefined], ['null', null], ['空字串', ''], ['純空白', ' \t '], ['數字', 123], ['布林', true], ['物件', {}], ['陣列', ['a']], ['函數', () => 'a'], ['包裝物件', Object('a')], ['含換行(會破壞報告行)', 'a\nb'], ['含 CR', 'a\rb'], ['含 U+2028', 'a\u2028b'], ['含 U+0085', 'a\u0085b'], ['含 NUL', 'a\u0000b'], ['含 DEL', 'a\u007fb']]) {
            it(`systemName 為${label}: 視為未給, 報告與未給時逐字相同`, function() {
                assert.strict.equal(build({ systemName: v }), defaultMd)
            })
        }

    })

    describe('packageNotes (spec ③)', function() {

        it('新增: 被標注之套件(semver)有自訂說明則附於預設說明之後, 預設之 xlsx、vue 說明仍在', function() {
            let md = build({ packageNotes: { semver: { heading: '【semver 自訂】', body: '自訂內容 A\n\n第二段' } } })
            assert.strict.ok(md.includes('【semver 自訂】\n\n自訂內容 A\n\n第二段\n'), md)
            let ix = ['【xlsx 套件說明】', '【vue 套件/框架說明】', '【semver 自訂】'].map((h) => md.indexOf(h))
            assert.strict.ok(ix[0] > 0 && ix[0] < ix[1] && ix[1] < ix[2], ix.join(','))
            assert.strict.ok(md.includes(PACKAGE_NOTES.xlsx.body) && md.includes(PACKAGE_NOTES.vue.body))
        })

        it('新增: 未被標注之套件的說明不顯示', function() {
            let md = build({ packageNotes: { lodash: { heading: '【lodash 自訂】', body: '不應出現' } } })
            assert.strict.equal(md, defaultMd)
        })

        it('新增: 未給 heading 用「【套件名 套件說明】」', function() {
            let md = build({ packageNotes: { semver: { body: '只有內容' } } })
            assert.strict.ok(md.includes('【semver 套件說明】\n\n只有內容\n'), md)
        })

        it('覆寫: xlsx 說明改為自訂, 預設內容消失, 位置不變(仍在 vue 之前)', function() {
            let md = build({ packageNotes: { xlsx: { heading: '【xlsx 自訂】', body: '自訂 xlsx 內容' } } })
            assert.strict.ok(md.includes('【xlsx 自訂】\n\n自訂 xlsx 內容\n'), md)
            assert.strict.ok(!md.includes('SheetJS') && !md.includes('【xlsx 套件說明】'), md)
            assert.strict.ok(md.indexOf('【xlsx 自訂】') < md.indexOf('【vue 套件/框架說明】'), md)
            assert.strict.ok(md.includes(PACKAGE_NOTES.vue.body)) //另一套件之預設說明不受影響
        })

        it('覆寫: 只給 body 時沿用該套件預設之 heading', function() {
            let md = build({ packageNotes: { vue: { body: '只換內容' } } })
            assert.strict.ok(md.includes('【vue 套件/框架說明】\n\n只換內容\n'), md)
            assert.strict.ok(!md.includes('表 1 Vue2 已知漏洞'), md)
        })

        it('heading 非預期(非字串、空白、含換行): 退回預設 heading(覆寫)或「【套件名 套件說明】」(新增)', function() {
            for (let h of [123, '', '  ', 'a\nb', 'a\u2028b', 'a\u0000b', null, {}, Object('h')]) {
                let md = build({ packageNotes: { vue: { heading: h, body: 'B1' }, semver: { heading: h, body: 'B2' } } })
                assert.strict.ok(md.includes('【vue 套件/框架說明】\n\nB1\n') && md.includes('【semver 套件說明】\n\nB2\n'), `${String(h)}: ${md}`)
            }
        })

        it('還原: 以原本等價之說明覆寫 vue 說明, 給了 packageNotes.vue 之內容逐字出現', function() {
            let md = build({ systemName: '範例系統', packageNotes: { vue: restoredVue } })
            assert.strict.ok(md.includes(`${restoredVue.heading}\n\n${restoredVue.body}\n`), md)
        })

        //K3: entry 非預期(缺 body、body 非字串或空白、非物件)者忽略該筆: 新增者不顯示, 覆寫者退回預設
        let badEntries = [['字串', 'text'], ['null', null], ['數字', 5], ['陣列', [{ body: 'x' }]], ['空物件', {}], ['body 空字串', { body: '' }], ['body 純空白', { body: '  \n ' }], ['body 數字', { body: 123 }], ['body 包裝物件', { body: Object('x') }], ['body 物件', { body: { a: 1 } }]]
        for (let [label, e] of badEntries) {
            it(`entry 為「${label}」: 該筆忽略(新增者不顯示, 覆寫者退回預設說明)`, function() {
                assert.strict.equal(build({ packageNotes: { semver: e, vue: e } }), defaultMd)
            })
        }

        //K3: packageNotes 本身非預期(非一般物件)視為未給
        for (let [label, v] of [['undefined', undefined], ['null', null], ['字串', 'x'], ['數字', 1], ['陣列', [{ vue: { body: 'x' } }]], ['Map', new Map([['vue', { body: 'x' }]])], ['Date', new Date()], ['函數', () => ({})], ['class 實例', new WithVue()]]) {
            it(`packageNotes 為${label}: 視為未給, 報告與未給時逐字相同`, function() {
                assert.strict.equal(build({ packageNotes: v }), defaultMd)
            })
        }

        it('Object.create(null) 之 packageNotes 有效', function() {
            let o = Object.create(null)
            o.semver = { body: 'NP' }
            assert.strict.ok(build({ packageNotes: o }).includes('【semver 套件說明】\n\nNP\n'))
        })

        it('entry 之取值拋錯(getter)只忽略該筆, 不使報告失敗', function() {
            let bad = {}
            Object.defineProperty(bad, 'body', { enumerable: true, get: () => boom('boom') })
            let md = build({ packageNotes: { semver: bad, vue: { body: 'V2' } } })
            assert.strict.ok(!md.includes('【semver 套件說明】') && md.includes('【vue 套件/框架說明】\n\nV2\n'), md)
        })

        it('以 __proto__ 為鍵不污染原型, 不當成套件說明', function() {
            let evil = JSON.parse('{"__proto__":{"body":"polluted"},"constructor":{"body":"polluted"},"semver":{"body":"ok"}}')
            let md = build({ packageNotes: evil })
            assert.strict.equal({}.body, undefined)
            assert.strict.ok(!md.includes('polluted') && md.includes('【semver 套件說明】\n\nok\n'), md)
        })

        it('不改動預設說明(PACKAGE_NOTES)與呼叫端傳入之物件; 連續呼叫互不影響', function() {
            let before = JSON.stringify(PACKAGE_NOTES)
            let keys = Object.keys(PACKAGE_NOTES)
            let input = { vue: { heading: '【H】', body: 'B' }, semver: { body: 'S' } }
            Object.freeze(input.vue)
            Object.freeze(input.semver)
            Object.freeze(input)
            let a = build({ packageNotes: input })
            assert.strict.ok(a.includes('【H】'))
            assert.strict.equal(JSON.stringify(PACKAGE_NOTES), before)
            assert.strict.deepStrictEqual(Object.keys(PACKAGE_NOTES), keys)
            assert.strict.equal(build({}), defaultMd) //上一次之自訂不殘留
        })

        it('截圖失敗之報告同樣附自訂說明', function() {
            let md = build({ packageNotes: { semver: { body: 'NG-S' } } }, fx.exsbomNg)
            assert.strict.ok(md.includes('【semver 套件說明】\n\nNG-S\n'), md)
        })

        it('自訂之 heading 與 body 原樣輸出, 不被改寫', function() {
            let body = '  前有空白\n| a | b |\n|---|---|\n末行  '
            let md = build({ packageNotes: { semver: { heading: '### 自訂 `標題`', body } } })
            assert.strict.ok(md.includes('### 自訂 `標題`\n\n  前有空白\n| a | b |\n|---|---|\n末行'), md)
        })

    })

    describe('equivalent to the current report (spec ④)', function() {

        //golden 取自修前 HEAD 之 buildReport 以同一夾具(test/tools/reportFixture.mjs)之產出, 使用端之系統名代換為中立假名「範例系統」
        let golden = (k) => fs.readFileSync(`./test/fixtures/report-restored-${k}.golden.md`, 'utf8')
        let restored = { systemName: '範例系統', packageNotes: { vue: restoredVue } }

        it('截圖成功: 給與原本等價之 systemName 與 packageNotes, 報告逐字等於現版產出', function() {
            assert.strict.equal(build(restored), golden('ok'))
        })

        it('截圖失敗: 同上', function() {
            assert.strict.equal(build(restored, fx.exsbomNg), golden('ng'))
        })

        it('只給 systemName(未還原 vue 說明)時: 與現版產出之差異僅在 vue 說明(通用事實保留, 使用端現況與規劃之句子移出)', function() {
            let md = build({ systemName: '範例系統' })
            let g = golden('ok')
            let a = md.split('\n')
            let b = g.split('\n')
            let diff = b.filter((l) => !a.includes(l))
            assert.strict.deepStrictEqual(diff, [
                '目前範例系統都使用 vue（2.7.16），此為 vue2 最新版。其被提報之漏洞主要是中低風險漏洞，詳情如下表 1：',
                '若欲修復此 2 漏洞，仍須待之後進行大規模之底層重構，才有辦法讓範例系統由 vue2 升 vue3 版。',
            ])
            //預設 vue 說明新增之句子(通用事實)
            assert.strict.deepStrictEqual(a.filter((l) => !b.includes(l)), ['vue2 最新版為 2.7.16，其被提報之漏洞主要是中低風險漏洞，詳情如下表 1：'])
        })

    })

})
