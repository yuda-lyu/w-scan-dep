import assert from 'assert'
import vm from 'vm'
import { parseWsdOpt, resetWarned } from '../src/scanOpt.mjs'
import * as moduleNs from './tools/reportFixture.mjs'


//2026-11-06 sd330: WScanDep 第三參數 opt(systemName、packageNotes、debug、funLog)之檢測
//規格: dspec〈輸入參數之檢測機制〉§4 V4(opt 本身: undefined/null 視為未給, 其他非一般物件無效)、V5/K3(各鍵給了而非預期者視為未給、改用預設, 不報錯)、
//V6(已移除之鍵 fdTools 給了即無效)、V7(未宣告之鍵忽略)、V9(不改寫呼叫端之 opt)、V11(每鍵只讀一次, 讀取拋錯即無效)、K3 debug(true 時警告, 固定詞彙、不含傳入之值、每行程每原因一次)、V19 訊息格式
describe('parseWsdOpt (WScanDep third argument)', function() {

    let warns = []
    let warnBak = null

    beforeEach(function() {
        resetWarned()
        warns = []
        warnBak = console.warn
        console.warn = (m) => warns.push(String(m))
    })

    afterEach(function() {
        console.warn = warnBak
    })

    let SECRET = 'SECRET-VALUE-0xBEEF'

    function boom(msg) {
        throw new Error(msg)
    }

    describe('opt itself (V4)', function() {

        for (let [label, v] of [['undefined', undefined], ['null', null], ['{}', {}], ['Object.create(null)', Object.create(null)]]) {
            it(`${label}: 視為未給, 取預設(系統名為空字串=中立說法, 無自訂說明)`, function() {
                let r = parseWsdOpt(v)
                assert.strict.equal(r.systemName, '')
                assert.strict.deepStrictEqual({ ...r.packageNotes }, {})
                assert.strict.deepStrictEqual(warns, [])
            })
        }

        it('跨 realm 建立之一般物件有效(不以 Object.prototype 同一性判定)', function() {
            let o = vm.runInNewContext('({ systemName: "範例系統", packageNotes: { semver: { body: "B" } } })')
            let r = parseWsdOpt(o)
            assert.strict.equal(r.systemName, '範例系統')
            assert.strict.deepStrictEqual(Object.keys(r.packageNotes), ['semver'])
        })

        let revoked = (() => {
            let p = Proxy.revocable({}, {})
            p.revoke()
            return p.proxy
        })()
        for (let [label, v] of [['字串', 'x'], ['數字', 1], ['布林 true', true], ['布林 false', false], ['陣列', []], ['Date', new Date()], ['Map', new Map()], ['函數', () => ({})], ['class 實例', new (class A {})()], ['包裝物件', Object('x')], ['Symbol', Symbol('s')], ['BigInt', 1n], ['模組命名空間物件(原型 null 但非一般物件)', moduleNs], ['以 Symbol.toStringTag 偽裝', { [Symbol.toStringTag]: 'X' }], ['已撤銷之 Proxy', revoked]]) {
            it(`${label}: 無效, 拋 invalid opt: must be a plain object, 且訊息不含傳入之值`, function() {
                let err = null
                try {
                    parseWsdOpt(v)
                }
                catch (e) {
                    err = e
                }
                assert.strict.ok(err instanceof Error, label)
                assert.strict.equal(err.message, 'invalid opt: must be a plain object')
            })
        }

        it('不改寫呼叫端之 opt(凍結之 opt 可通過; 回傳新物件)', function() {
            let notes = { semver: { body: 'B' } }
            let opt = Object.freeze({ systemName: ' S ', packageNotes: Object.freeze(notes) })
            Object.freeze(notes.semver)
            let r = parseWsdOpt(opt)
            assert.strict.equal(r.systemName, 'S')
            assert.strict.notEqual(r.packageNotes, notes)
            assert.strict.equal(opt.systemName, ' S ')
        })

    })

    describe('removed key opt.fdTools (V6)', function() {

        for (let v of ['C:/x/tools', '', 0, false, {}, ['a'], 'x']) {
            it(`fdTools 為 ${JSON.stringify(v)}: 拋錯, 指向 W_BIN_CACHE`, function() {
                let err = null
                try {
                    parseWsdOpt({ fdTools: v })
                }
                catch (e) {
                    err = e
                }
                assert.strict.ok(err instanceof Error)
                assert.strict.equal(err.message, 'invalid opt.fdTools: removed, use env W_BIN_CACHE (see README 外部執行檔)')
            })
        }

        it('其餘鍵皆有效時 fdTools 仍使整個 opt 無效', function() {
            assert.strict.throws(() => parseWsdOpt({ systemName: '範例系統', fdTools: 'x' }), /opt\.fdTools: removed/)
        })

        it('fdTools 為 undefined 或 null 視為未給(V5), 不拋錯', function() {
            assert.strict.doesNotThrow(() => parseWsdOpt({ fdTools: undefined }))
            assert.strict.doesNotThrow(() => parseWsdOpt({ fdTools: null }))
        })

        //V11: 讀取拋錯(存取器、Proxy)即無效, 不得當成「未給」而放行已移除之鍵
        it('fdTools 之取值拋錯(存取器、Proxy get)視為無效: 拋錯, 不放行', function() {
            let opt = {}
            Object.defineProperty(opt, 'fdTools', { enumerable: true, get: () => boom(SECRET) })
            assert.strict.throws(() => parseWsdOpt(opt), (e) => e.message === 'invalid opt.fdTools: removed, use env W_BIN_CACHE (see README 外部執行檔)')
            let px = new Proxy({}, { get: (t, k, r) => (k === 'fdTools' ? boom(SECRET) : Reflect.get(t, k, r)) })
            assert.strict.throws(() => parseWsdOpt(px), (e) => e.message === 'invalid opt.fdTools: removed, use env W_BIN_CACHE (see README 外部執行檔)')
        })

    })

    describe('opt.systemName (S1: 單行非空白字串)', function() {

        it('有效: 去前後空白後回傳', function() {
            assert.strict.equal(parseWsdOpt({ systemName: '範例系統' }).systemName, '範例系統')
            assert.strict.equal(parseWsdOpt({ systemName: ' \t範例 系統\u3000' }).systemName, '範例 系統')
        })

        for (let [label, v] of [['null', null], ['空字串', ''], ['純空白', ' \t\u3000'], ['數字', 123], ['布林', true], ['物件', {}], ['陣列', ['a']], ['函數', () => 'a'], ['包裝物件', Object('a')], ['含 LF', 'a\nb'], ['含 CR', 'a\rb'], ['含 U+2028', 'a\u2028b'], ['含 U+2029', 'a\u2029b'], ['含 U+0085', 'a\u0085b'], ['含 NUL', 'a\u0000b'], ['含 DEL', 'a\u007fb'], ['Symbol', Symbol('s')], ['BigInt', 1n]]) {
            it(`${label}: 視為未給(中立說法), 不拋錯`, function() {
                assert.strict.equal(parseWsdOpt({ systemName: v }).systemName, '')
            })
        }

        it('取值拋錯(getter)視為無效, 不拋錯', function() {
            let opt = {}
            Object.defineProperty(opt, 'systemName', { enumerable: true, get: () => boom(SECRET) })
            assert.strict.equal(parseWsdOpt(opt).systemName, '')
        })

        it('每個鍵只讀一次(V11)', function() {
            let n = 0
            let opt = {}
            Object.defineProperty(opt, 'systemName', {
                enumerable: true,
                get: () => {
                    n++
                    return '範例系統'
                },
            })
            assert.strict.equal(parseWsdOpt(opt).systemName, '範例系統')
            assert.strict.equal(n, 1)
        })

    })

    describe('opt.packageNotes', function() {

        it('有效 entry 正規化為 { heading?, body }(heading 無效則不帶), 保持給定順序, 只含有效者', function() {
            let r = parseWsdOpt({
                packageNotes: {
                    b: { heading: ' H ', body: 'B1', extra: 'x' },
                    a: { body: 'B2' },
                    bad1: { body: '' },
                    bad2: 'text',
                    bad3: { heading: 'ok', body: 5 },
                    c: { heading: 'two\nlines', body: 'B3' },
                },
            })
            assert.strict.deepStrictEqual(Object.keys(r.packageNotes), ['b', 'a', 'c'])
            assert.strict.deepStrictEqual({ ...r.packageNotes.b }, { heading: ' H ', body: 'B1' }) //heading、body 原樣, 不去空白(原樣輸出)
            assert.strict.deepStrictEqual({ ...r.packageNotes.a }, { body: 'B2' })
            assert.strict.deepStrictEqual({ ...r.packageNotes.c }, { body: 'B3' })
        })

        for (let [label, v] of [['null', null], ['字串', 'x'], ['數字', 1], ['陣列', [{ body: 'x' }]], ['Map', new Map()], ['Date', new Date()], ['函數', () => ({})], ['class 實例', new (class A {})()]]) {
            it(`${label}: 視為未給, 不拋錯`, function() {
                assert.strict.deepStrictEqual({ ...parseWsdOpt({ packageNotes: v }).packageNotes }, {})
            })
        }

        it('取值拋錯(getter、Proxy ownKeys)之 packageNotes 或 entry 視為無效, 不拋錯', function() {
            let opt = {}
            Object.defineProperty(opt, 'packageNotes', { enumerable: true, get: () => boom(SECRET) })
            assert.strict.deepStrictEqual({ ...parseWsdOpt(opt).packageNotes }, {})
            let px = new Proxy({}, { ownKeys: () => boom(SECRET) })
            assert.strict.deepStrictEqual({ ...parseWsdOpt({ packageNotes: px }).packageNotes }, {})
            let bad = {}
            Object.defineProperty(bad, 'body', { enumerable: true, get: () => boom(SECRET) })
            let r = parseWsdOpt({ packageNotes: { x: bad, y: { body: 'ok' } } })
            assert.strict.deepStrictEqual(Object.keys(r.packageNotes), ['y'])
        })

        it('以 __proto__ 為鍵: 不污染原型, 結果物件之原型不被改', function() {
            let evil = JSON.parse('{"__proto__":{"body":"polluted"},"semver":{"body":"ok"}}')
            let r = parseWsdOpt({ packageNotes: evil })
            assert.strict.equal({}.body, undefined)
            assert.strict.equal(Object.getPrototypeOf(r.packageNotes), null)
            assert.strict.equal(r.packageNotes.semver.body, 'ok')
            assert.strict.equal(Object.prototype.hasOwnProperty.call(r.packageNotes, '__proto__'), true) //作為一般鍵保存(僅是不匹配任何套件名), 不改變原型
        })

    })

    describe('opt.debug 與 opt.funLog (K3: 警告固定詞彙、不含傳入之值、每行程每原因一次)', function() {

        it('debug 未給或非 true: 靜默(不警告)', function() {
            for (let d of [undefined, false, 'true', 1, {}, null]) {
                parseWsdOpt({ debug: d, systemName: 123, packageNotes: 5, funLog: 'x' })
            }
            assert.strict.deepStrictEqual(warns, [])
        })

        it('debug 為 true: 非預期之鍵各警告一次(console.warn), 內容為固定詞彙, 不含傳入之值', function() {
            parseWsdOpt({ debug: true, systemName: SECRET + '\n1', packageNotes: SECRET + 2 })
            assert.strict.deepStrictEqual(warns, [
                '[w-scan-dep WScanDep] invalid opt.systemName: must be a single-line non-blank string, using default (neutral wording)',
                '[w-scan-dep WScanDep] invalid opt.packageNotes: must be a plain object, using default notes only',
            ])
            for (let w of warns) assert.strict.ok(!w.includes(SECRET), w)
            //同一原因第二次不再警告
            parseWsdOpt({ debug: true, systemName: SECRET + '\n1', packageNotes: SECRET + 2 })
            assert.strict.equal(warns.length, 2)
        })

        it('entry 非預期: 各原因警告一次, 不含套件名與值', function() {
            parseWsdOpt({ debug: true, packageNotes: { [SECRET]: 'text', b: { heading: SECRET + '\nx', body: 'B' }, c: { body: SECRET, bad: 1 }, d: { body: 9 } } })
            assert.strict.deepStrictEqual(warns, [
                '[w-scan-dep WScanDep] invalid opt.packageNotes entry: must be a plain object with a non-blank string body (heading optional), entry ignored',
                '[w-scan-dep WScanDep] invalid opt.packageNotes entry heading: must be a single-line non-blank string, using default heading',
            ])
            for (let w of warns) assert.strict.ok(!w.includes(SECRET), w)
        })

        it('未宣告之鍵: 忽略(V7), debug 為 true 時提示一次, 不含鍵名', function() {
            let r = parseWsdOpt({ debug: true, [SECRET]: 1, sysName: '拼錯之鍵' })
            assert.strict.equal(r.systemName, '')
            assert.strict.deepStrictEqual(warns, ['[w-scan-dep WScanDep] unknown opt keys ignored (known: systemName, packageNotes, debug, funLog)'])
            assert.strict.deepStrictEqual(parseWsdOpt({ [SECRET]: 1 }).systemName, '') //debug 未開: 靜默
        })

        it('已宣告之鍵(含 debug、funLog)與 fdTools 之外皆為合法, 不觸發未知鍵提示', function() {
            parseWsdOpt({ debug: true, funLog: () => {}, systemName: 'S', packageNotes: {} })
            assert.strict.deepStrictEqual(warns, [])
        })

        it('有 funLog(函數)則交 funLog(msg, info), 不用 console.warn; funLog 拋錯不影響', function() {
            let got = []
            parseWsdOpt({ debug: true, systemName: 5, funLog: (m, info) => got.push([m, info]) })
            assert.strict.deepStrictEqual(got, [['[w-scan-dep WScanDep] invalid opt.systemName: must be a single-line non-blank string, using default (neutral wording)', { fn: 'WScanDep', reason: 'invalid', key: 'opt.systemName' }]])
            assert.strict.deepStrictEqual(warns, [])
            resetWarned()
            assert.strict.doesNotThrow(() => parseWsdOpt({ debug: true, systemName: 5, funLog: () => boom(SECRET) }))
        })

        //funLog 為 async 函數(回傳 rejected promise)時, 其 rejection 一律忽略, 否則成為 unhandledRejection 而使呼叫端行程崩潰; 以短暫觀察窗斷言「沒有發生」(否定斷言)
        it('funLog 回傳 rejected promise: 不成為 unhandledRejection', async function() {
            let seen = []
            let h = (e) => seen.push(e)
            process.on('unhandledRejection', h)
            try {
                parseWsdOpt({ debug: true, systemName: 5, funLog: () => Promise.reject(new Error(SECRET)) })
                await new Promise((resolve) => setImmediate(resolve))
                await new Promise((resolve) => setImmediate(resolve))
            }
            finally {
                process.off('unhandledRejection', h)
            }
            assert.strict.deepStrictEqual(seen, [])
        })

        it('funLog 非函數: 警告該鍵並改用 console.warn(其餘警告亦走 console.warn)', function() {
            parseWsdOpt({ debug: true, systemName: 5, funLog: 'x' })
            assert.strict.deepStrictEqual(warns, [
                '[w-scan-dep WScanDep] invalid opt.funLog: must be a function, using console.warn',
                '[w-scan-dep WScanDep] invalid opt.systemName: must be a single-line non-blank string, using default (neutral wording)',
            ])
        })

        it('resetWarned 後可再警告(去重表為行程層級)', function() {
            parseWsdOpt({ debug: true, systemName: 5 })
            resetWarned()
            parseWsdOpt({ debug: true, systemName: 5 })
            assert.strict.equal(warns.length, 2)
        })

    })

})
