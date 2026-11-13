import fs from 'fs'
import path from 'path'
import assert from 'assert'


//R-PW-ONLY(w-playwright 設計 §8.4、F9): Chromium 系瀏覽器之啟動一律經 w-playwright, 本套件不直接匯入 playwright / playwright-core, 且不宣告其相依。
//不啟動任何瀏覽器; 以檔案掃描(src、test、toolg 之 .mjs/.js, 含動態 import 與 require)與 package.json 判定。
//起因: Chromium 系瀏覽器每啟動一個新根行程即以錯誤密碼替目前 Windows 使用者呼叫一次 LogonUser, 10 分鐘內 10 次即鎖帳號; w-playwright 於每次啟動合併出恰一串含守門功能之 --disable-features。
describe('unit-pwOnly (R-PW-ONLY)', function() {
    this.timeout(60000)

    //與 w-playwright 規則帳本 R-PW-ONLY 之盤點正則相同(靜態 from、動態 import()、require())
    let reDirect = /(from\s+|import\(\s*|require\(\s*)['"`]playwright(-core)?['"`/]/
    let reViaWpw = /from\s+['"]w-playwright['"]/
    let reLaunchSite = /wpw\.(launchChromium|launchChromiumPersistent)\(/g
    let skipDirs = new Set(['node_modules', '_tmp', 'output', 'dist', 'tmp'])

    let walk = (dir, out) => {
        for (let ent of fs.readdirSync(dir, { withFileTypes: true })) {
            let p = path.join(dir, ent.name)
            if (ent.isDirectory()) {
                if (!skipDirs.has(ent.name)) walk(p, out)
            }
            else if (/\.(mjs|js)$/.test(ent.name)) {
                out.push(p)
            }
        }
        return out
    }
    let files = []
    for (let d of ['src', 'test', 'toolg']) walk(path.resolve(d), files)
    let read = (p) => fs.readFileSync(p, 'utf8')

    it(`should detect the direct imports the rule forbids and accept the w-playwright import (the regex itself)`, function() {
        //spec: R-PW-ONLY 盤點正則須抓得到靜態、動態、require 三種直接匯入, 且不誤判 w-playwright
        //樣本以插值組字, 使本檔原始碼不含可被同一正則命中之字面(否則下列掃描會命中本檔)
        let pw = 'play' + 'wright'
        for (let s of [
            `import { chromium } from '${pw}'`,
            `import { chromium } from "${pw}-core"`,
            `const { chromium } = await import('${pw}')`,
            `const pw = require("${pw}-core")`,
            `import x from '${pw}-core/lib/x.js'`,
        ]) {
            assert.strict.equal(reDirect.test(s), true, s)
        }
        for (let s of [
            `import wpw from 'w-${pw}'`,
            `import wpw from "w-${pw}"`,
        ]) {
            assert.strict.equal(reDirect.test(s), false, s)
            assert.strict.equal(reViaWpw.test(s), true, s)
        }
    })

    it(`should scan a non-empty set of files that includes the launch site, so that a zero result is not an empty scan`, function() {
        //防空集合: 掃描範圍壞掉時結果也是 0, 故須先確認掃到了檔案, 且啟動點檔案(src/exsbom.mjs)在內並以 w-playwright 匯入
        assert.strict.ok(files.length >= 30, `scanned ${files.length} files`)
        let ex = path.resolve('src/exsbom.mjs')
        assert.strict.ok(files.includes(ex))
        assert.strict.equal(reViaWpw.test(read(ex)), true)
    })

    it(`should not import playwright or playwright-core in src, test and toolg (0 hits)`, function() {
        let hits = []
        for (let p of files) {
            let lines = read(p).split(/\r?\n/)
            lines.forEach((l, i) => {
                if (reDirect.test(l)) hits.push(`${path.relative(process.cwd(), p)}:${i + 1}: ${l.trim()}`)
            })
        }
        assert.strict.deepStrictEqual(hits, [])
    })

    it(`should not declare playwright or playwright-core in package.json and should depend on w-playwright (^1.0.1 or later)`, function() {
        let pkg = JSON.parse(read(path.resolve('package.json')))
        for (let k of ['dependencies', 'devDependencies', 'peerDependencies', 'optionalDependencies']) {
            let m = pkg[k] || {}
            assert.strict.equal('playwright' in m, false, `${k}.playwright`)
            assert.strict.equal('playwright-core' in m, false, `${k}.playwright-core`)
        }
        assert.strict.equal(typeof pkg.dependencies['w-playwright'], 'string')
        assert.strict.match(pkg.dependencies['w-playwright'], /^\^1\.0\.\d+$|^\^1\.[1-9]\d*\.\d+$/)
        //安裝實際取得之 w-playwright 版本不低於 1.0.1(自帶 playwright-core 精確版, 守門與版本比對於其內)
        let inst = JSON.parse(read(path.resolve('node_modules/w-playwright/package.json')))
        let [a, b, c] = inst.version.split('.').map(Number)
        assert.strict.equal(a > 1 || (a === 1 && (b > 0 || c >= 1)), true, inst.version)
    })

    it(`should have exactly one launch site in src (src/exsbom.mjs), which the wiring test in api-wsdEntry.test.mjs covers`, function() {
        //站點全集: 新增第二個啟動點時須同時補其接線測試(R-PW-WIRING), 故此處釘住數量與位置
        let sites = []
        for (let p of files.filter((f) => f.startsWith(path.resolve('src') + path.sep))) {
            let lines = read(p).split(/\r?\n/)
            lines.forEach((l, i) => {
                if (/^\s*\/\//.test(l)) return //註解行不算
                if ((l.match(reLaunchSite) || []).length) sites.push(`${path.relative(process.cwd(), p).replace(/\\/g, '/')}:${i + 1}`)
            })
        }
        assert.strict.equal(sites.length, 1, sites.join('\n'))
        assert.strict.ok(sites[0].startsWith('src/exsbom.mjs:'), sites[0])
    })

})
