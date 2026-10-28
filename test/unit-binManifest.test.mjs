import fs from 'fs'
import path from 'path'
import assert from 'assert'
import { execSync, spawnSync } from 'child_process'
import fsEnsureBins from 'wsemi/src/fsEnsureBins.mjs'
import { TOOLS } from '../src/config.mjs'


//規格: 外部執行檔之存放下載校驗與離線(制式規格) S1、S3、S5、M1、M2、M3、M5、§8 T1、T2、§9 rollup
//本套件為主幹模式(floating)之廠商檔: repo內無執行檔, 故T2(實檔與清單一致)改為驗清單之網址為版本標籤之資產網址、非releases/latest
describe(`bin/manifest.json`, function() {
    this.timeout(180000)

    let read = () => JSON.parse(fs.readFileSync('bin/manifest.json', 'utf8')) //於it內讀: 缺清單時單案失敗而非整檔載入失敗
    let fdt = path.resolve('./test/_tmp/binManifest')

    after(function() {
        fs.rmSync(fdt, { recursive: true, force: true, maxRetries: 5, retryDelay: 200 })
    })

    it(`should be a floating-mode manifest of this package listing exactly the tools of src/config.mjs (M1, M5)`, function() {
        let m = read()
        assert.strict.equal(m.schema, 1)
        assert.strict.equal(m.pkg, 'w-scan-dep')
        assert.strict.equal(m.mode, 'floating')
        assert.strict.equal(m.repo, 'yuda-lyu/w-scan-dep')
        assert.strict.deepStrictEqual(m.files.map((f) => f.name), TOOLS.map((t) => t.exeName))
        assert.strict.equal(m.commit, undefined) //廠商檔不鏡像入repo, 無提交可釘
    })

    it(`should pass the schema check of fsEnsureBins and list every tool as missing when offline with an empty cache (M1, M2)`, async function() {
        let m = read()
        let err = null
        try {
            await fsEnsureBins('bin/manifest.json', { pkgRoot: '.', cacheDir: path.join(fdt, 'cache'), mirror: '', offline: true })
        }
        catch (e) {
            err = e
        }
        //離線且快取為空: 清單有效時為E_OFFLINE_MISSING(缺檔), 清單無效時為E_MANIFEST; 不連網
        assert.strict.equal(err && err.code, 'E_OFFLINE_MISSING', err && err.message)
        assert.strict.deepStrictEqual(err.missing.map((v) => v.name), m.files.map((f) => f.name))
    })

    it(`should point every file at the tagged asset of the vendor repo, never releases/latest, with sha256 and size of the archive and of the extracted exe (M2, M3, S3)`, function() {
        let m = read()
        for (let f of m.files) {
            let t = TOOLS.find((v) => v.exeName === f.name)
            let r = /^https:\/\/github\.com\/([^/]+\/[^/]+)\/releases\/download\/(v[0-9][0-9A-Za-z.-]*)\/([A-Za-z0-9._-]+)$/.exec(f.url)
            assert.strict.notEqual(r, null, `${f.name}: ${f.url}`) //M2: 版本標籤之資產網址
            assert.strict.equal(r[1], t.repo, f.name) //廠商repo同src/config.mjs(報告引用處)
            assert.strict.equal(/latest/.test(f.url), false, f.name)
            assert.strict.equal(f.path, undefined, f.name) //S3: 廠商檔不鏡像, 無repo內路徑
            assert.strict.equal(f.parts, undefined, f.name)
            assert.strict.match(f.sha256, /^[0-9a-f]{64}$/, f.name)
            assert.strict.equal(Number.isSafeInteger(f.size) && f.size > 0, true, f.name)
            if (/\.zip$/.test(r[3])) {
                //壓縮檔: 解出之執行檔另記一組, 且與壓縮檔之雜湊不同
                assert.strict.equal(f.extract.type, 'zip', f.name)
                assert.strict.equal(f.extract.member, f.name, f.name)
                assert.strict.match(f.extract.sha256, /^[0-9a-f]{64}$/, f.name)
                assert.strict.notEqual(f.extract.sha256, f.sha256, f.name)
                assert.strict.equal(f.extract.size > f.size, true, f.name)
            }
            else {
                assert.strict.equal(f.extract, undefined, f.name)
                assert.strict.equal(r[3].endsWith('.exe'), true, f.name)
            }
            //M3: note寫明核對依據(廠商公告之checksums, 或首次下載自算與日期)
            assert.strict.match(f.note, /^v[0-9][0-9A-Za-z.-]*: (SHA-256依廠商公告之\S+核對|廠商未公告checksums,首次下載自算SHA-256\(\d{4}-\d{2}-\d{2}\))/, f.name)
            assert.strict.equal(f.note.startsWith(`${r[2]}:`), true, `${f.name}: note之版本須同網址之標籤`)
        }
    })

    it(`should keep only manifest.json in bin/ (no vendor binary is mirrored into the repo) (S3)`, function() {
        assert.strict.deepStrictEqual(fs.readdirSync('bin'), ['manifest.json'])
    })

    it(`should not pack external executables into the npm package, only bin/manifest.json, even with decoy files lying around (S1, S5, T1)`, function() {
        //誘餌檔: 缺少對應之忽略規則時, 這些檔確定會進包而使本案變紅(不依賴他案是否恰留下副本)
        let decoys = [
            'bin/__decoy__.exe',
            'bin/__decoy__.zip.001',
            'bin-cache/aa/__decoy__.exe',
            'test/_tmp/__decoy__/__decoy__.exe',
        ]
        for (let p of decoys) {
            assert.strict.equal(fs.existsSync(p), false, `decoy already exists: ${p}`)
        }
        //只刪自己放的誘餌檔與自己建立的空資料夾(bin-cache/ 可能已有真實快取, 不可整夾刪除)
        let made = []
        let madeDirs = []
        let fps = null
        try {
            for (let p of decoys) {
                let missing = []
                for (let d = path.dirname(p); !fs.existsSync(d); d = path.dirname(d)) {
                    missing.push(d)
                }
                fs.mkdirSync(path.dirname(p), { recursive: true })
                madeDirs.push(...missing)
                fs.writeFileSync(p, 'MZ-decoy')
                made.push(p)
            }
            let r = JSON.parse(execSync('npm pack --dry-run --json', { encoding: 'utf8', windowsHide: true }))
            let info = Array.isArray(r) ? r[0] : Object.values(r)[0] //npm 11以前為陣列, npm 12起為以套件名為鍵之物件
            fps = info.files.map((v) => v.path)
        }
        finally {
            for (let p of made) {
                fs.rmSync(p, { force: true })
            }
            for (let d of madeDirs.sort((a, b) => b.length - a.length)) { //深層先
                try {
                    fs.rmdirSync(d) //非空即拋錯, 不刪他人之檔
                }
                catch (e) {} // eslint-disable-line no-unused-vars
            }
        }
        assert.strict.deepStrictEqual(fps.filter((v) => /\.(exe|dll|msi|zip|7z|\d{3})$/i.test(v)), [])
        assert.strict.deepStrictEqual(fps.filter((v) => v.startsWith('bin/') || v.startsWith('bin-cache/')), ['bin/manifest.json'])
        assert.strict.equal(fps.some((v) => v.startsWith('test/_tmp/')), false)
        assert.strict.equal(fps.some((v) => v.startsWith('sgud/')), false)
        for (let p of ['src/ensureBins.mjs', 'src/toolVersions.mjs', 'src/WScanDep.mjs', 'bin/manifest.json', 'package.json']) {
            assert.strict.equal(fps.includes(p), true, p)
        }
        assert.strict.equal(fps.includes('src/download.mjs'), false) //自寫之下載邏輯已移除
    })

    it(`should ignore the cache and the test scratch folder in git, but not bin/manifest.json (S5)`, function() {
        let ignored = (p) => spawnSync('git', ['check-ignore', '-q', p], { windowsHide: true }).status === 0
        assert.strict.equal(ignored('bin-cache/aa/syft.exe'), true)
        assert.strict.equal(ignored('test/_tmp/x/y.exe'), true)
        assert.strict.equal(ignored('bin/manifest.json'), false)
    })

    it(`should list url, crypto, stream, stream/promises and os as external and global in the rollup config, as the bundled wsemi needs them (§9)`, function() {
        let text = fs.readFileSync('toolg/gDistRollup.mjs', 'utf8')
        let block = (key) => {
            let r = new RegExp(`${key}:\\s*[\\[{]([\\s\\S]*?)[\\]}],?\\s*(?:\\n\\s*(?:globals|external)|\\n\\}\\))`).exec(text)
            return r ? r[1] : ''
        }
        for (let key of ['globals', 'external']) {
            let b = block(key)
            for (let n of ['url', 'crypto', 'stream', 'stream/promises', 'os']) {
                assert.strict.equal(new RegExp(`['"]${n}['"]`).test(b), true, `${key} lacks ${n}`)
            }
        }
    })

})
