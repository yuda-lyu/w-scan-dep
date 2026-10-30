import assert from 'assert'
import fs from 'fs'
import path from 'path'
import { npmInstall } from '../src/install.mjs'
import { runSyft } from '../src/scan.mjs'
import ensureBins from '../src/ensureBins.mjs'


//建議w-scan-dep調整.md(Gitea #27, 主控裁定 2): 掃描範圍只算 dependencies 所提供者(程式碼與其所附之執行檔), devDependencies 之開發與建置工具不在範圍。
//syft 之 npm 編目器預設不收 dev 套件, 但 PE／Go binary 編目器掃描安裝所得之檔案, 不分正式或開發用, 故全量安裝時開發用套件所附之執行檔仍被編入 SBOM;
//隔離安裝改為 npm install --omit=dev 後, 開發用套件所附之執行檔不落地, 各編目器一致。
//連網(npm registry, 取 npm_config_registry 所指者)並用真實 syft(經 ensureBins 取得, 與 WScanDep.test.mjs 同); 夾具為真實小套件:
//  dependencies:    boxen@4.2.0(其相依 term-size@2.2.1 附 vendor/windows/term-size.exe, 正式套件所附之執行檔)
//  devDependencies: clipboardy@2.3.0(附 fallbacks/windows/clipboard_i686.exe、clipboard_x86_64.exe, 開發用套件所附之執行檔, 只在開發樹)
//                   term-size@2.2.1(同時為 boxen 之相依: 開發用之宣告不使正式樹內之它被排除)
describe('scan scope (real syft over the dependencies-only install)', function() {
    this.timeout(900000)

    let root = path.resolve('./test/_tmp/scanScope')
    let prj = path.join(root, 'prj')
    let scan = path.join(root, 'scan')
    let comps = null

    before(async function() {
        fs.rmSync(root, { recursive: true, force: true })
        fs.mkdirSync(prj, { recursive: true })
        fs.mkdirSync(scan, { recursive: true })
        fs.writeFileSync(path.join(prj, 'package.json'), JSON.stringify({
            name: 'scope-real',
            version: '1.0.0',
            dependencies: { boxen: '4.2.0' },
            devDependencies: { 'clipboardy': '2.3.0', 'term-size': '2.2.1' },
        }))
        let bins = await ensureBins({ names: 'syft.exe' })
        await npmInstall(prj)
        let { cdx } = await runSyft(bins['syft.exe'], prj, scan, () => {})
        comps = JSON.parse(fs.readFileSync(cdx, 'utf8')).components
    })

    after(function() {
        fs.rmSync(root, { recursive: true, force: true, maxRetries: 5, retryDelay: 200 })
    })

    let found = (c) => ((c.properties || []).find((p) => /foundBy$/.test(p.name)) || {}).value
    let names = () => comps.filter((c) => c.type !== 'file').map((c) => c.name)

    //spec: dependencies 所提供之執行檔(正式套件所附者)照收
    it('正式套件所附之執行檔仍在 SBOM(term-size.exe, 為 boxen 之相依)', function() {
        let exe = comps.filter((c) => c.type === 'application' && c.name === 'term-size')
        assert.strict.equal(exe.length, 1, JSON.stringify(names()))
        assert.strict.equal(found(exe[0]), 'pe-binary-package-cataloger')
        assert.strict.ok(comps.some((c) => c.type === 'library' && c.name === 'term-size' && c.version === '2.2.1'))
        assert.strict.ok(comps.some((c) => c.type === 'library' && c.name === 'boxen' && c.version === '4.2.0'))
    })

    //spec: devDependencies 所附之執行檔(開發與建置工具)不在範圍, 不入 SBOM
    it('開發用套件所附之執行檔不在 SBOM(clipboardy 之 clipboard_*.exe), 該套件亦不在', function() {
        let bad = comps.filter((c) => /clipboard/i.test(c.name))
        assert.strict.deepStrictEqual(bad.map((c) => `${c.type}:${c.name}`), [], '開發用套件及其執行檔不應出現')
        assert.strict.deepStrictEqual(comps.filter((c) => c.type === 'file' && /clipboardy/i.test(c.name)), [])
        //開發樹獨有之相依(arch 為 clipboardy 之相依)亦不在
        assert.strict.equal(names().includes('arch'), false)
    })

    //spec: 正式樹內之套件不因同時列於 devDependencies 而被排除(如 vue 為正式套件之對等相依且列於 devDependencies)
    it('SBOM 之 npm 套件即正式相依樹(boxen 與其傳遞相依, 不含開發樹獨有者)', function() {
        let libs = comps.filter((c) => c.type === 'library').map((c) => c.name)
        for (let n of ['boxen', 'term-size', 'chalk', 'widest-line', 'string-width']) {
            assert.strict.ok(libs.includes(n), `${n} 應在 SBOM: ${libs.join(',')}`)
        }
        for (let n of ['clipboardy', 'arch', 'execa', 'is-wsl']) {
            assert.strict.equal(libs.includes(n), false, `${n} 不應在 SBOM`)
        }
    })

})
