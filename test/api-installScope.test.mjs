import assert from 'assert'
import fs from 'fs'
import path from 'path'
import { npmInstall } from '../src/install.mjs'
import { computeUpdateList } from '../src/updatelist.mjs'
import { withEnv } from './tools/fakeBins.mjs'
import { fakeNpmRegistry } from './tools/fakeNpmRegistry.mjs'
import { scopePackages, scopeProject, scopeInstalled, scopeNotInstalled } from './tools/scopeFixture.mjs'


//建議w-scan-dep調整.md(Gitea #27, 主控裁定 2、5): 掃描範圍只算 dependencies(使用者裁定: 掃描對象為網頁前後端服務或編譯出之 app,
//開發與建置工具不在範圍)。隔離安裝只裝正式相依樹(npm install --omit=dev), 使 devDependencies 及其所附之執行檔不落地, syft 之各編目器
//(含不分正式或開發之 PE／Go binary 編目器)自然一致; 正式套件之對等相依、同時為正式套件之相依者照收; 待更新清單(updateList)隨之只剩正式相依樹。
//真實 npm 對本機假 registry(test/tools/fakeNpmRegistry.mjs, 夾具見 test/tools/scopeFixture.mjs), 不連外網; npm 快取改指本案暫存夾
describe('npmInstall scope (dependencies only)', function() {
    this.timeout(180000)

    let root = path.resolve('./test/_tmp/installScope')
    let port = 8997
    let reg = null
    let prj = path.join(root, 'prj')
    let nm = path.join(prj, 'node_modules')
    let installed = (name) => fs.existsSync(path.join(nm, name, 'package.json'))
    let version = (name) => JSON.parse(fs.readFileSync(path.join(nm, name, 'package.json'), 'utf8')).version

    before(async function() {
        fs.rmSync(root, { recursive: true, force: true })
        fs.mkdirSync(prj, { recursive: true })
        fs.writeFileSync(path.join(prj, 'package.json'), JSON.stringify(scopeProject))
        reg = await fakeNpmRegistry(port, scopePackages)
        await withEnv({
            npm_config_registry: reg.url,
            npm_config_cache: path.join(root, 'npm-cache'),
            npm_config_update_notifier: 'false',
        }, () => npmInstall(prj))
    })

    after(async function() {
        if (reg) await reg.close()
        fs.rmSync(root, { recursive: true, force: true, maxRetries: 5, retryDelay: 200 })
    })

    //spec: devDependencies 之開發與建置工具及其所附之執行檔不在掃描範圍(不落地, 不入 SBOM)
    it('devDependencies 及其只在開發樹之相依不落地', function() {
        for (let name of scopeNotInstalled) {
            assert.strict.equal(fs.existsSync(path.join(nm, name)), false, `${name} 不應被安裝`)
        }
    })

    //spec: dependencies 及其完整相依樹照收; 同時為正式套件之相依者(傳遞相依、對等相依)照收, 即使亦列於 devDependencies
    it('正式相依樹照收: 直接相依、傳遞相依(亦為開發工具之相依者)、正式套件之對等相依(亦列於 devDependencies 者與未列者)', function() {
        for (let name of scopeInstalled) {
            assert.strict.equal(installed(name), true, `${name} 應被安裝`)
        }
        //對等相依之版本為 devDependencies 所釘者, 與全量安裝時一致(SBOM 內之 npm 套件版本不因 --omit=dev 而改變)
        assert.strict.equal(version('peer-fw'), '1.0.0')
        assert.strict.equal(version('semver'), '7.0.0')
    })

    it('node_modules 之內容恰為正式相依樹', function() {
        let names = fs.readdirSync(nm).filter((n) => !n.startsWith('.')).sort()
        assert.strict.deepStrictEqual(names, scopeInstalled)
    })

    //spec(主控裁定 5): updateList 隨之只剩正式相依樹。風險套件 semver 同時被正式套件 prod-mid 與開發工具 dev-tool 引入, 引入路徑只應有 prod-mid
    it('待更新清單(updateList)之引入路徑只含正式相依樹', function() {
        let scan = { osv: { mdText: '' }, grype: { matches: [{ name: 'semver', version: '7.0.0', id: 'GHSA-test', severity: 'High', fixedIn: '7.5.2' }] } }
        let logs = []
        let ul = computeUpdateList(prj, scan, null, (m) => logs.push(m))
        let recs = [...ul.byOrigin.values()].flatMap((m) => [...m.values()])
        assert.strict.deepStrictEqual(logs, []) //npm ls 於缺少 devDependencies 之安裝樹仍得有效輸出
        assert.strict.deepStrictEqual(recs.map((r) => `${r.depName}->${r.leafName}@${r.leafVersion}`), ['prod-mid->semver@7.0.0'])
        assert.strict.deepStrictEqual(ul.cascades.map((c) => `${c.leaf}|${c.chainStr}`), ['semver@7.0.0|主系統'])
    })

})
