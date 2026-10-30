import assert from 'assert'
import fs from 'fs'
import path from 'path'
import { npmInstall } from '../src/install.mjs'
import { withEnv } from './tools/fakeBins.mjs'
import { fakeNpmRegistry } from './tools/fakeNpmRegistry.mjs'
import { scopePackages, scopeProject, scopeInstalled, scopeNotInstalled } from './tools/scopeFixture.mjs'


//建議w-scan-dep調整.md(Gitea #27)之主控裁定(run02): result.json 之 scope: 'dependencies' 是報告引用之依據, 必須為真, 呼叫端之 npm 設定不得使範圍失真。
//npm 以 include 優先於 omit: 環境變數 npm_config_include=dev(或已棄用別名 production=false、dev=true、also=dev)會抵消 --omit=dev(npm 12.1.0 實測)。
// 1) 隔離安裝之子行程環境移除上述環境變數(只動子行程副本, 不改 process.env)
// 2) 呼叫端專案之 .npmrc 不會被讀到(npm 之專案設定檔只取安裝目錄處)
// 3) 來自設定檔(使用者層、全域層、安裝目錄內 .npmrc)而環境變數無從移除者, 由安裝後驗證攔下: 有 dev 套件落地即拋錯(fail-closed)
//真實 npm 對本機假 registry(夾具見 test/tools/scopeFixture.mjs), 不連外網; npm 快取改指本案暫存夾; 設定檔路徑以 npm_config_userconfig／globalconfig 指向本案暫存夾, 不動使用者之 ~/.npmrc
describe('npmInstall scope vs. caller npm settings', function() {
    this.timeout(180000)

    let root = path.resolve('./test/_tmp/installScopeEnv')
    let port = 8999
    let reg = null
    let seq = 0

    let baseEnv = () => ({
        npm_config_registry: reg.url,
        npm_config_cache: path.join(root, 'npm-cache'),
        npm_config_update_notifier: 'false',
    })
    //每案一個全新安裝資料夾(含 package.json 與 files 指定之檔)
    let mkPrj = (files = {}) => {
        let d = path.join(root, `prj${++seq}`)
        fs.mkdirSync(d, { recursive: true })
        fs.writeFileSync(path.join(d, 'package.json'), JSON.stringify(scopeProject))
        for (let [f, c] of Object.entries(files)) fs.writeFileSync(path.join(d, f), c)
        return d
    }
    let installedNames = (d) => fs.readdirSync(path.join(d, 'node_modules')).filter((n) => !n.startsWith('.')).sort()
    let rejected = (d, env) => withEnv({ ...baseEnv(), ...env }, () => npmInstall(d).then(() => null, (e) => e))

    before(async function() {
        fs.rmSync(root, { recursive: true, force: true })
        fs.mkdirSync(root, { recursive: true })
        reg = await fakeNpmRegistry(port, scopePackages)
    })

    after(async function() {
        if (reg) await reg.close()
        fs.rmSync(root, { recursive: true, force: true, maxRetries: 5, retryDelay: 200 })
    })

    //spec(run02 裁定 1): 呼叫端環境設了會抵消 --omit=dev 之 npm 設定時, dev 套件及其執行檔仍不落地; 子行程環境之副本被移除, process.env 不變
    for (let [k, v] of [
        ['npm_config_include', 'dev'],
        ['NPM_CONFIG_INCLUDE', 'dev'], //前綴與鍵名不分大小寫, npm 一律當設定讀入
        ['npm_config_production', 'false'],
        ['npm_config_dev', 'true'],
        ['npm_config_also', 'dev'],
        ['npm_config_also', 'development'],
    ]) {
        it(`呼叫端環境 ${k}=${v} 下: devDependencies 仍不落地, 正式相依樹照收, 呼叫端之 process.env 不被改動`, async function() {
            let d = mkPrj()
            let kept = await withEnv({ ...baseEnv(), [k]: v }, async () => {
                await npmInstall(d)
                return process.env[k]
            })
            assert.strict.equal(kept, v, '呼叫端 process.env 之該項不應被移除')
            for (let name of scopeNotInstalled) {
                assert.strict.equal(fs.existsSync(path.join(d, 'node_modules', name)), false, `${name} 不應被安裝`)
            }
            assert.strict.deepStrictEqual(installedNames(d), scopeInstalled)
        })
    }

    //spec(run02 裁定 1): 隔離資料夾內不會讀到呼叫端專案之 .npmrc 之 include 設定。呼叫端專案(含 package.json 與 .npmrc)為上層, 安裝目錄為其內之子夾(同 fdOut 位於專案內之形態)
    it('呼叫端專案(上層)之 .npmrc 內 include[]=dev 不被讀到: devDependencies 仍不落地', async function() {
        let top = path.join(root, `caller${++seq}`)
        fs.mkdirSync(top, { recursive: true })
        fs.writeFileSync(path.join(top, 'package.json'), JSON.stringify(scopeProject))
        fs.writeFileSync(path.join(top, '.npmrc'), 'include[]=dev\nproduction=false\n')
        let d = path.join(top, 'out', 'test')
        fs.mkdirSync(d, { recursive: true })
        fs.writeFileSync(path.join(d, 'package.json'), JSON.stringify(scopeProject))
        await withEnv(baseEnv(), () => npmInstall(d))
        assert.strict.deepStrictEqual(installedNames(d), scopeInstalled)
    })

    //spec(run02 裁定 2): 安裝後驗證範圍; 仍有 dev 套件被裝入即拋錯(fail-closed), 訊息寫明原因與排除方式。
    //以下三處設定環境變數無從移除(使用者層、全域層、安裝目錄內之專案層), 每案之前提: 該設定確實使 dev 套件落地(驗證步驟攔下之對象存在)
    let cfgFile = (name, text) => {
        let f = path.join(root, name)
        fs.writeFileSync(f, text)
        return f
    }
    let cases = [
        ['使用者層設定檔 include[]=dev', () => ({ env: { npm_config_userconfig: cfgFile('user-include.npmrc', 'include[]=dev\n') } })],
        ['使用者層設定檔 production=false', () => ({ env: { npm_config_userconfig: cfgFile('user-production.npmrc', 'production=false\n') } })],
        ['全域設定檔 include[]=dev', () => ({ env: { npm_config_globalconfig: cfgFile('global-include.npmrc', 'include[]=dev\n') } })],
        ['安裝目錄內 .npmrc 之 include[]=dev', () => ({ files: { '.npmrc': 'include[]=dev\n' } })],
    ]
    for (let [title, make] of cases) {
        it(`${title}: 裝入 dev 套件即拋錯, 訊息寫明套件、原因與排除方式`, async function() {
            let { env = {}, files = {} } = make()
            let d = mkPrj(files)
            let err = await rejected(d, env)
            assert.strict.ok(err instanceof Error, 'npmInstall 應拋錯而非回傳')
            //前提: dev 套件確已落地(npm 照設定檔裝了)
            assert.strict.equal(fs.existsSync(path.join(d, 'node_modules', 'dev-tool', 'package.json')), true)
            assert.strict.match(err.message, /掃描範圍 dependencies 不成立/)
            assert.strict.ok(err.message.includes('dev-only-sub') && err.message.includes('dev-tool'), err.message)
            assert.strict.ok(err.message.includes('npm config list'), err.message) //如何排除
            assert.strict.ok(err.message.includes(d), err.message) //指明隔離資料夾
        })
    }

})
