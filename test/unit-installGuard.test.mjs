import assert from 'assert'
import fs from 'fs'
import path from 'path'
import { npmInstallEnv, assertDependenciesOnly, NPM_DEV_OVERRIDE_ENV } from '../src/install.mjs'
import { withEnv } from './tools/fakeBins.mjs'


//建議w-scan-dep調整.md(Gitea #27)之主控裁定(run02): result.json 之 scope: 'dependencies' 必須為真, 呼叫端 npm 設定不得使範圍失真
//本檔為單元層(不跑 npm): npmInstallEnv 子行程環境副本之移除規則; assertDependenciesOnly 安裝後驗證(fail-closed)。真實 npm 之對照見 api-installScopeEnv.test.mjs
describe('npmInstallEnv (child env copy for the isolated install)', function() {

    //spec(run02 裁定 1): 移除會抵消 --omit=dev 之 npm 設定環境變數(npm 12.1.0 實測: include=dev、production=false、dev=true、also=dev|development), 前綴與鍵名不分大小寫
    it('移除 npm_config_include／production／dev／also(任意大小寫)', function() {
        let env = {
            npm_config_include: 'dev',
            NPM_CONFIG_INCLUDE: 'dev',
            Npm_Config_Production: 'false',
            npm_config_dev: 'true',
            NPM_CONFIG_ALSO: 'development',
        }
        assert.strict.deepStrictEqual(npmInstallEnv(env), {})
    })

    //spec(run02 裁定 1): 不得過度移除——registry、快取、其餘 npm 設定與一般環境變數照傳(否則隔離安裝連不到呼叫端指定之倉庫)
    it('其餘環境變數照傳: registry、快取、userconfig、omit、only、optional、NODE_ENV、與 include 僅前綴相同之其他設定', function() {
        let env = {
            npm_config_registry: 'http://127.0.0.1:4873/',
            npm_config_cache: 'C:\\c',
            npm_config_userconfig: 'C:\\u.npmrc',
            npm_config_omit: 'peer',
            npm_config_only: 'prod',
            npm_config_optional: 'false',
            npm_config_include_workspace_root: 'true', //鍵名不同於 include
            npm_config_devdir: 'C:\\gyp', //鍵名不同於 dev
            NODE_ENV: 'development',
            PATH: 'C:\\bin',
            W_NPM_INSTALL_TIMEOUT: '600',
        }
        assert.strict.deepStrictEqual(npmInstallEnv(env), env)
    })

    //spec(run02 裁定 1): 只動子行程之 env 副本, 不改傳入物件與 process.env
    it('回傳新物件, 不改傳入之環境; 預設取 process.env 時亦不改 process.env', async function() {
        let env = { npm_config_include: 'dev', KEEP: '1' }
        let out = npmInstallEnv(env)
        assert.strict.notEqual(out, env)
        assert.strict.deepStrictEqual(env, { npm_config_include: 'dev', KEEP: '1' })
        await withEnv({ npm_config_include: 'dev', npm_config_production: 'false' }, () => {
            let o = npmInstallEnv()
            assert.strict.equal(Object.keys(o).some((k) => NPM_DEV_OVERRIDE_ENV.test(k)), false)
            assert.strict.equal(process.env.npm_config_include, 'dev')
            assert.strict.equal(process.env.npm_config_production, 'false')
        })
    })

})

describe('assertDependenciesOnly (post-install scope check, fail-closed)', function() {

    let root = path.resolve('./test/_tmp/installGuard')
    let seq = 0

    before(function() {
        fs.rmSync(root, { recursive: true, force: true })
        fs.mkdirSync(root, { recursive: true })
    })

    after(function() {
        fs.rmSync(root, { recursive: true, force: true, maxRetries: 5, retryDelay: 200 })
    })

    //組一個模擬 npm install 後之安裝目錄: hidden 為 node_modules/.package-lock.json 之 packages, lock 為 package-lock.json 之 packages, dirs 為實際存在之相對資料夾
    let mk = ({ hidden, lock, dirs = [], raw = {} } = {}) => {
        let d = path.join(root, `case${++seq}`)
        fs.mkdirSync(d, { recursive: true })
        for (let p of dirs) fs.mkdirSync(path.join(d, p), { recursive: true })
        if (hidden) {
            fs.mkdirSync(path.join(d, 'node_modules'), { recursive: true })
            fs.writeFileSync(path.join(d, 'node_modules', '.package-lock.json'), JSON.stringify({ name: 'x', lockfileVersion: 3, packages: hidden }))
        }
        if (lock) fs.writeFileSync(path.join(d, 'package-lock.json'), JSON.stringify({ name: 'x', lockfileVersion: 3, packages: { '': { name: 'x' }, ...lock } }))
        for (let [f, c] of Object.entries(raw)) {
            fs.mkdirSync(path.dirname(path.join(d, f)), { recursive: true })
            fs.writeFileSync(path.join(d, f), c)
        }
        return d
    }
    let errOf = (d) => assertDependenciesOnly(d).then(() => null, (e) => e)

    //spec(run02 裁定 2): 隱藏鎖定檔(只列實際落地者)有 dev 標記之套件 = dev 套件被裝入, 拋錯, 訊息寫明原因與排除方式
    it('隱藏鎖定檔(node_modules/.package-lock.json)含 dev:true 項即拋錯, 訊息列出套件並寫明原因與排除方式', async function() {
        let d = mk({ hidden: { 'node_modules/prod-mid': {}, 'node_modules/dev-tool': { dev: true }, 'node_modules/dev-only-sub': { dev: true } } })
        let err = await errOf(d)
        assert.strict.ok(err instanceof Error)
        assert.strict.match(err.message, /掃描範圍 dependencies 不成立/)
        assert.strict.ok(err.message.includes('dev-only-sub、dev-tool'), err.message)
        assert.strict.ok(err.message.includes('不輸出 scope: \'dependencies\'') && err.message.includes('npm config list') && err.message.includes('include'), err.message)
    })

    //spec(run02 裁定 2): package-lock.json 在 --omit=dev 下仍含 dev:true 項(實測), 故以其路徑是否實際落地判定; 落地即拋錯(隱藏鎖定檔缺時之第二來源)
    it('package-lock.json 之 dev:true 項, 其路徑實際存在於磁碟即拋錯(巢狀路徑以末段套件名報出)', async function() {
        let d = mk({ lock: { 'node_modules/prod-mid': {}, 'node_modules/a/node_modules/c': { dev: true } }, dirs: ['node_modules/prod-mid', 'node_modules/a/node_modules/c'] })
        let err = await errOf(d)
        assert.strict.ok(err instanceof Error)
        assert.strict.match(err.message, /裝入了 devDependencies 套件\(c\)/)
    })

    //spec(run02 裁定 2): 正常省略成功之狀態不得誤報——package-lock.json 含 dev:true 項但未落地, 隱藏鎖定檔不含
    it('--omit=dev 成功之狀態(鎖定檔含 dev:true 項但未落地, 隱藏鎖定檔無)通過', async function() {
        let d = mk({
            hidden: { 'node_modules/prod-mid': {}, 'node_modules/semver': {} },
            lock: { 'node_modules/prod-mid': {}, 'node_modules/semver': {}, 'node_modules/dev-tool': { dev: true }, 'node_modules/dev-only-sub': { dev: true } },
            dirs: ['node_modules/prod-mid', 'node_modules/semver'],
        })
        assert.strict.equal(await errOf(d), null)
    })

    //spec(run02 裁定 2 + 1c): 同時為正式樹之相依者(不標 dev)、僅為選用相依者(devOptional、optional)、對等相依(peer)皆合法落地, 不誤報
    it('devOptional、optional、peer 標記之套件(正式樹所需)落地不誤報', async function() {
        let d = mk({
            hidden: { 'node_modules/a': { devOptional: true }, 'node_modules/b': { optional: true }, 'node_modules/c': { peer: true }, 'node_modules/d': { dev: false } },
            lock: { 'node_modules/a': { devOptional: true }, 'node_modules/b': { optional: true }, 'node_modules/c': { peer: true } },
            dirs: ['node_modules/a', 'node_modules/b', 'node_modules/c'],
        })
        assert.strict.equal(await errOf(d), null)
    })

    //spec(run02 裁定 2): 無相依之專案 npm 不建 node_modules; 無可驗證之物亦無 dev 套件, 通過
    it('無 node_modules 且無鎖定檔(零相依、或安裝為空作業)通過; node_modules 只有隱藏項(.bin)亦通過', async function() {
        assert.strict.equal(await errOf(mk()), null)
        assert.strict.equal(await errOf(mk({ dirs: ['node_modules/.bin'] })), null)
    })

    //fail-closed: 有套件落地卻兩份鎖定檔皆無, 無從驗證範圍, 不得放行
    it('node_modules 有套件卻無任何鎖定檔可驗證即拋錯', async function() {
        let err = await errOf(mk({ dirs: ['node_modules/prod-mid'] }))
        assert.strict.ok(err instanceof Error)
        assert.strict.match(err.message, /無 package-lock\.json 與 node_modules\/\.package-lock\.json 可驗證掃描範圍/)
    })

    //fail-closed: 鎖定檔損毀 = 無從驗證, 拋錯而非當作沒有 dev 套件
    it('鎖定檔非有效 JSON 即拋錯(不當作沒有 dev 套件)', async function() {
        let hiddenBad = await errOf(mk({ raw: { 'node_modules/.package-lock.json': '{ not json' } }))
        assert.strict.ok(hiddenBad instanceof Error)
        assert.strict.match(hiddenBad.message, /\.package-lock\.json 非有效 JSON 而無法驗證掃描範圍/)
        let lockBad = await errOf(mk({ raw: { 'package-lock.json': '{ not json' } }))
        assert.strict.ok(lockBad instanceof Error)
        assert.strict.match(lockBad.message, /package-lock\.json 非有效 JSON 而無法驗證掃描範圍/)
    })

    //訊息只列前 5 個, 其餘以總數表示(大型專案之錯誤訊息不灌爆)
    it('dev 套件超過 5 個時訊息列前 5 個並寫總數', async function() {
        let hidden = {}
        for (let i = 1; i <= 7; i++) hidden[`node_modules/dev-${i}`] = { dev: true }
        let err = await errOf(mk({ hidden }))
        assert.strict.ok(err instanceof Error)
        assert.strict.ok(err.message.includes('dev-1、dev-2、dev-3、dev-4、dev-5 等 7 個') && !err.message.includes('dev-6'), err.message)
    })

})
