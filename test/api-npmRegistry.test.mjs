import assert from 'assert'
import fs from 'fs'
import path from 'path'
import { spawnSync } from 'child_process'
import { npmInstall } from '../src/install.mjs'
import { readCallerRegistry, writeRegistryNpmrc } from '../src/npmRegistry.mjs'
import { withEnv } from './tools/fakeBins.mjs'
import { fakeNpmRegistry } from './tools/fakeNpmRegistry.mjs'
import { scopePackages, scopeProject, scopeInstalled } from './tools/scopeFixture.mjs'


//主控裁定(隔離安裝沿用呼叫端專案之倉庫設定, 規則帳本 R-NPM-REGISTRY-01):
// 1. 實測確認屬實: 專案層 .npmrc 指 A、使用者層指 B 時, 只複製 package.json 至隔離資料夾之安裝由 B 解析(本檔「前提」案)
// 2. 於呼叫端專案目錄取得 npm 之生效 registry 與 @scope:registry(專案層、使用者層、全域層、環境變數合併後者), 寫入隔離資料夾之 .npmrc
// 3. 只帶倉庫位址類設定(不帶 include 等, 不帶認證值)
// 4. 取得生效設定失敗(逾時、離開碼非 0、輸出非 JSON、無法啟動)時拋錯, 不退回預設, 訊息不含 npm 輸出與認證值
//真實 npm 對本機假 registry(test/tools/fakeNpmRegistry.mjs; A 埠 8971、B 埠 8972、scope 專用 S 埠 8973), 不連外網;
//npm 快取每案獨立; 使用者層／全域設定檔以 npm_config_userconfig／globalconfig 指向本案暫存夾, 不動使用者之 ~/.npmrc
//取得失敗各形態以替身 npm(test/tools/fakeNpm/, 置於 PATH 前端)模擬
describe('npmRegistry: 隔離安裝沿用呼叫端專案之倉庫設定(真實 npm)', function() {
    this.timeout(180000)

    let root = path.resolve('./test/_tmp/npmRegistry')
    let fakeNpmDir = path.resolve('./test/tools/fakeNpm')
    let ports = { A: 8971, B: 8972, S: 8973 }
    let A = null
    let B = null
    let S = null
    let seq = 0
    let emptyGlobal = ''

    let SECRET = {
        projToken: 'PROJ-SECRET-TOKEN-91f3',
        projAuth: 'PROJ-SECRET-AUTH-77aa',
        projUser: 'proj-secret-user-5c2d',
        projPass: 'proj-secret-pass-0b8e',
        userToken: 'USER-SECRET-TOKEN-4e19',
        urlUser: 'leakuser',
        urlPass: 'leakpass',
    }
    let b64 = (s) => Buffer.from(s).toString('base64')

    let fresh = (name) => {
        let d = path.join(root, `${name}${++seq}`)
        fs.mkdirSync(d, { recursive: true })
        return d
    }
    let write = (f, text) => {
        fs.writeFileSync(f, text)
        return f
    }
    //npm 設定: 使用者層檔(userText 為其內容)、全域層指向空檔、npm_config_registry 清除(由設定檔決定)、快取每案獨立
    let envOf = (userText, extra = {}) => ({
        npm_config_registry: undefined,
        npm_config_userconfig: write(path.join(fresh('user'), '.npmrc'), userText),
        npm_config_globalconfig: emptyGlobal,
        npm_config_cache: fresh('cache'),
        npm_config_update_notifier: 'false',
        ...extra,
    })
    //呼叫端專案: 含 package.json 與專案層 .npmrc
    let mkCaller = (npmrc, pkg = scopeProject) => {
        let d = fresh('caller')
        write(path.join(d, 'package.json'), JSON.stringify(pkg))
        if (npmrc !== null) write(path.join(d, '.npmrc'), npmrc)
        return d
    }
    //隔離安裝資料夾(fdOut/test 之形態): 只複製 package.json
    let mkIsolated = (caller) => {
        let d = fresh('iso')
        fs.copyFileSync(path.join(caller, 'package.json'), path.join(d, 'package.json'))
        return d
    }
    let installedNames = (d) => fs.readdirSync(path.join(d, 'node_modules')).filter((n) => !n.startsWith('.')).sort()
    let listFiles = (d) => fs.readdirSync(d, { recursive: true, withFileTypes: true }).filter((v) => v.isFile()).map((v) => path.join(v.parentPath, v.name))
    let rejected = (p) => p.then(() => null, (e) => e)
    let pathWith = (dir) => {
        let k = Object.keys(process.env).find((x) => x.toLowerCase() === 'path') || 'PATH'
        return { [k]: dir + path.delimiter + (process.env[k] || '') }
    }

    before(function() {
        fs.rmSync(root, { recursive: true, force: true })
        fs.mkdirSync(root, { recursive: true })
        emptyGlobal = write(path.join(root, 'empty-global.npmrc'), '\n')
    })
    beforeEach(async function() {
        A = await fakeNpmRegistry(ports.A, scopePackages)
        B = await fakeNpmRegistry(ports.B, {}) //解析不到任何套件(模擬「改由別的倉庫解析而拿不到／拿到舊版」)
        S = await fakeNpmRegistry(ports.S, { '@acme/lib': { '1.0.0': {} } })
    })
    afterEach(async function() {
        for (let r of [A, B, S]) if (r) await r.close()
        A = B = S = null
    })
    after(function() {
        fs.rmSync(root, { recursive: true, force: true, maxRetries: 5, retryDelay: 200 })
    })

    //主控裁定 1 + 2(spec: 專案層 .npmrc 指 A、使用者層指 B → 由 A 安裝)
    describe('registry: 專案層 A、使用者層 B', function() {

        //前提(此案不經本修正之碼, 只用 npm): 只複製 package.json 之隔離資料夾讀不到呼叫端專案層 .npmrc, 改由使用者層 B 解析 —— 即待修正之現象
        it('前提: 專案層 .npmrc 指 A、使用者層指 B 時, 未沿用設定之隔離安裝由 B 解析而失敗, A 完全未被詢問', async function() {
            let caller = mkCaller(`registry=${A.url}\n`)
            let iso = mkIsolated(caller)
            let err = await withEnv(envOf(`registry=${B.url}\n`), () => rejected(npmInstall(iso)))
            assert.strict.ok(err instanceof Error, '未沿用時應安裝失敗(B 無套件)')
            assert.strict.ok(B.requests().includes('/prod-mid'), `B 應被詢問: ${B.requests()}`)
            assert.strict.deepStrictEqual(A.requests(), [])
        })

        it('於呼叫端專案目錄取得之生效 registry 為專案層之 A(非使用者層之 B); 寫入 .npmrc 後隔離安裝由 A 解析, B 完全未被詢問', async function() {
            let caller = mkCaller(`registry=${A.url}\n`)
            let callerFiles = fs.readdirSync(caller).sort()
            let callerRc = fs.readFileSync(path.join(caller, '.npmrc'), 'utf8')
            let iso = mkIsolated(caller)
            let r = await withEnv(envOf(`registry=${B.url}\n`), async () => {
                let reg = await readCallerRegistry(caller)
                await writeRegistryNpmrc(iso, reg.entries)
                await npmInstall(iso)
                return reg
            })
            assert.strict.deepStrictEqual(r.entries, [{ key: 'registry', url: A.url }])
            assert.strict.deepStrictEqual(installedNames(iso), scopeInstalled)
            assert.strict.ok(A.requests().some((v) => v.endsWith('.tgz')), `套件應取自 A: ${A.requests()}`)
            assert.strict.deepStrictEqual(B.requests(), [])
            //不改呼叫端專案: 其檔案與 .npmrc 內容不變
            assert.strict.deepStrictEqual(fs.readdirSync(caller).sort(), callerFiles)
            assert.strict.equal(fs.readFileSync(path.join(caller, '.npmrc'), 'utf8'), callerRc)
        })

        it('registry 只設在使用者層(專案層未設)時, 生效值為使用者層之值, 隔離安裝同樣由其解析(與未修正前等價, 不另生差異)', async function() {
            let caller = mkCaller(null)
            let iso = mkIsolated(caller)
            let r = await withEnv(envOf(`registry=${A.url}\n`), async () => {
                let reg = await readCallerRegistry(caller)
                await writeRegistryNpmrc(iso, reg.entries)
                await npmInstall(iso)
                return reg
            })
            assert.strict.deepStrictEqual(r.entries, [{ key: 'registry', url: A.url }])
            assert.strict.deepStrictEqual(installedNames(iso), scopeInstalled)
        })

        it('全域層設 registry 時生效值為全域層之值(專案層與使用者層未設); 使用者層優先於全域層(npm 之優先序)', async function() {
            let caller = mkCaller(null)
            let g = write(path.join(fresh('glob'), 'npmrc'), `registry=${B.url}\n`)
            let r1 = await withEnv(envOf('\n', { npm_config_globalconfig: g }), () => readCallerRegistry(caller))
            assert.strict.deepStrictEqual(r1.entries, [{ key: 'registry', url: B.url }])
            let r2 = await withEnv(envOf(`registry=${A.url}\n`, { npm_config_globalconfig: g }), () => readCallerRegistry(caller))
            assert.strict.deepStrictEqual(r2.entries, [{ key: 'registry', url: A.url }])
        })

        it('環境變數 npm_config_registry 優先於專案層(npm 之生效值): 取得之 registry 為環境變數者, 其餘照 npm 優先序', async function() {
            let caller = mkCaller(`registry=${B.url}\n`)
            let iso = mkIsolated(caller)
            let r = await withEnv(envOf(`registry=${B.url}\n`, { npm_config_registry: A.url }), async () => {
                let reg = await readCallerRegistry(caller)
                await writeRegistryNpmrc(iso, reg.entries)
                await npmInstall(iso)
                return reg
            })
            assert.strict.deepStrictEqual(r.entries, [{ key: 'registry', url: A.url }])
            assert.strict.deepStrictEqual(B.requests(), [])
        })

        it('專案層與使用者層皆未設 registry: 生效值為 npm 預設倉庫(照實取得並寫入, 與未修正前等價)', async function() {
            let caller = mkCaller(null)
            let r = await withEnv(envOf('\n'), () => readCallerRegistry(caller))
            assert.strict.deepStrictEqual(r.entries, [{ key: 'registry', url: 'https://registry.npmjs.org/' }])
        })

    })

    //主控裁定 2(spec: @scope:registry 只設在專案層 → 該 scope 由指定倉庫安裝)
    describe('@scope:registry 只設在專案層', function() {
        let pkgScoped = { ...scopeProject, dependencies: { ...scopeProject.dependencies, '@acme/lib': '1.0.0' } }

        it('前提: 未沿用時 @acme/lib 改向預設倉庫 A 詢問而失敗, S 完全未被詢問', async function() {
            let caller = mkCaller(`@acme:registry=${S.url}\n`, pkgScoped)
            let iso = mkIsolated(caller)
            let err = await withEnv(envOf(`registry=${A.url}\n`), () => rejected(npmInstall(iso)))
            assert.strict.ok(err instanceof Error)
            assert.strict.ok(A.requests().some((v) => v.includes('@acme')), `A 應被詢問 @acme/lib: ${A.requests()}`)
            assert.strict.deepStrictEqual(S.requests(), [])
        })

        it('專案層只設 @acme:registry=S(預設倉庫在使用者層為 A): 取得之設定含二者, 隔離安裝 @acme/lib 取自 S、其餘取自 A', async function() {
            let caller = mkCaller(`@acme:registry=${S.url}\n`, pkgScoped)
            let iso = mkIsolated(caller)
            let r = await withEnv(envOf(`registry=${A.url}\n`), async () => {
                let reg = await readCallerRegistry(caller)
                await writeRegistryNpmrc(iso, reg.entries)
                await npmInstall(iso)
                return reg
            })
            assert.strict.deepStrictEqual(r.entries, [{ key: 'registry', url: A.url }, { key: '@acme:registry', url: S.url }])
            assert.strict.deepStrictEqual(installedNames(iso), ['@acme', ...scopeInstalled])
            assert.strict.equal(fs.existsSync(path.join(iso, 'node_modules', '@acme', 'lib', 'package.json')), true)
            assert.strict.ok(S.requests().some((v) => v.includes('@acme')), `@acme/lib 應取自 S: ${S.requests()}`)
            assert.strict.equal(A.requests().some((v) => v.includes('@acme')), false, `A 不應被詢問 @acme/lib: ${A.requests()}`)
        })

    })

    //主控裁定 3(spec: 專案層 .npmrc 含 include[]=dev 時仍不被帶入; dev 不落地、#27 驗證照常)
    describe('不帶倉庫位址以外之設定(include 等)', function() {

        it('專案層 .npmrc 含 include[]=dev、production=false 等: 不寫入隔離資料夾之 .npmrc, devDependencies 不落地, 安裝後驗證通過', async function() {
            let caller = mkCaller(`registry=${A.url}\ninclude[]=dev\nproduction=false\nomit[]=optional\nstrict-ssl=false\nproxy=http://127.0.0.1:1/\n`)
            //前提: 這些設定在呼叫端專案目錄確實生效(其自身之 npm install 會裝入 dev 套件)
            let env = envOf(`registry=${B.url}\n`)
            let probe = await withEnv(env, () => spawnSync('npm config get include', { cwd: caller, shell: true, encoding: 'utf8', windowsHide: true }))
            assert.strict.match(probe.stdout, /dev/)
            let iso = mkIsolated(caller)
            await withEnv(env, async () => {
                let reg = await readCallerRegistry(caller)
                assert.strict.deepStrictEqual(reg.entries, [{ key: 'registry', url: A.url }])
                await writeRegistryNpmrc(iso, reg.entries)
                await npmInstall(iso) //內含 assertDependenciesOnly
            })
            let rc = fs.readFileSync(path.join(iso, '.npmrc'), 'utf8')
            for (let k of ['include', 'production', 'omit', 'strict-ssl', 'proxy', 'dev']) assert.strict.equal(rc.includes(k), false, `.npmrc 不應含 ${k}: ${rc}`)
            assert.strict.deepStrictEqual(installedNames(iso), scopeInstalled)
            assert.strict.equal(fs.existsSync(path.join(iso, 'node_modules', 'dev-tool')), false)
        })

    })

    //主控裁定 3(spec: 不帶認證值; 不得把任何認證值寫入 fdOut、log、錯誤訊息或結果檔)
    describe('認證值不帶入', function() {
        let projRc = () => [
            `registry=http://127.0.0.1:${ports.A}/`,
            `//127.0.0.1:${ports.A}/:_authToken=${SECRET.projToken}`,
            `//127.0.0.1:${ports.A}/:_auth=${b64(SECRET.projAuth)}`,
            `//127.0.0.1:${ports.A}/:username=${SECRET.projUser}`,
            `//127.0.0.1:${ports.A}/:_password=${b64(SECRET.projPass)}`,
            `_authToken=${SECRET.projToken}`,
            '',
        ].join('\n')
        let userRc = () => `//127.0.0.1:${ports.B}/:_authToken=${SECRET.userToken}\n`
        let values = Object.values(SECRET).concat([b64(SECRET.projAuth), b64(SECRET.projPass)])
        let leaks = (text) => values.filter((v) => text.includes(v))

        it('專案層／使用者層之 _authToken、_auth、username、_password(依主機鍵與不分主機)皆不寫入隔離資料夾(.npmrc、package-lock.json 等一切檔案)與取得之設定物件', async function() {
            let caller = mkCaller(projRc())
            let iso = mkIsolated(caller)
            let env = envOf(userRc())
            //前提: 這些認證確實在呼叫端專案之 npm 設定內(否則下列「無洩漏」無意義)
            let rcText = fs.readFileSync(path.join(caller, '.npmrc'), 'utf8') + fs.readFileSync(env.npm_config_userconfig, 'utf8')
            for (let s of [SECRET.projToken, b64(SECRET.projAuth), SECRET.projUser, b64(SECRET.projPass), SECRET.userToken]) {
                assert.strict.ok(rcText.includes(s), `前提: 呼叫端設定應含 ${s}`)
            }
            let reg = await withEnv(env, async () => {
                let r = await readCallerRegistry(caller)
                await writeRegistryNpmrc(iso, r.entries)
                await npmInstall(iso)
                return r
            })
            assert.strict.deepStrictEqual(reg, { entries: [{ key: 'registry', url: A.url }], strippedAuth: [] })
            assert.strict.deepStrictEqual(leaks(JSON.stringify(reg)), [])
            let rc = fs.readFileSync(path.join(iso, '.npmrc'), 'utf8')
            assert.strict.equal(rc.includes('auth') || rc.includes('password') || rc.includes('username'), false, rc)
            for (let f of listFiles(iso)) {
                assert.strict.deepStrictEqual(leaks(fs.readFileSync(f, 'latin1')), [], `${f} 含認證值`)
            }
            assert.strict.deepStrictEqual(installedNames(iso), scopeInstalled)
        })

        //真實 npm(12.1.0 實測)把網址內嵌帳密之 registry 視為受保護: config list 不列出(config get 亦拒絕)。無從得知位址時拋錯, 不改用預設倉庫
        it('registry 網址內嵌帳密(npm 視為受保護而不列出): 拋錯並寫明改法, 訊息不含帳密', async function() {
            let caller = mkCaller(`registry=http://${SECRET.urlUser}:${SECRET.urlPass}@127.0.0.1:${ports.A}/\n`)
            let err = await withEnv(envOf('\n'), () => rejected(readCallerRegistry(caller)))
            assert.strict.ok(err instanceof Error, '應拋錯而非退回預設倉庫')
            assert.strict.match(err.message, /^無法取得呼叫端專案\(.+\)生效之 npm 倉庫設定,已中止/)
            assert.strict.match(err.message, /npm config list --json 未列出 registry\(npm 對網址內嵌帳密之 registry 視為受保護而不列出\)/)
            assert.strict.ok(err.message.includes('//主機/:_authToken'), err.message)
            assert.strict.deepStrictEqual(leaks(err.message), [])
        })

        //npm 若列出內嵌帳密之網址(較舊版本), 去除帳密後沿用其位址, 並標出被去除之鍵
        it('npm 列出之 registry／@scope:registry 網址內嵌帳密(替身 npm 模擬): 去除帳密後沿用位址, 回報被去除之鍵, 輸出不含帳密', async function() {
            let caller = mkCaller(null)
            let conf = JSON.stringify({
                'registry': `http://${SECRET.urlUser}:${SECRET.urlPass}@127.0.0.1:${ports.A}/`,
                '@acme:registry': `http://${SECRET.urlUser}:@127.0.0.1:${ports.S}/`,
            })
            let r = await withEnv({ ...pathWith(fakeNpmDir), FAKE_NPM_MODE: 'conf', FAKE_NPM_CONF: conf }, () => readCallerRegistry(caller, { timeoutMs: 30000 }))
            assert.strict.deepStrictEqual(r.entries, [{ key: 'registry', url: A.url }, { key: '@acme:registry', url: S.url }])
            assert.strict.deepStrictEqual(r.strippedAuth, ['registry', '@acme:registry'])
            assert.strict.deepStrictEqual(leaks(JSON.stringify(r)), [])
        })

    })

    //主控裁定 4(spec: 取得生效設定失敗時拋錯並寫明理由與訊息; 不含認證值)
    describe('取得生效設定失敗', function() {
        let sec = 'FAKE-NPM-SECRET-d41d8cd9'
        let withFake = (mode, extra, fn) => withEnv({ ...pathWith(fakeNpmDir), FAKE_NPM_MODE: mode, FAKE_NPM_SECRET: sec, ...extra }, fn)
        let head = /^無法取得呼叫端專案\(.+\)生效之 npm 倉庫設定,已中止\(不改用隔離資料夾之預設設定,以免掃描結果與專案實際安裝不符\):/

        for (let [mode, tail] of [
            ['exit1', /npm config list --json 離開碼 1;請於該資料夾執行 npm config list 檢視原因$/],
            ['garbage', /npm config list --json 之輸出不是 JSON 物件$/],
            ['text', /npm config list --json 之輸出不是 JSON 物件$/],
            ['array', /npm config list --json 之輸出不是 JSON 物件$/],
            ['null', /npm config list --json 之輸出不是 JSON 物件$/],
        ]) {
            it(`替身 npm 模式 ${mode}: 拋錯, 訊息寫明呼叫端專案與原因, 不含 npm 輸出與認證值`, async function() {
                let caller = mkCaller(null)
                let err = await withFake(mode, {}, () => rejected(readCallerRegistry(caller, { timeoutMs: 30000 })))
                assert.strict.ok(err instanceof Error, '應拋錯而非退回預設')
                assert.strict.match(err.message, head)
                assert.strict.match(err.message, tail)
                assert.strict.ok(err.message.includes(caller), err.message)
                assert.strict.equal(err.message.includes(sec), false, `訊息含認證值: ${err.message}`)
                assert.strict.equal(err.message.includes('_authToken'), false, err.message)
            })
        }

        //真實 npm 一律列出 registry(未設時為預設倉庫); 缺少者代表被 npm 隱藏(內嵌帳密), 不得當作「呼叫端無設定」而改用預設
        it('npm 之輸出缺少 registry(含輸出 {}): 拋錯, 不當作呼叫端無設定而改用預設', async function() {
            let caller = mkCaller(null)
            let err = await withFake('empty', {}, () => rejected(readCallerRegistry(caller, { timeoutMs: 30000 })))
            assert.strict.ok(err instanceof Error)
            assert.strict.match(err.message, head)
            assert.strict.match(err.message, /未列出 registry/)
        })

        it('npm 回報之 registry 不是 http(s) 網址: 拋錯, 訊息指明鍵名而不含該值', async function() {
            let caller = mkCaller(null)
            let conf = JSON.stringify({ 'registry': 'http://ok.example/', '@acme:registry': `C:\\repo\\${sec}` })
            let err = await withFake('conf', { FAKE_NPM_CONF: conf }, () => rejected(readCallerRegistry(caller, { timeoutMs: 30000 })))
            assert.strict.ok(err instanceof Error)
            assert.strict.match(err.message, /@acme:registry 不是 http\(s\) 網址/)
            assert.strict.equal(err.message.includes(sec), false, err.message)
        })

        it('npm 不在 PATH(shell 找不到 npm): 拋錯(離開碼非 0), 不退回預設', async function() {
            let caller = mkCaller(null)
            let empty = fresh('nopath')
            let k = Object.keys(process.env).find((x) => x.toLowerCase() === 'path') || 'PATH'
            let err = await withEnv({ [k]: empty }, () => rejected(readCallerRegistry(caller, { timeoutMs: 30000 })))
            assert.strict.ok(err instanceof Error)
            assert.strict.match(err.message, head)
            assert.strict.match(err.message, /離開碼 [1-9]\d*/)
        })

        it('呼叫端專案目錄不存在(無法啟動): 拋錯', async function() {
            let err = await rejected(readCallerRegistry(path.join(root, 'no-such-dir'), { timeoutMs: 30000 }))
            assert.strict.ok(err instanceof Error)
            assert.strict.match(err.message, head)
        })

        //逾時: 替身 npm 永不結束; 時限 3 秒, 逾時即樹狀結束並拋含「逾時」之錯誤(此為時限本身之行為, 以短時限驗證)
        it('npm config list 逾時: 拋含「逾時」與調整變數 W_NPM_CONFIG_TIMEOUT 之錯誤, 且該行程樹已結束', async function() {
            let caller = mkCaller(null)
            let pidFile = path.join(fresh('pid'), 'pid.txt')
            let t0 = Date.now()
            let err = await withFake('hang', { FAKE_NPM_PIDFILE: pidFile }, () => rejected(readCallerRegistry(caller, { timeoutMs: 3000 })))
            let ms = Date.now() - t0
            assert.strict.ok(err instanceof Error)
            assert.strict.match(err.message, head)
            assert.strict.match(err.message, /npm config list --json 逾時\(超過 3 秒未完成\)/)
            assert.strict.ok(err.message.includes('W_NPM_CONFIG_TIMEOUT') && err.message.includes('已結束'), err.message)
            assert.strict.ok(ms >= 3000, String(ms))
            //前提: 替身確已啟動並卡住; 行程樹已結束(npm.cmd 之 node 行程不再存活)
            assert.strict.equal(fs.existsSync(pidFile), true, '替身 npm 應已啟動')
            let pid = Number(fs.readFileSync(pidFile, 'utf8'))
            let alive = () => {
                try {
                    process.kill(pid, 0)
                    return true
                }
                catch {
                    return false
                }
            }
            let t1 = Date.now()
            while (alive() && Date.now() - t1 < 10000) await new Promise((resolve) => setTimeout(resolve, 100))
            assert.strict.equal(alive(), false, `替身 npm(PID ${pid})未被結束`)
        })

    })

})
