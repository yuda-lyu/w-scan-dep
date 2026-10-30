import assert from 'assert'
import fs from 'fs'
import path from 'path'
import { pickRegistrySettings, renderNpmrc, writeRegistryNpmrc, npmConfigTimeoutMs, describeRegistry, REGISTRY_KEY } from '../src/npmRegistry.mjs'


//主控裁定(隔離安裝沿用呼叫端專案之倉庫設定, 規則帳本 R-NPM-REGISTRY-01):
// 3. 只帶倉庫位址類設定(registry、@scope:registry); 不帶 include／production／dev／also／omit 等(#27 之 scope 不得失真); 不帶認證值, 認證值不得寫入 fdOut／log／錯誤訊息／結果檔
// 以下為不啟動 npm 之單元測試; 真實 npm 與替身 npm 之案見 api-npmRegistry.test.mjs
describe('npmRegistry: pickRegistrySettings', function() {

    //npm config list --json 之實測形態(見規則帳本): 合併後之生效值, 含 registry、@scope:registry 與大量其他設定
    let conf = (extra = {}) => ({
        'json': true,
        'userconfig': 'C:\\Users\\x\\.npmrc',
        'registry': 'http://a.example:4873/',
        '@acme:registry': 'http://scope.example/',
        '@bar_baz:registry': 'http://bar.example/',
        'always-auth': true,
        'strict-ssl': false,
        'include': ['dev'],
        'production': false,
        'dev': true,
        'also': 'dev',
        'omit': ['peer'],
        'only': 'prod',
        'optional': false,
        'cafile': 'C:\\ca.pem',
        'https-proxy': 'http://proxy.example:8080/',
        'replace-registry-host': 'npmjs',
        ...extra,
    })

    //spec 3: 只帶 registry 與 @scope:registry; 其餘(安裝集合、TLS、代理、其他設定)一概不帶
    it('只挑出 registry 與 @scope:registry, 不帶 include／production／dev／also／omit 等其他任何設定', function() {
        let r = pickRegistrySettings(conf())
        assert.strict.deepStrictEqual(r.entries, [
            { key: 'registry', url: 'http://a.example:4873/' },
            { key: '@acme:registry', url: 'http://scope.example/' },
            { key: '@bar_baz:registry', url: 'http://bar.example/' },
        ])
        assert.strict.deepStrictEqual(r.strippedAuth, [])
    })

    //spec 3: 認證類設定不帶(含 npm 版本若將之列入輸出時, 以鍵名層層擋下)
    it('認證類鍵(_authToken、_auth、username、_password 及依主機鍵)不帶入, 其值不出現在輸出', function() {
        let secret = 'SECRET-TOKEN-VALUE'
        let r = pickRegistrySettings(conf({
            '_authToken': secret,
            '_auth': secret,
            'username': secret,
            '_password': secret,
            '//a.example:4873/:_authToken': secret,
            '//a.example:4873/:_auth': secret,
            '//a.example:4873/:username': secret,
            '//a.example:4873/:_password': secret,
            '//a.example:4873/:email': secret,
            '//a.example:4873/:certfile': secret,
            '//a.example:4873/:keyfile': secret,
        }))
        assert.strict.equal(JSON.stringify(r).includes(secret), false)
        assert.strict.deepStrictEqual(r.entries.map((v) => v.key), ['registry', '@acme:registry', '@bar_baz:registry'])
    })

    //spec 3: 不帶認證值之延伸 — 網址內嵌之帳密(http://user:pass@host/)亦為認證值, 去除之; 其餘網址部分不變
    it('registry 網址內嵌之帳密去除, 並標出被去除之鍵; 輸出不含帳密', function() {
        let r = pickRegistrySettings(conf({
            'registry': 'http://leakuser:leakpass@a.example:4873/path/',
            '@acme:registry': 'https://tok:@scope.example/',
        }))
        assert.strict.deepStrictEqual(r.entries.slice(0, 2), [
            { key: 'registry', url: 'http://a.example:4873/path/' },
            { key: '@acme:registry', url: 'https://scope.example/' },
        ])
        assert.strict.deepStrictEqual(r.strippedAuth, ['registry', '@acme:registry'])
        let s = JSON.stringify(r)
        for (let leak of ['leakuser', 'leakpass', 'tok:']) assert.strict.equal(s.includes(leak), false, leak)
    })

    //spec 4(取得失敗不靜默): 倉庫值不是 http(s) 網址即無法忠實沿用, 拋錯; 訊息只寫鍵名, 不寫設定值
    for (let bad of ['not a url', 'file:///C:/x/', 'ftp://a.example/', 'C:\\repo\\', 'user:pass@a.example']) {
        it(`registry 值「${bad}」非 http(s) 網址: 拋錯, 訊息指明鍵名而不含該值`, function() {
            let err
            try {
                pickRegistrySettings(conf({ '@acme:registry': bad }))
            }
            catch (e) {
                err = e
            }
            assert.strict.ok(err instanceof Error)
            assert.strict.match(err.message, /@acme:registry 不是 http\(s\) 網址/)
            assert.strict.equal(err.message.includes(bad), false, err.message)
        })
    }

    it('null、空字串、非字串之 registry 值略過(視為未設定)', function() {
        let r = pickRegistrySettings({ 'registry': null, '@a:registry': '', '@b:registry': '  ', '@c:registry': 5, '@d:registry': ['x'], '@e:registry': 'http://e.example/' })
        assert.strict.deepStrictEqual(r.entries, [{ key: '@e:registry', url: 'http://e.example/' }])
    })

    it('registry 排第一, scope 依鍵名排序(輸出順序固定)', function() {
        let r = pickRegistrySettings({ '@z:registry': 'http://z.example/', 'registry': 'http://r.example/', '@a:registry': 'http://a.example/' })
        assert.strict.deepStrictEqual(r.entries.map((v) => v.key), ['registry', '@a:registry', '@z:registry'])
    })

    it('REGISTRY_KEY 只接受 registry 與 @scope:registry, 不接受鍵名僅前後綴相同者', function() {
        for (let k of ['registry', '@a:registry', '@my-org_x.y~z:registry']) assert.strict.equal(REGISTRY_KEY.test(k), true, k)
        for (let k of ['registry-x', 'x-registry', 'replace-registry-host', 'omit-lockfile-registry-resolved', '@a:registry-x', '@:registry', '@a:b:registry', '//a/:registry', ' registry', '@a/b:registry']) {
            assert.strict.equal(REGISTRY_KEY.test(k), false, k)
        }
    })

    it('describeRegistry 以「鍵=網址」列出(供 log, 網址已去除帳密)', function() {
        let r = pickRegistrySettings(conf({ registry: 'http://u:p@a.example/' }))
        let s = describeRegistry(r.entries)
        assert.strict.equal(s, 'registry=http://a.example/、@acme:registry=http://scope.example/、@bar_baz:registry=http://bar.example/')
    })

})

describe('npmRegistry: renderNpmrc 與 writeRegistryNpmrc', function() {
    let root = path.resolve('./test/_tmp/npmRegistryUnit')
    let seq = 0
    let mk = () => {
        let d = path.join(root, `d${++seq}`)
        fs.mkdirSync(d, { recursive: true })
        return d
    }

    before(function() {
        fs.rmSync(root, { recursive: true, force: true })
        fs.mkdirSync(root, { recursive: true })
    })
    after(function() {
        fs.rmSync(root, { recursive: true, force: true, maxRetries: 5, retryDelay: 200 })
    })

    //spec 3: .npmrc 只有倉庫位址行(與一行註解); 值以 JSON 字串引號包住(網址內 ; # 不被 ini 當註解)
    it('renderNpmrc: 一行註解加各倉庫位址行, 值以引號包住, 末尾換行', function() {
        let s = renderNpmrc([{ key: 'registry', url: 'http://a.example/x;y#z/' }, { key: '@acme:registry', url: 'http://s.example/' }])
        assert.strict.deepStrictEqual(s.split('\n'), [
            '; w-scan-dep:沿用呼叫端專案生效之 npm 倉庫位址設定(registry、@scope:registry);不含認證值與其他設定',
            'registry="http://a.example/x;y#z/"',
            '@acme:registry="http://s.example/"',
            '',
        ])
    })

    it('writeRegistryNpmrc: 於隔離資料夾寫入 .npmrc 並回傳路徑, 不動資料夾內其他檔案', async function() {
        let d = mk()
        fs.writeFileSync(path.join(d, 'package.json'), '{}')
        let entries = [{ key: 'registry', url: 'http://a.example/' }]
        let p = await writeRegistryNpmrc(d, entries)
        assert.strict.equal(p, path.join(d, '.npmrc'))
        assert.strict.equal(fs.readFileSync(p, 'utf8'), renderNpmrc(entries))
        assert.strict.deepStrictEqual(fs.readdirSync(d).sort(), ['.npmrc', 'package.json'])
    })

    //spec 3(結果只取決於呼叫端專案之設定): 上次執行或他處留下之 .npmrc 一律被取代, 不沿用其內容
    it('writeRegistryNpmrc: 既有 .npmrc(他處或上次留下, 含 include[]=dev)被取代, 新檔不含舊內容', async function() {
        let d = mk()
        fs.writeFileSync(path.join(d, '.npmrc'), 'registry=http://old.example/\ninclude[]=dev\n')
        await writeRegistryNpmrc(d, [{ key: 'registry', url: 'http://new.example/' }])
        let s = fs.readFileSync(path.join(d, '.npmrc'), 'utf8')
        assert.strict.ok(s.includes('http://new.example/'))
        assert.strict.equal(s.includes('old.example') || s.includes('include'), false, s)
    })

    it('writeRegistryNpmrc: entries 為空時刪除既有 .npmrc 並回傳 null(上次之設定不殘留)', async function() {
        let d = mk()
        fs.writeFileSync(path.join(d, '.npmrc'), 'registry=http://old.example/\n')
        fs.writeFileSync(path.join(d, 'package.json'), '{}')
        let r = await writeRegistryNpmrc(d, [])
        assert.strict.equal(r, null)
        assert.strict.deepStrictEqual(fs.readdirSync(d), ['package.json'])
    })

    it('writeRegistryNpmrc: 無既有檔且 entries 為空時不建檔、不拋錯', async function() {
        let d = mk()
        assert.strict.equal(await writeRegistryNpmrc(d, []), null)
        assert.strict.deepStrictEqual(fs.readdirSync(d), [])
    })

})

describe('npmRegistry: npmConfigTimeoutMs(W_NPM_CONFIG_TIMEOUT)', function() {
    it('未設或空白為預設 60 秒', function() {
        assert.strict.equal(npmConfigTimeoutMs({}), 60000)
        assert.strict.equal(npmConfigTimeoutMs({ W_NPM_CONFIG_TIMEOUT: '  ' }), 60000)
    })
    it('秒數換算為毫秒', function() {
        assert.strict.equal(npmConfigTimeoutMs({ W_NPM_CONFIG_TIMEOUT: '5' }), 5000)
        assert.strict.equal(npmConfigTimeoutMs({ W_NPM_CONFIG_TIMEOUT: '0.5' }), 500)
    })
    for (let bad of ['0', '-1', 'abc', '0x10', '1e10', 'Infinity']) {
        it(`值「${bad}」不合法: 拋錯且訊息指明變數名(不靜默改用預設)`, function() {
            assert.strict.throws(() => npmConfigTimeoutMs({ W_NPM_CONFIG_TIMEOUT: bad }), /W_NPM_CONFIG_TIMEOUT/)
        })
    }
})
