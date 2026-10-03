import assert from 'assert'
import fs from 'fs'
import path from 'path'
import { spawn, spawnSync } from 'child_process'
import { ensureTool, installVerDir } from '../src/download.mjs'


//opt.fdTools(2026-10-02 擴充):同一 toolsDir 之同版本執行檔路徑固定、不重複下載;
//工具安裝於暫存夾完成後才改名為正式版本夾:失敗不留殘缺執行檔、並行同版本互不破壞、防毒短暫鎖定時重試
describe('ensureTool', function() {
    this.timeout(60000)

    let root = path.resolve('./test/_tmp/ensureTool')
    let fdTools = path.join(root, 'tools')
    let log = () => {}
    let fetch0 = globalThis.fetch
    let calls //資產下載之 url 紀錄
    let release
    let assetBody
    let assetFail

    let toolExe = { key: 'fake-exe', repo: 'x/fake-exe', kind: 'exe', matchAsset: (n) => n === 'fake.exe', exeName: 'fake.exe' }
    let toolZip = { key: 'fake-zip', repo: 'x/fake-zip', kind: 'zip', matchAsset: (n) => /\.zip$/.test(n), exeName: 'fake.exe' }

    //GitHub API 與資產下載改由此回應(僅替換網路,檔案系統為真)
    let stubFetch = () => {
        globalThis.fetch = async (url) => {
            if (url.startsWith('https://api.github.com/')) return { ok: true, json: async () => release }
            calls.push(url)
            if (assetFail) return { ok: false, status: 500 }
            return { ok: true, arrayBuffer: async () => assetBody.buffer.slice(assetBody.byteOffset, assetBody.byteOffset + assetBody.byteLength) }
        }
    }

    //以 Windows 內建 bsdtar 製作 zip(與 download.mjs 解壓所用者同一工具)
    let makeZip = (files) => {
        let src = path.join(root, 'zipsrc')
        fs.rmSync(src, { recursive: true, force: true })
        fs.mkdirSync(src, { recursive: true })
        for (let [n, c] of Object.entries(files)) fs.writeFileSync(path.join(src, n), c)
        let zip = path.join(root, 'fake.zip')
        let tar = path.join(process.env.SystemRoot || 'C:\\Windows', 'System32', 'tar.exe')
        let r = spawnSync(tar, ['-a', '-cf', zip, '-C', src, ...Object.keys(files)], { encoding: 'utf8' })
        assert.strict.strictEqual(r.status, 0, r.stderr)
        return fs.readFileSync(zip)
    }

    let tmpRoot = (tool) => path.join(fdTools, tool.key, '.tmp')

    beforeEach(function() {
        fs.rmSync(root, { recursive: true, force: true })
        fs.mkdirSync(root, { recursive: true })
        calls = []
        assetFail = false
        assetBody = Buffer.from('fake-exe-content-v1')
        release = { tag_name: 'v1.0.0', assets: [{ name: 'fake.exe', browser_download_url: 'https://example.invalid/fake.exe' }] }
        stubFetch()
    })

    afterEach(function() {
        globalThis.fetch = fetch0
    })

    after(function() {
        fs.rmSync(root, { recursive: true, force: true })
    })

    it('exe 資產:首次下載後位於 <toolsDir>/<工具>/<版本>/,不留暫存夾', async function() {
        let r = await ensureTool(toolExe, { toolsDir: fdTools, log })
        assert.strict.strictEqual(r.exePath, path.join(fdTools, 'fake-exe', 'v1.0.0', 'fake.exe'))
        assert.strict.strictEqual(r.version, 'v1.0.0')
        assert.strict.deepEqual(fs.readFileSync(r.exePath), assetBody)
        assert.strict.strictEqual(calls.length, 1)
        assert.strict.ok(!fs.existsSync(tmpRoot(toolExe)))
    })

    it('同一 toolsDir 第二次(例如另一個 fdOut)沿用快取:不再下載、路徑相同', async function() {
        let r1 = await ensureTool(toolExe, { toolsDir: fdTools, log })
        let logs = []
        let r2 = await ensureTool(toolExe, { toolsDir: fdTools, log: (m) => logs.push(m) })
        assert.strict.strictEqual(r2.exePath, r1.exePath)
        assert.strict.strictEqual(calls.length, 1)
        assert.strict.ok(logs.some((m) => m.includes('已有最新版 v1.0.0(快取)')), logs.join('\n'))
    })

    it('資產下載失敗時拋錯:正式路徑不留執行檔、暫存夾已清;之後可正常重抓', async function() {
        assetFail = true
        await assert.rejects(ensureTool(toolExe, { toolsDir: fdTools, log }), /下載失敗 500/)
        assert.strict.ok(!fs.existsSync(path.join(fdTools, 'fake-exe', 'v1.0.0')))
        assert.strict.ok(!fs.existsSync(tmpRoot(toolExe)))

        assetFail = false
        let r = await ensureTool(toolExe, { toolsDir: fdTools, log })
        assert.strict.deepEqual(fs.readFileSync(r.exePath), assetBody)
        assert.strict.strictEqual(calls.length, 2)
    })

    it('版本夾殘缺(無執行檔)時,下載完成後取代之', async function() {
        let verDir = path.join(fdTools, 'fake-exe', 'v1.0.0')
        fs.mkdirSync(verDir, { recursive: true })
        fs.writeFileSync(path.join(verDir, 'junk.txt'), 'partial')
        let r = await ensureTool(toolExe, { toolsDir: fdTools, log })
        assert.strict.deepEqual(fs.readFileSync(r.exePath), assetBody)
        assert.strict.deepEqual(fs.readdirSync(verDir), ['fake.exe'])
        assert.strict.ok(!fs.existsSync(tmpRoot(toolExe)))
    })

    it('zip 資產:於暫存夾解壓,版本夾只留解壓內容(無 zip),不留暫存夾', async function() {
        assetBody = makeZip({ 'fake.exe': 'zip-exe-content', 'README.md': 'readme' })
        release = { tag_name: 'v2.0.0', assets: [{ name: 'fake_2.0.0_windows_amd64.zip', browser_download_url: 'https://example.invalid/fake.zip' }] }
        let r = await ensureTool(toolZip, { toolsDir: fdTools, log })
        assert.strict.strictEqual(r.exePath, path.join(fdTools, 'fake-zip', 'v2.0.0', 'fake.exe'))
        assert.strict.strictEqual(fs.readFileSync(r.exePath, 'utf8'), 'zip-exe-content')
        assert.strict.deepEqual(fs.readdirSync(path.join(fdTools, 'fake-zip', 'v2.0.0')).sort(), ['README.md', 'fake.exe'])
        assert.strict.ok(!fs.existsSync(tmpRoot(toolZip)))
    })

    it('zip 解壓失敗(壞檔)時拋錯,不留版本夾與暫存夾', async function() {
        assetBody = Buffer.from('not-a-zip')
        release = { tag_name: 'v2.0.0', assets: [{ name: 'fake_2.0.0_windows_amd64.zip', browser_download_url: 'https://example.invalid/fake.zip' }] }
        await assert.rejects(ensureTool(toolZip, { toolsDir: fdTools, log }), /解壓失敗/)
        assert.strict.ok(!fs.existsSync(path.join(fdTools, 'fake-zip', 'v2.0.0')))
        assert.strict.ok(!fs.existsSync(tmpRoot(toolZip)))
    })

    it('同時下載同版本至同一 toolsDir:兩者回傳同一路徑、檔案完整、不留暫存夾', async function() {
        let [r1, r2] = await Promise.all([
            ensureTool(toolExe, { toolsDir: fdTools, log }),
            ensureTool(toolExe, { toolsDir: fdTools, log }),
        ])
        assert.strict.strictEqual(r1.exePath, r2.exePath)
        assert.strict.strictEqual(calls.length, 2)
        assert.strict.deepEqual(fs.readFileSync(r1.exePath), assetBody)
        assert.strict.deepEqual(fs.readdirSync(path.dirname(r1.exePath)), ['fake.exe'])
        assert.strict.ok(!fs.existsSync(tmpRoot(toolExe)))
    })

})


describe('installVerDir', function() {
    this.timeout(60000)

    let root = path.resolve('./test/_tmp/installVerDir')

    beforeEach(function() {
        fs.rmSync(root, { recursive: true, force: true })
        fs.mkdirSync(path.join(root, 'tmp'), { recursive: true })
        fs.writeFileSync(path.join(root, 'tmp', 'fake.exe'), 'x')
    })

    after(function() {
        fs.rmSync(root, { recursive: true, force: true })
    })

    //Windows 下行程之工作目錄無法改名,以子行程停在暫存夾內模擬防毒短暫鎖定
    let hold = (dir, ms) => spawn(process.execPath, ['-e', `setTimeout(()=>{},${ms})`], { cwd: dir, stdio: 'ignore' })
    let wait = (ms) => new Promise((resolve) => setTimeout(resolve, ms))
    let waitExit = (child) => new Promise((resolve) => child.exitCode !== null ? resolve() : child.once('exit', resolve))

    it('暫存夾被短暫占用時重試,占用解除後改名成功', async function() {
        let child = hold(path.join(root, 'tmp'), 1500)
        await wait(300)
        let t0 = Date.now()
        let r = await installVerDir(path.join(root, 'tmp'), path.join(root, 'v1'), 'fake.exe', { timeout: 15000 })
        assert.strict.strictEqual(r, true)
        assert.strict.ok(Date.now() - t0 >= 500, '應有重試等待')
        assert.strict.strictEqual(fs.readFileSync(path.join(root, 'v1', 'fake.exe'), 'utf8'), 'x')
        assert.strict.ok(!fs.existsSync(path.join(root, 'tmp')))
        await waitExit(child)
    })

    it('占用超過時限即拋錯,不建立版本夾', async function() {
        let child = hold(path.join(root, 'tmp'), 20000)
        try {
            await wait(300)
            await assert.rejects(installVerDir(path.join(root, 'tmp'), path.join(root, 'v1'), 'fake.exe', { timeout: 500 }), (err) => {
                assert.strict.ok(['EPERM', 'EACCES', 'EBUSY'].includes(err.code), err.code)
                return true
            })
            assert.strict.ok(!fs.existsSync(path.join(root, 'v1')))
            assert.strict.ok(fs.existsSync(path.join(root, 'tmp', 'fake.exe')))
        }
        finally {
            child.kill()
            await waitExit(child)
        }
    })

    it('目標已有他程序完成之版本夾時沿用之(回傳 false),不覆蓋', async function() {
        fs.mkdirSync(path.join(root, 'v1'), { recursive: true })
        fs.writeFileSync(path.join(root, 'v1', 'fake.exe'), 'winner')
        let r = await installVerDir(path.join(root, 'tmp'), path.join(root, 'v1'), 'fake.exe')
        assert.strict.strictEqual(r, false)
        assert.strict.strictEqual(fs.readFileSync(path.join(root, 'v1', 'fake.exe'), 'utf8'), 'winner')
    })

    it('force 時以本次下載取代既有版本夾', async function() {
        fs.mkdirSync(path.join(root, 'v1'), { recursive: true })
        fs.writeFileSync(path.join(root, 'v1', 'fake.exe'), 'old')
        let r = await installVerDir(path.join(root, 'tmp'), path.join(root, 'v1'), 'fake.exe', { force: true })
        assert.strict.strictEqual(r, true)
        assert.strict.strictEqual(fs.readFileSync(path.join(root, 'v1', 'fake.exe'), 'utf8'), 'x')
    })

})
