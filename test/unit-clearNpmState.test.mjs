import assert from 'assert'
import fs from 'fs'
import path from 'path'
import { spawn } from 'child_process'
import { clearNpmState } from '../src/install.mjs'


//建議w-scan-dep修正.md 三:npm install 之前清空 testDir 之 package-lock.json 與 node_modules,
//並回驗確實不存在;刪除失敗即中止並說明,不以舊內容繼續掃描
describe('clearNpmState', function() {

    let root = path.resolve('./test/_tmp/clearNpmState')

    let mk = (p, s = '{}') => {
        fs.mkdirSync(path.dirname(p), { recursive: true })
        fs.writeFileSync(p, s, 'utf8')
    }

    beforeEach(function() {
        fs.rmSync(root, { recursive: true, force: true })
        fs.mkdirSync(root, { recursive: true })
    })

    after(function() {
        fs.rmSync(root, { recursive: true, force: true })
    })

    it('刪除上次之 package-lock.json 與 node_modules,保留其他檔案', async function() {
        mk(path.join(root, 'package.json'))
        mk(path.join(root, 'package-lock.json'), '{"stale":true}')
        mk(path.join(root, 'node_modules', '.package-lock.json'))
        mk(path.join(root, 'node_modules', 'w-email', 'package.json'), '{"version":"1.1.3"}')
        mk(path.join(root, 'node_modules', '@scope', 'pkg', 'lib', 'index.js'), '')
        mk(path.join(root, 'other.txt'), 'keep')

        await clearNpmState(root)

        //npm 安裝狀態已不存在
        assert.strict.ok(!fs.existsSync(path.join(root, 'package-lock.json')))
        assert.strict.ok(!fs.existsSync(path.join(root, 'node_modules')))
        //非 npm 安裝狀態不刪
        assert.strict.ok(fs.existsSync(path.join(root, 'package.json')))
        assert.strict.strictEqual(fs.readFileSync(path.join(root, 'other.txt'), 'utf8'), 'keep')
    })

    it('首次掃描(無殘留)不報錯', async function() {
        await clearNpmState(root)
        assert.strict.deepEqual(fs.readdirSync(root), [])
    })

    it('node_modules 被占用無法刪除時拋錯並說明,不視為已清除', async function() {
        let held = path.join(root, 'node_modules', 'a')
        mk(path.join(held, 'index.js'), '')
        //Windows 下行程之工作目錄無法刪除,以子行程停在 node_modules/a 內模擬占用
        let child = spawn(process.execPath, ['-e', 'setTimeout(()=>{},60000)'], { cwd: held, stdio: 'ignore' })
        try {
            await new Promise((r) => setTimeout(r, 500))
            await assert.rejects(clearNpmState(root), (err) => {
                assert.strict.match(err.message, /清除上次安裝殘留/)
                assert.strict.ok(err.message.includes(path.join(root, 'node_modules')))
                assert.strict.match(err.message, /不以舊內容繼續掃描/)
                return true
            })
            assert.strict.ok(fs.existsSync(held))
        }
        finally {
            await new Promise((r) => {
                child.once('exit', r)
                child.kill()
            })
        }
    })

})
