import assert from 'assert'
import fs from 'fs'
import path from 'path'
import { npmInstall } from '../src/install.mjs'
import { withEnv } from './tools/fakeBins.mjs'
import { hangRegistry } from './tools/hangRegistry.mjs'


//建議w-scan-dep修正.md(Gitea #24)三:npm install 須有時限,逾時須結束整個子行程樹並拋出含「逾時」字樣之錯誤(主控裁定 5)。
//以接受連線但永不回應之本機服務當 registry(npm_config_registry),真實執行 npm;npm 快取改指本案暫存夾,不受本機快取影響
describe('npmInstall', function() {
    this.timeout(120000)

    let root = path.resolve('./test/_tmp/npmInstall')
    let port = 8985
    let reg = null

    let env = () => ({
        npm_config_registry: reg.url,
        npm_config_cache: path.join(root, 'npm-cache'),
        npm_config_update_notifier: 'false',
    })
    let prj = (name, pkg) => {
        let d = path.join(root, name)
        fs.mkdirSync(d, { recursive: true })
        fs.writeFileSync(path.join(d, 'package.json'), typeof pkg === 'string' ? pkg : JSON.stringify(pkg))
        return d
    }

    before(async function() {
        fs.rmSync(root, { recursive: true, force: true })
        fs.mkdirSync(root, { recursive: true })
        reg = await hangRegistry(port)
    })

    after(async function() {
        if (reg) await reg.close()
        fs.rmSync(root, { recursive: true, force: true, maxRetries: 5, retryDelay: 200 })
    })

    it('registry 接受連線但永不回應時,時限到即以含「逾時」之錯誤結束,且安裝子行程樹已結束(npm 之連線全數關閉)', async function() {
        let d = prj('hang', { name: 'hang', version: '1.0.0', dependencies: { 'is-number': '7.0.0' } })
        let timeoutMs = 15000
        let t0 = Date.now()
        let err = await withEnv(env(), () => npmInstall(d, { timeoutMs }).then(() => null, (e) => e))
        let ms = Date.now() - t0
        //逾時以錯誤結束,訊息含「逾時」、時限與調整方式
        assert.strict.ok(err instanceof Error, 'npm install 應以錯誤結束')
        assert.strict.match(err.message, /npm install 逾時\(超過 15 秒未完成\)/)
        assert.strict.ok(err.message.includes('已結束安裝子行程樹') && err.message.includes('W_NPM_INSTALL_TIMEOUT'), err.message)
        //不早於時限結束(上限由 mocha 之 timeout 兜底,只防懸置)
        assert.strict.ok(ms >= timeoutMs, String(ms))
        //前提:npm 確已連上無回應之 registry(卡住之原因即該 registry)
        assert.strict.ok(reg.accepted() >= 1, `registry 收到之連線數 ${reg.accepted()}`)
        //整個子行程樹已結束:npm(cmd.exe 之子行程)結束時其連線由作業系統關閉;只結束 cmd.exe 時 npm 續跑、連線仍在
        assert.strict.ok(await reg.allClosed(15000), `仍有 ${reg.open()} 條連線未關閉:npm 行程未結束`)
    })

    it('不需連網之安裝於時限內完成時正常結束,產出 package-lock.json', async function() {
        let d = prj('empty', { name: 'empty', version: '1.0.0', dependencies: {} })
        await withEnv(env(), () => npmInstall(d, { timeoutMs: 60000 }))
        assert.strict.ok(fs.existsSync(path.join(d, 'package-lock.json')))
    })

    it('npm install 以非 0 結束時拋出含離開碼之錯誤(非逾時)', async function() {
        let d = prj('bad', '{ not json')
        let err = await withEnv(env(), () => npmInstall(d, { timeoutMs: 60000 }).then(() => null, (e) => e))
        assert.strict.ok(err instanceof Error)
        assert.strict.match(err.message, /^npm install 失敗\(exit [1-9]\d*\)$/)
    })

})
