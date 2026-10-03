import assert from 'assert'
import path from 'path'
import { resolveLayout } from '../src/layout.mjs'


//opt.fdTools(2026-10-02 擴充)有給時工具改用該共用資料夾,沒給時維持 fdOut/tools;
//fdTools 不可位於 fdOut 之 test(syft 掃描目標)或 pics(每次整夾重建)內
describe('resolveLayout', function() {

    let fdOut = './test/_tmp/resolveLayout/out'
    let outAbs = path.resolve(fdOut)

    it('未給 opt.fdTools 時工具放 fdOut/tools(同 1.0.6)', function() {
        assert.strict.deepEqual(resolveLayout(fdOut), {
            outDir: outAbs,
            testDir: path.join(outAbs, 'test'),
            scanDir: path.join(outAbs, 'scan'),
            picsDir: path.join(outAbs, 'pics'),
            exsbomDir: path.join(outAbs, 'exsbom-work'),
            toolsDir: path.join(outAbs, 'tools'),
            shared: false,
        })
        for (let opt of [null, {}, { fdTools: '' }, { fdTools: undefined }, { fdTools: null }]) {
            let r = resolveLayout(fdOut, opt)
            assert.strict.strictEqual(r.toolsDir, path.join(outAbs, 'tools'), JSON.stringify(opt))
            assert.strict.strictEqual(r.shared, false)
        }
    })

    it('opt.fdTools 相對路徑以 cwd 解析,絕對路徑原樣使用', function() {
        let r = resolveLayout(fdOut, { fdTools: './test/_tmp/resolveLayout/tools' })
        assert.strict.strictEqual(r.toolsDir, path.resolve('./test/_tmp/resolveLayout/tools'))
        assert.strict.strictEqual(r.shared, true)

        let abs = path.resolve('./test/_tmp/resolveLayout/abs-tools')
        assert.strict.strictEqual(resolveLayout(fdOut, { fdTools: abs }).toolsDir, abs)

        //兩個不同 fdOut 給同一 fdTools,工具資料夾相同
        let a = resolveLayout('./test/_tmp/resolveLayout/a', { fdTools: abs })
        let b = resolveLayout('./test/_tmp/resolveLayout/b', { fdTools: abs })
        assert.strict.strictEqual(a.toolsDir, b.toolsDir)
    })

    it('opt.fdTools 位於 fdOut/test、pics 或 exsbom-work(含相等、子夾、大小寫不同)時拋錯', function() {
        let cases = [
            ['test', path.join(fdOut, 'test')],
            ['test', path.join(fdOut, 'test', 'tools')],
            ['test', path.join(outAbs, 'test', 'node_modules', 'x')],
            ['test', path.join(outAbs, 'TEST').toUpperCase()],
            ['pics', path.join(fdOut, 'pics')],
            ['pics', path.join(outAbs, 'pics', 'a', 'b')],
            ['pics', path.join(outAbs, 'Pics')],
            ['exsbom-work', path.join(fdOut, 'exsbom-work')],
            ['exsbom-work', path.join(outAbs, 'exsbom-work', 'tools')],
        ]
        for (let [name, fdTools] of cases) {
            assert.strict.throws(() => resolveLayout(fdOut, { fdTools }), (err) => {
                assert.strict.ok(err.message.includes(`opt.fdTools 不可位於輸出資料夾之 ${name} 內`), err.message)
                assert.strict.ok(err.message.includes(path.resolve(fdTools)), err.message)
                return true
            }, fdTools)
        }
    })

    it('opt.fdTools 為 fdOut 本身、scan、tools、或名稱以 test/pics 開頭之兄弟夾時允許', function() {
        for (let fdTools of [
            fdOut,
            path.join(fdOut, 'scan'),
            path.join(fdOut, 'tools'),
            path.join(fdOut, 'testing'),
            path.join(fdOut, 'pics2'),
            path.join(fdOut, 'exsbom'),
            path.join(fdOut, '..', 'tools'),
        ]) {
            assert.strict.strictEqual(resolveLayout(fdOut, { fdTools }).toolsDir, path.resolve(fdTools))
        }
    })

    it('opt 非物件或 opt.fdTools 非字串時拋錯,不靜默忽略', function() {
        //常見誤用:把 fdTools 直接當第三個參數傳入
        assert.strict.throws(() => resolveLayout(fdOut, './tools'), /opt 需為物件/)
        assert.strict.throws(() => resolveLayout(fdOut, { fdTools: 123 }), /opt\.fdTools 需為資料夾路徑字串/)
        assert.strict.throws(() => resolveLayout(fdOut, { fdTools: ['./tools'] }), /opt\.fdTools 需為資料夾路徑字串/)
    })

})
