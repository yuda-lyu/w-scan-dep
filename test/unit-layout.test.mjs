import assert from 'assert'
import path from 'path'
import { resolveLayout, assertToolsOutside } from '../src/layout.mjs'


//產物落點(fdOut 之子夾)與掃描工具位置之防呆。
//2026-10-29 起外部執行檔經 ensureBins 存於快取(預設 <套件根>/bin-cache/, 可由 W_BIN_CACHE 改位置), 不再有 opt.fdTools 與 fdOut/tools;
//工具位置不可位於 fdOut 之 test(syft 掃描目標)、pics(每次整夾重建)或 exsbom-work(每次清除)內
describe('resolveLayout', function() {

    let fdOut = './test/_tmp/resolveLayout/out'
    let outAbs = path.resolve(fdOut)

    it('fdOut 之子夾皆錨定於 fdOut,不再有 toolsDir 與 shared', function() {
        assert.strict.deepEqual(resolveLayout(fdOut), {
            outDir: outAbs,
            testDir: path.join(outAbs, 'test'),
            scanDir: path.join(outAbs, 'scan'),
            picsDir: path.join(outAbs, 'pics'),
            exsbomDir: path.join(outAbs, 'exsbom-work'),
        })
    })

})


describe('assertToolsOutside', function() {

    let fdOut = './test/_tmp/resolveLayout/out'
    let outAbs = path.resolve(fdOut)
    let layout = resolveLayout(fdOut)

    it('工具位於 fdOut/test、pics 或 exsbom-work(含相等、子夾、大小寫不同)時拋錯,訊息含路徑與 W_BIN_CACHE 提示', function() {
        let cases = [
            ['test', path.join(outAbs, 'test', 'syft.exe')],
            ['test', path.join(outAbs, 'test', 'cache', 'w-scan-dep', 'aa', 'syft.exe')],
            ['test', path.join(outAbs, 'test', 'node_modules', 'x', 'syft.exe')],
            ['test', path.join(outAbs, 'TEST', 'syft.exe')],
            ['pics', path.join(outAbs, 'pics', 'a', 'b', 'ex-sbom.exe')],
            ['pics', path.join(outAbs, 'Pics', 'ex-sbom.exe')],
            ['exsbom-work', path.join(outAbs, 'exsbom-work', 'ex-sbom.exe')],
            ['exsbom-work', path.join(outAbs, 'exsbom-work', 'tools', 'x', 'ex-sbom.exe')],
        ]
        for (let [name, p] of cases) {
            assert.strict.throws(() => assertToolsOutside([path.join(outAbs, '..', 'ok', 'a.exe'), p], layout), (err) => {
                assert.strict.ok(err.message.includes(`掃描工具不可位於輸出資料夾之 ${name} 內`), err.message)
                assert.strict.ok(err.message.includes(p), err.message)
                assert.strict.ok(err.message.includes('W_BIN_CACHE'), err.message)
                return true
            }, p)
        }
    })

    it('工具位於 fdOut 本身、scan、tools、名稱以 test/pics 開頭之兄弟夾,或 fdOut 之外時允許', function() {
        for (let p of [
            path.join(outAbs, 'syft.exe'),
            path.join(outAbs, 'scan', 'syft.exe'),
            path.join(outAbs, 'tools', 'syft', 'syft.exe'),
            path.join(outAbs, 'testing', 'syft.exe'),
            path.join(outAbs, 'pics2', 'syft.exe'),
            path.join(outAbs, 'exsbom', 'syft.exe'),
            path.join(outAbs, '..', 'tools', 'syft.exe'),
            path.resolve('./bin-cache/aa/syft.exe'),
        ]) {
            assert.strict.doesNotThrow(() => assertToolsOutside([p], layout), p)
        }
    })

})
