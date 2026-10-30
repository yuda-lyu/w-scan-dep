import assert from 'assert'
import { npmInstallTimeoutMs, NPM_INSTALL_TIMEOUT_DEFAULT } from '../src/install.mjs'


//建議w-scan-dep修正.md(Gitea #24)三:npm install 之時限可由環境變數 W_NPM_INSTALL_TIMEOUT(秒)調整,預設 20 分鐘;
//值不為正數時拋錯(不靜默改用預設)(主控裁定 5)
describe('npmInstallTimeoutMs', function() {

    it('未設或空白時為預設 20 分鐘', function() {
        assert.strict.strictEqual(NPM_INSTALL_TIMEOUT_DEFAULT, 1200)
        assert.strict.strictEqual(npmInstallTimeoutMs({}), 1200000)
        assert.strict.strictEqual(npmInstallTimeoutMs({ W_NPM_INSTALL_TIMEOUT: '' }), 1200000)
        assert.strict.strictEqual(npmInstallTimeoutMs({ W_NPM_INSTALL_TIMEOUT: '  ' }), 1200000)
    })

    it('正數秒(含小數、指數)換算為毫秒', function() {
        assert.strict.strictEqual(npmInstallTimeoutMs({ W_NPM_INSTALL_TIMEOUT: '90' }), 90000)
        assert.strict.strictEqual(npmInstallTimeoutMs({ W_NPM_INSTALL_TIMEOUT: '0.5' }), 500)
        assert.strict.strictEqual(npmInstallTimeoutMs({ W_NPM_INSTALL_TIMEOUT: '3600' }), 3600000)
        assert.strict.strictEqual(npmInstallTimeoutMs({ W_NPM_INSTALL_TIMEOUT: '1e3' }), 1000000)
    })

    it('非正數、非數字或超過計時器上限(2147483 秒)即拋錯,訊息含變數名與原值', function() {
        //超過 2^31-1 毫秒時 setTimeout 會改為 1 毫秒,安裝將立即被判逾時
        assert.strict.strictEqual(npmInstallTimeoutMs({ W_NPM_INSTALL_TIMEOUT: '2147483' }), 2147483000)
        for (let v of ['0', '-5', 'abc', '20m', 'Infinity', 'NaN', '2147484', '999999999', '0x10', '1e-7']) {
            assert.strict.throws(() => npmInstallTimeoutMs({ W_NPM_INSTALL_TIMEOUT: v }), (err) => {
                assert.strict.ok(err.message.includes('W_NPM_INSTALL_TIMEOUT 須為正數') && err.message.includes(`「${v}」`), err.message)
                return true
            })
        }
    })

})
