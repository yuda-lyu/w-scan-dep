import assert from 'assert'
import { scanTimeoutsMs, SCAN_TIMEOUTS } from '../src/scan.mjs'


//建議w-scan-dep修正.md(Gitea #24)三之同類(主控裁定 2): syft、grype、osv-scanner 之單次執行時限各由環境變數(秒)調整,
//預設值依實測訂定(R-SCAN-TIMEOUT-01); 值不為正數時拋錯(不靜默改用預設)
describe('scanTimeoutsMs', function() {

    //預設值依實測(1364 個元件之專案): syft 暖 6 秒、冷 81 秒、本機被他程序占滿(CPU 88%)時 519 秒; grype 冷資料庫(含下載)86 秒; osv-scanner 每次 3.5 秒內; 預設取其 5 倍以上
    it('未設或空白時為各工具之預設(syft 60 分鐘、grype 30 分鐘、osv-scanner 10 分鐘), 皆明顯大於實測最大值', function() {
        assert.strict.deepStrictEqual(scanTimeoutsMs({}), { 'syft': 3600000, 'grype': 1800000, 'osv-scanner': 600000 })
        assert.strict.deepStrictEqual(scanTimeoutsMs({ W_SYFT_TIMEOUT: '', W_GRYPE_TIMEOUT: ' ', W_OSV_SCANNER_TIMEOUT: '  ' }), { 'syft': 3600000, 'grype': 1800000, 'osv-scanner': 600000 })
        let measuredMaxMs = { 'syft': 519000, 'grype': 86000, 'osv-scanner': 3500 }
        for (let [k, ms] of Object.entries(scanTimeoutsMs({}))) {
            assert.strict.ok(ms >= measuredMaxMs[k] * 5, `${k}: ${ms}`)
        }
    })

    it('環境變數名與工具對應: W_SYFT_TIMEOUT、W_GRYPE_TIMEOUT、W_OSV_SCANNER_TIMEOUT(與 W_NPM_INSTALL_TIMEOUT 同為秒)', function() {
        assert.strict.deepStrictEqual(Object.fromEntries(Object.entries(SCAN_TIMEOUTS).map(([k, v]) => [k, v.envName])), {
            'syft': 'W_SYFT_TIMEOUT',
            'grype': 'W_GRYPE_TIMEOUT',
            'osv-scanner': 'W_OSV_SCANNER_TIMEOUT',
        })
    })

    it('各自調整、互不影響(正數秒, 含小數)', function() {
        assert.strict.deepStrictEqual(scanTimeoutsMs({ W_SYFT_TIMEOUT: '90' }), { 'syft': 90000, 'grype': 1800000, 'osv-scanner': 600000 })
        assert.strict.deepStrictEqual(scanTimeoutsMs({ W_GRYPE_TIMEOUT: '0.5' }), { 'syft': 3600000, 'grype': 500, 'osv-scanner': 600000 })
        assert.strict.deepStrictEqual(scanTimeoutsMs({ W_OSV_SCANNER_TIMEOUT: '3600' }), { 'syft': 3600000, 'grype': 1800000, 'osv-scanner': 3600000 })
    })

    it('非正數、非數字或超過計時器上限(2147483 秒)即拋錯, 訊息含該工具之變數名與原值', function() {
        for (let [name, tool] of [['W_SYFT_TIMEOUT', 'syft'], ['W_GRYPE_TIMEOUT', 'grype'], ['W_OSV_SCANNER_TIMEOUT', 'osv-scanner']]) {
            assert.strict.strictEqual(SCAN_TIMEOUTS[tool].envName, name)
            for (let v of ['0', '-5', 'abc', '10m', 'Infinity', '2147484', '0x10', '1e-7']) {
                assert.strict.throws(() => scanTimeoutsMs({ [name]: v }), (err) => {
                    assert.strict.ok(err.message.includes(`環境變數 ${name} 須為正數`) && err.message.includes(`「${v}」`), err.message)
                    return true
                })
            }
        }
    })

})
