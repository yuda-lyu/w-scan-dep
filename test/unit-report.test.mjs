import assert from 'assert'
import { buildReport } from '../src/report.mjs'
import { buildUpdateListMd } from '../src/updatelist.mjs'


//建議w-scan-dep修正.md(Gitea #24)一建議 2、二(主控裁定 2、4): ex-sbom 截圖失敗時 result.md 註明失敗與原因, 並附 ex-sbom.log 摘錄(前 6 行);
//不依賴 ex-sbom 與本機 TCP 表(api-wsdEntry 之崩潰案需真的啟動替身 ex-sbom 並經埠之監聽者查詢確認身分; 2026-10-30 前該查詢為 netstat, 作業系統 TCP 表異常時會假紅, 現改 wsemi 之 execProcessPortPidsSync)
describe('buildReport (ex-sbom screenshot failure)', function() {

    let scan = { osv: { packages: [], mdText: '' }, grype: { matches: [] } }
    let build = (exsbom) => buildReport({ target: 'prj/package.json', toolVersions: {}, scan, exsbom, date: '2026-10-30', picsPrefix: './pics/' })
    let head = 'ex-sbom(PID 1)於截圖期間意外結束(離開碼 2),本次截圖作廢;ex-sbom.log 摘錄:'
    let lines = ['fatal error: stack overflow', 'runtime: goroutine stack exceeds', 'line3', 'line4', 'line5', 'line6', 'line7', 'line8']

    //建議w-scan-dep調整.md(Gitea #27, 主控裁定 3): result.md 寫明掃描範圍(只算 dependencies; 對象為網頁前後端服務或 app, 開發與建置工具不在範圍及其理由), 截圖成敗皆照寫
    it('result.md 之「掃描資訊」寫明掃描範圍: 只算 dependencies(含其所附之執行檔), devDependencies 之開發與建置工具不在範圍', function() {
        let ng = build({ ok: false, error: head, overviewShot: null, componentShots: [], summary: [], removedRelationships: null })
        let ok = build({ ok: true, error: null, overviewShot: 'C:/x/pics/topology-overview.png', componentShots: [], summary: [], removedRelationships: [] })
        let line = '- 掃描範圍：僅 dependencies（正式相依樹，含其所附之執行檔）；devDependencies 之開發與建置工具不在範圍內（其風險由執行機自行掃描或以防毒軟體處理）。'
        for (let md of [ng, ok]) {
            assert.strict.ok(md.includes(line), md)
            //位於「掃描資訊」節內(掃描日期、掃描目標之後, 工具版本表之前)
            assert.strict.ok(md.indexOf('- 掃描目標：') < md.indexOf(line) && md.indexOf(line) < md.indexOf('本次掃描所使用之各工具版本'), md)
        }
    })

    it('截圖失敗: 註明「ex-sbom 截圖失敗，本次無截圖」與原因首行, 不引用截圖', function() {
        let md = build({ ok: false, error: head, overviewShot: null, componentShots: [], summary: [], removedRelationships: null })
        assert.strict.ok(md.includes('ex-sbom 截圖失敗，本次無截圖（ex-sbom(PID 1)於截圖期間意外結束(離開碼 2),本次截圖作廢）。'), md)
        assert.strict.ok(!md.includes('](./pics/'), md)
    })

    it('原因含 log 摘錄時: 附程式碼區塊, 只取前 6 行(其後之行不附, 全文見 result.json)', function() {
        let md = build({ ok: false, error: [head, ...lines].join('\n'), overviewShot: null, componentShots: [], summary: [], removedRelationships: [] })
        assert.strict.ok(md.includes('ex-sbom 結束前之輸出（摘錄）：'), md)
        let block = md.split('```')[1]
        assert.strict.deepStrictEqual(block.trim().split('\n'), lines.slice(0, 6))
        assert.strict.ok(!md.includes('line7') && !md.includes('line8'), md)
    })

    it('原因只有一行時不附摘錄區塊', function() {
        let md = build({ ok: false, error: '埠 18080 啟動失敗', overviewShot: null, componentShots: [], summary: [], removedRelationships: null })
        assert.strict.ok(md.includes('ex-sbom 截圖失敗，本次無截圖（埠 18080 啟動失敗）。'), md)
        assert.strict.ok(!md.includes('ex-sbom 結束前之輸出（摘錄）') && !md.includes('```'), md)
    })

    it('截圖成功且有剔除之循環關係時, 註明剔除者; 失敗時不註明', function() {
        let removedRelationships = [{ from: 'string.prototype.trim@1.2.11', to: 'es-abstract@1.24.2', relationshipType: 'DEPENDENCY_OF' }]
        let ok = build({ ok: true, error: null, overviewShot: 'C:/x/pics/topology-overview.png', componentShots: [], summary: [], removedRelationships })
        assert.strict.ok(ok.includes('剔除 1 筆構成循環之關係') && ok.includes('string.prototype.trim@1.2.11 DEPENDENCY_OF es-abstract@1.24.2'), ok)
        let ng = build({ ok: false, error: head, overviewShot: null, componentShots: [], summary: [], removedRelationships })
        assert.strict.ok(!ng.includes('剔除 1 筆構成循環之關係'), ng)
    })

})


//建議w-scan-dep調整.md(Gitea #27, 主控裁定 5): 待更新套件.md 寫明掃描範圍與「引入路徑只含正式相依樹」(updateList 取自只裝正式相依樹之 npm ls)
describe('buildUpdateListMd (scan scope)', function() {

    it('待更新套件.md 之標頭寫明掃描範圍, 無待更新項目時亦然', function() {
        let md = buildUpdateListMd({ target: 'prj/package.json', date: '2026-10-30', updateList: { byOrigin: new Map(), cascades: [] } })
        assert.strict.ok(md.includes('- 掃描範圍：僅 dependencies（正式相依樹，含其所附之執行檔）；devDependencies 之開發與建置工具不在範圍內（其風險由執行機自行掃描或以防毒軟體處理）；本清單之引入路徑亦只含正式相依樹。'), md)
        assert.strict.ok(md.indexOf('- 掃描目標：') < md.indexOf('- 掃描範圍：') && md.indexOf('- 掃描範圍：') < md.indexOf('本次無需連鎖更新之項目'), md)
    })

})
