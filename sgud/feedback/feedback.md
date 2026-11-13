# 回饋

任務中發現之自有套件、全域技能、全域設定之調整與抽提提案(只增不改,處置結果另記一列).回饋只是紀錄與提案,實際修改走全域設定 §5.2、§13.

| 日期 | 類別 | 對象 | 內容 | 依據 |
| --- | --- | --- | --- | --- |
| 2026-11-13 | 全域技能 | role-coder-for-test(遷移相依之測試作法;或主控派工模板) | 遷移輪若要「修前紅」,須在改 `package.json`、`npm i`(移除舊相依)**之前**先取修前基線;之後修前之 `src` 因舊相依無法解析而整檔載不起來,紅燈只是模組缺失之弱紅.建議派工提示詞或技能補一句:移除舊相依前先跑受影響之非瀏覽器測試並存 log,再以「暫把啟動點改為不經新套件」之變異證明接線斷言能抓到 | 本輪 `tmp/quiet-run/20261113-144354-pm-sd-red.log`(`before` 因 `playwright` 無法解析而失敗)、`sgud/rule/rulebook.md` R-PW-ONLY-01〈變異〉 |
| 2026-11-13 | 自有套件 | w-playwright(`launchChromium` 之錯誤) | 使用端以固定詞彙之 `exsbom.error` 呈現啟動失敗時,Playwright 原訊息只交 `opt.funLog('launch-error', …)`;使用端若不傳 `funLog`,啟動失敗之診斷(如缺哪個檔、哪個通道)只剩 `E_LAUNCH`／`browser launch failed` 一句.建議 README 補一段「使用端如何把 `funLog` 接到自己的 log」之範例(含 `launch-error` 之第三參數為原錯誤、可能含命令列與設定檔路徑,寫 log 前自行遮罩) | `C:/opensrc/開源-JS-004-3-w-playwright/w-playwright/README.md`「對外錯誤只含固定詞彙」段;本套件接線測試之 `j.exsbom.error` 為 `browser launch failed` |
