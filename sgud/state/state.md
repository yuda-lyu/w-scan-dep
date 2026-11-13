# 狀態

本檔記載當前已開發功能之最新狀態:各功能做到哪裡、對應之規則帳本條目與測試檔、已知缺口與待辦、最近一次驗證或發布之版本.只記現況,不寫過程(過程見 `sgud/exp/experience.md`).規則帳本為藍圖(`sgud/rule/rulebook.md`),兩者比對即知尚未做到者.

套件:`w-scan-dep`(`package.json` version 未動,現為 1.0.28;Gitea #24〔run01~03〕與 Gitea #27〔任務 20261030151214 run01,掃描範圍限定 dependencies〕之修正已發布於較早版本).相依 `wsemi` ^1.9.59、`w-playwright` ^1.0.1(2026-11-13 起取代 `playwright`,見下列〈截圖用瀏覽器〉列;遷移輪待主控複審並發布).

## 功能現況

| 功能 | 狀態 | 規則帳本 | 測試 |
| --- | --- | --- | --- |
| 依賴掃描主流程 `WScanDep(fpIn, fdOut, opt)`:npm install → syft/grype/osv-scanner → ex-sbom 截圖 → `result.json`/`result.md`/`待更新套件.md` | 完成;第三參數 `opt` 只含報告用語(`systemName`、`packageNotes`、`debug`、`funLog`,見下列〈報告用語〉列);`opt.fdTools` 已於 2026-10-29 移除(給了即 reject);`opt` 非一般物件亦 reject | §2 前置條件、R-BIN-ENSURE-01 規則 5、7、R-REPORT-TEXT-01 | `test/WScanDep.test.mjs`(完整掃描,需連網、首次啟動新快取路徑之 ex-sbom 會觸發防火牆詢問)、`test/api-wsdEntry.test.mjs` |
| 報告用語由呼叫端傳入(`src/scanOpt.mjs`;`report.mjs` 之 `buildReport` 新增選用參數 `systemName`、`packageNotes`;README〈報告用語〉與〈Breaking changes〉、`WScanDep` 之 JSDoc) | 完成(2026-11-06,排程第 330 項,使用者裁定公開 repo 不得含使用端之專案名、計畫名與業主字樣):預設文字與預設 vue 說明中立(「進行依賴套件掃描」「使用 syft 掃描已安裝之依賴」;vue 說明只留通用事實);`systemName` 代入兩處;`packageNotes` 新增或覆寫套件說明;給與原本等價之選項時報告逐字等於修前產出;`result.json`、`待更新套件.md`、檔名、章節結構不變 | R-REPORT-TEXT-01 | `test/unit-reportOpt.test.mjs`、`test/unit-scanOpt.test.mjs`、`test/unit-readmeRestore.test.mjs`、`test/api-wsdEntry.test.mjs`(2 案)、`test/WScanDep.test.mjs`(1 案)、golden `test/fixtures/report-restored-{ok,ng}.golden.md`、夾具 `test/tools/reportFixture.mjs` |
| 掃描工具取得 `src/ensureBins.mjs`(`WScanDep.ensureBins` 靜態屬性) | 完成:wsemi `fsEnsureBins` 主幹模式;快取 `<套件根>/bin-cache/`,`W_BIN_CACHE`/`W_BIN_MIRROR`/`W_BIN_OFFLINE` | R-BIN-ENSURE-01 | `test/api-ensureBins.test.mjs`(T3~T8)、`test/api-wsdEntry.test.mjs` |
| 清單 `bin/manifest.json`(floating,4 項) | 完成:syft v1.55.0、grype v0.121.0、osv-scanner v2.7.0、ex-sbom v0.2.0(2026-10-29 由 `toolg/genBinManifest.mjs` 產生,廠商 checksums 與 GitHub API digest 核對) | R-BIN-ENSURE-01 規則 2 | `test/unit-binManifest.test.mjs`(T1、T2、schema) |
| 更新工具 `toolg/genBinManifest.mjs` | 完成:查最新版、下載資產與 checksums、核對、寫清單;`--dry-run`、`--only`、`--tag` | R-BIN-ENSURE-01 | `test/unit-genBinManifest.test.mjs` |
| 工具版本標籤推得 `src/toolVersions.mjs` | 完成:由快取路徑 sha256 反查清單 | R-BIN-ENSURE-01 | `test/unit-toolVersions.test.mjs` |
| 工具位置防呆 `assertToolsOutside`(`src/layout.mjs`) | 完成 | R-BIN-ENSURE-01 規則 6 | `test/unit-layout.test.mjs`、`test/api-wsdEntry.test.mjs` |
| ex-sbom 驅動(服務埠、身分確認、工作目錄、log 判定) | 完成 | §2 | `test/WScanDep.test.mjs` 之 `captureExSbom`、`test/unit-exsbom.test.mjs` |
| 埠之監聽者之身分確認(wsemi `execProcessPortPidsSync`,useBoth;失敗即拋錯)與選埠快照不看狀態欄 | 完成(2026-10-30 run03;`src/exsbom.mjs` 之 `portListeners`/`ownsPort`,相依 `wsemi` ^1.9.32) | R-EXSBOM-PORT-01 | `test/unit-exsbom.test.mjs`〈exsbom portListeners 與 ownsPort〉與 `parseNetstat` 兩案、`test/api-exsbomPort.test.mjs`(真實環境)、替身 `test/tools/portExecKit.mjs`、`test/tools/holdPort.mjs` |
| ex-sbom 失敗只作廢截圖(`result.json` 之 `exsbom.ok/error`,刪 pics,報告與待更新清單註明);意外結束之訊息附 log 摘錄 | 完成(2026-10-29 run01,Gitea #24) | R-EXSBOM-FAIL-01 | `test/api-wsdEntry.test.mjs`(fakeExSbom 崩潰、攔截拋錯)、`test/WScanDep.test.mjs`(真 ex-sbom 之 stack overflow、被結束)、`test/unit-exsbom.test.mjs`〈exitReasonFromLog〉 |
| 上傳 ex-sbom 前剔除相依循環(`exsbom.removedRelationships`) | 完成(同上) | R-EXSBOM-CYCLE-01 | `test/unit-exsbom.test.mjs`〈breakDependencyCycles〉、`test/WScanDep.test.mjs`(含循環之 fixture 產出截圖)、`test/fixtures/cycle.spdx.json` |
| npm install 時限(`W_NPM_INSTALL_TIMEOUT`,預設 1200 秒,逾時樹狀結束) | 完成(同上) | R-NPM-TIMEOUT-01 | `test/api-npmInstall.test.mjs`、`test/unit-npmInstallTimeout.test.mjs`、`test/api-wsdEntry.test.mjs` |
| syft／grype／osv-scanner 單次時限(`W_SYFT_TIMEOUT` 3600 秒、`W_GRYPE_TIMEOUT` 1800 秒、`W_OSV_SCANNER_TIMEOUT` 600 秒,逾時樹狀結束;三工具改非同步,共用 `src/proc.mjs`) | 完成(2026-10-30 run02,Gitea #24 同類) | R-SCAN-TIMEOUT-01 | `test/api-scanTimeout.test.mjs`、`test/unit-scanTimeout.test.mjs`、`test/unit-proc.test.mjs`、`test/api-wsdEntry.test.mjs`、替身 `test/tools/hangTool.mjs` |
| 掃描範圍只算 dependencies(隔離安裝 `npm install --omit=dev`;`result.json` 之 `scope: 'dependencies'`;`result.md`、`待更新套件.md` 寫明範圍;`updateList` 只剩正式相依樹;README〈掃描範圍〉與〈Breaking changes〉、`WScanDep` 之 JSDoc) | 完成(2026-10-30,Gitea #27,使用者裁定;不提供掃描開發工具之開關;run02 起範圍不受呼叫端 npm 設定影響:子行程環境移除抵消 `--omit=dev` 者＋安裝後驗證,有 dev 套件即拋錯) | R-SCAN-SCOPE-01 | `test/api-installScope.test.mjs`、`test/api-installScopeEnv.test.mjs`、`test/unit-installGuard.test.mjs`、`test/api-scanScope.test.mjs`(連網＋真 syft)、`test/api-wsdEntry.test.mjs`(指令、`scope`、整合案)、`test/unit-report.test.mjs`、`test/WScanDep.test.mjs`「test」、替身 `test/tools/fakeNpmRegistry.mjs`、`test/tools/scopeFixture.mjs` |
| 隔離安裝沿用呼叫端專案之倉庫位址設定(`src/npmRegistry.mjs`;`WScanDep` 於 `fpIn` 所在資料夾取 `npm config list --json` 之生效 `registry`／`@scope:registry`,寫入 `fdOut/test/.npmrc`;環境變數 `W_NPM_CONFIG_TIMEOUT` 預設 60 秒;README〈隔離安裝沿用呼叫端專案之倉庫設定〉與〈Breaking changes〉) | 完成(2026-10-30,任務 20261030174519 run01,主控提出之 Gitea #27 run02 範圍外發現):只帶位址,不帶 include 等安裝集合設定與認證值;取得失敗(逾時、離開碼非 0、輸出非 JSON、無法啟動、npm 未列出 registry)即拋錯,不進入安裝、`fdOut` 不被建立;`result.*` 欄位不變 | R-NPM-REGISTRY-01 | `test/unit-npmRegistry.test.mjs`、`test/api-npmRegistry.test.mjs`(真實 npm＋假 registry 埠 8971~8973)、`test/api-wsdEntry.test.mjs`〈the registry settings of the calling project〉(埠 8975~8977)、替身 `test/tools/fakeNpm/`(`npm.cmd`＋`fakeNpm.mjs`) |
| 截圖用瀏覽器經 `w-playwright` 啟動(`src/exsbom.mjs` 唯一啟動點 `wpw.launchChromium({ headless: true })`;`package.json` 無 `playwright`／`playwright-core`;`toolg/gDistRollup.mjs` 之 `external`／`globals` 為 `'w-playwright'`;README〈截圖用瀏覽器〉與〈Breaking changes〉) | 完成(2026-11-13,排程第 442 項,任務 20261113103344 pm-sd):守門參數一律由 `w-playwright` 加入;不自動安裝(維持修前行為,取得瀏覽器見 README);`PWDEBUG` inspector 值／`SELENIUM_REMOTE_URL`／`playwright-core` 版本與其內附表不符時拒絕啟動 → 只作廢截圖;`exsbom.error` 改為 `w-playwright` 之固定詞彙 | R-PW-ONLY-01 | `test/unit-pwOnly.test.mjs`(5 案,不啟動瀏覽器)、`test/api-wsdEntry.test.mjs`〈…only through w-playwright…(R-PW-WIRING)〉(替身)與「crash」案(真 headless shell)、`test/WScanDep.test.mjs` |
| 重跑清除上次安裝殘留 | 完成(未動) | — | `test/unit-clearNpmState.test.mjs` |
| osv-scanner 執行與離開碼 | 完成(2026-10-30 改經 `runTool` 非同步執行,離開碼判讀不變) | R-SCAN-TIMEOUT-01 規則 5 | `test/unit-runOsv.test.mjs` |

## 已知缺口與待辦

- **`dist/`、`docs/dist/` 仍為遷移前之舊產物**(2026-11-13):`dist/w-scan-dep.umd.js` 仍 `require('playwright')`,而 `package.json` 已無 `playwright`;發布流程(`script.txt` 含 `gDistRollup`)重產後才改為 `require('w-playwright')`,**不可跳過建置直接發布**.以 `toolg/gDistRollup.mjs` 同選項另編至暫存目錄驗證:產物 `require("w-playwright")`、載入後為函數且帶 `ensureBins`.
- 截圖測試(`WScanDep.test.mjs` 之 `captureExSbom` 組約 8 案)每案各啟動一次 headless shell;`captureExSbom` 無注入瀏覽器之接縫,同檔共用須改 API,本輪未改(headless shell 不觸發錯誤密碼計數,屬效能選做).
- **`dist/`、`docs/dist/` 仍為舊產物**(2026-11-06 sd330):含舊預設文字(使用端之系統名與 vue 現況規劃),由發布流程(`script.txt`)重產後才中立;本輪未重產(`cleanFolder` 會先刪 `dist`、`docs`,失敗無法以 git 還原)。以新 `src/` 另編至暫存目錄之 UMD 已驗證不含舊字樣。git 歷史與已發布之 npm 版本仍含舊文字,無法由本套件消除。
- **使用端升版後須傳入報告用語**:要保留原本那份報告之措辭,傳 `systemName` 與 `packageNotes.vue`(README〈還原成升版前那份報告之措辭〉);未傳者 `result.md` 之上述文字變為中立。
- 「業主」一詞(`src/report.mjs:46`「供業主查核」)為通用角色詞,未改;是否視為使用端字樣由主控裁定(R-REPORT-TEXT-01 已知限制)。

- **`bin/manifest.json` 尚未推上 GitHub 主幹**(本輪不得 commit/push):推上前執行期取主幹清單得 404,退回 npm 包內基準清單(功能正常);推上並發布後主幹模式才完整生效.
- 未發布:`dist/`、`docs/` 為發布時自動產製,本輪未重編(UMD 已以暫存輸出驗證 external/globals 與 default 匯出形態).
- 完整掃描(`test/WScanDep.test.mjs`「test」案)需連網與 npm registry,且首次以快取新路徑啟動 ex-sbom(Windows 防火牆詢問),本輪 agent 未跑,由主控/使用者跑.
- 離線部署之版本一致性:離線(`W_BIN_OFFLINE=1`)用基準清單,其版本為該 npm 包發布時之版本;連網機器若取到較新之主幹清單,兩邊版本不同(README〈外部執行檔〉已說明作法).
- 舊版遺留之 `test/output/tools/`(已 gitignore)仍被 `captureExSbom` 測試在快取尚無 ex-sbom 時沿用(該路徑已有防火牆規則);快取有 ex-sbom 後改用快取.
- 掃描工具時限之預設值依一個真實專案(1364 個元件)之冷啟動實測訂定(syft 81 秒、grype 冷資料庫 86 秒、osv-scanner 3.5 秒內);更大專案或更慢網路請以環境變數調高(README〈掃描工具時限〉).osv.dev 之卡住情形無法量測,以替身模擬.`updatelist.mjs` 之 `npm ls`(`spawnSync`,本機唯讀)刻意無時限.
- `captureExSbom` 中「頁面操作先失敗、ex-sbom 結束事件稍後」之競態以等 exit 至多 2 秒緩解,無確定性測試(未證實根除).

- **作業系統 TCP 表異常已繞過**(2026-10-30 run03):Windows 11 26300(KB5127936)之系統 TCP 狀態值錯誤,`netstat -ano` 整列漏列新起之監聽、對外連線反列 LISTENING;run01、run02 之全套因此 8 案未綠.身分確認已改 wsemi `execProcessPortPidsSync(port, { useBoth: true })`(R-EXSBOM-PORT-01),run03 全套綠.**選埠之全表快照 `listeningPorts()` 仍為 netstat**(wsemi 無全表查詢),漏列只會多選到被占用之埠而換埠重試.
- 身分確認為同步呼叫、本 OS 上每次約 1 秒(阻塞事件迴圈),每次擷取約 3 次;wsemi 預設每個子指令逾時 10 秒,機器極忙致 PowerShell 逾時時查詢失敗 → 拋錯 → 只作廢截圖(fail-closed,未放寬時限).
- 已知缺口(R-EXSBOM-PORT-01):`finally` 之釋放確認 log 訊息無測試;回傳前重驗之「查詢失敗」分支無直接測試.
- 已知缺口(R-SCAN-SCOPE-01):①`api-scanScope.test.mjs` 需連 npm registry(取 `npm_config_registry` 所指者)與真 syft,離線無法跑(其餘新案離線);②(run02 已處理,規則 7)呼叫端 npm 設定抵消 `--omit=dev`:環境變數 `include=dev`／`production=false`／`dev=true`／`also=dev` 由子行程環境副本移除,設定檔層(使用者層、全域層、安裝目錄內)由安裝後驗證拋錯;未實測之局限:`install-strategy=linked` 等改變 `node_modules` 版面之設定、`optionalDependencies`／根專案 `peerDependencies`／workspaces 無夾具;③使用端專案(`E:` 槽)本機不存在,真實驗收以同形態替身 `package.json` 進行,提出端之三個專案需其於新版發布後自行重掃確認(建議檔〈驗證建議〉1~3).
- 已知缺口(R-NPM-REGISTRY-01):①registry 網址內嵌帳密時 npm 視為受保護而不列出,`WScanDep` 無從得知位址而拋錯(請改以 `//主機/:_authToken` 依主機鍵設定認證);內嵌帳密之 `@scope:registry` 缺席與未設無從區分,不會被沿用;②`cafile`、`strict-ssl`、代理等 TLS／代理設定不帶(裁定 3 只帶位址;私有倉庫須專案層才有之自簽憑證設定時,隔離安裝連線失敗);③workspaces(monorepo 成員)無夾具,未驗證;④`api-wsdEntry` 既有案(攔截 `spawn`、`npmMode: 'ok'`)現會真的執行一次 `npm config list --json`(放行,不計入呼叫序列),結果取決於開發機之使用者層設定,僅寫入各案之暫存夾.
- 「清除前次殘留之工作子夾」案之時序假設已修(2026-10-30 run02):占用者改由 `test/tools/holdDir.mjs` 等確被持有才往下;清除邏輯另有不經 ex-sbom 之確定性單元測試(`cleanStaleWork` 已匯出).

## 最近一次驗證

2026-11-13(任務 20261113103344 pm-sd,截圖用瀏覽器改經 `w-playwright`):**全套 `npm test`(`--lock`)376 通過／0 失敗／0 略過**(約 1 分 44 秒;原 370 + 新增 6 案:`unit-pwOnly` 5、`api-wsdEntry` 接線 1);含真實掃描「test」案(真 syft/grype/osv-scanner/ex-sbom,經 `w-playwright` 啟動 headless shell 並產出截圖)與 `captureExSbom` 組 10 案;全套前後錯誤密碼次數 0→0;變異 M1(啟動點不經 `wpw`)、M2(`src` 直接匯入 `playwright-core`)、M3(`package.json` 宣告 `playwright-core`)皆被抓到;R-PW-ONLY 盤點 0 命中(防空集合對照命中 2 行);以同選項另編 UMD 至暫存目錄,`w-playwright` 為 external;標準圖 0 張(本套件無像素基準).報告:`C:\opensrcOper\dnow\20261113103344\agent-out\pm-sd-修正報告.md`.

2026-11-06(任務 20261106102000 sd330,報告用語由呼叫端傳入):**全套 `npm test`(`--lock`)兩次皆 0 失敗**——第 1 次 359 通過(約 3 分 14 秒,審查前),第 2 次(最終碼)370 通過(約 1 分 49 秒;原 235 + 新增 135 案:`unit-reportOpt`、`unit-scanOpt`、`unit-readmeRestore`、`api-wsdEntry` 2 案,另改 `WScanDep.test.mjs` 1 案);修前紅(未改 `src` 之碼跑新測試)`unit-reportOpt`＋`api-wsdEntry` 受影響案 23 紅/33 綠(綠者為「非預期值視為未給」之守護案)、`unit-scanOpt` 因模組不存在整檔無法載入;變異 34 個(M1~M33、M12b)皆被抓到(M18 初版存活,補「不成為 unhandledRejection」案後被抓);eslint 變更行 0 error(`config.mjs`、`report.mjs` 既有舊問題 7 項未動);以新 `src` 另編 UMD 至暫存目錄驗證可打包、不含舊字樣;唯讀獨立審查(sonnet)17 項,6 項屬實已修、4 項屬實以文件註明、1 項屬實未修需裁示(`dist/`)、其餘 6 項不構成或依派工保留。報告:`C:\opensrcOper\dnow\20261106102000\agent-out\sd330-修正報告.md`.

2026-11-02(任務 20261102182000 pk-scan-dep,npm 包檢查改依 `dspec/自有套件之npm發布範圍.md` 原則 2〈套件測試之 npm 包檢查〉):`test/unit-binManifest.test.mjs` 之 T1 案不再斷言 `sgud/` 不入包,改斷言 `sgud/state/state.md`、`test/tools/` 隨包並擴充「不得入包」至 `.node`／`.gz`／`.tgz`／`CLAUDE*.md`／`tmp/`／`.env`;`.npmignore` 首段改為完整抄錄 `.gitignore`、其後排除項加註原則 2 第 1 條(打包清單 113 檔不變,其中 `sgud/` 4 檔,執行期 `src/`+`dist/`+`bin/` 15 檔 442,040 位元組);修前 `unit-binManifest` 6 通過/1 失敗(`sgud/` 不應入包),修後 7/0;變異 6 個(假 `.dll`、`sgud` 不入包、`test/tools` 不入包、`CLAUDE*.md`／`tmp`／`.env` 排除規則移除)皆被抓到;全套 `npm test`(`--lock`)235 通過/0 失敗(約 3 分 13 秒).報告:`C:\opensrcOper\dnow\20261102182000\agent-out\pk-scan-dep-修正報告.md`.

2026-10-30(任務 20261030174519 run01,隔離安裝沿用呼叫端專案之倉庫位址設定):**全套 `npm test`(`--lock`)235 通過/0 失敗**(兩次,約 1 分 25~35 秒;run02 之 178 + 新增 57 案:`unit-npmRegistry` 25、`api-npmRegistry` 22、`api-wsdEntry` 10);修前紅(`WScanDep` 不查詢、不寫 `.npmrc` = 修前行為)`api-wsdEntry` 新案 9 紅(`npm install 失敗(exit 1)`:由使用者層之 B 解析);變異 M0~M17 共 18 個皆被抓到(對照組全綠);eslint 變更檔 0 error.報告:`C:\opensrcOper\dnow\20261030174519\agent-out\run01-修正報告.md`.

2026-10-30(任務 20261030151214 run02,Gitea #27 之 §9 待裁示:範圍不受呼叫端 npm 設定影響):**全套 `npm test`(`--lock`)178 通過/0 失敗**(約 1 分 44 秒;run01 之 154 + 新增 24 案:`unit-installGuard` 11、`api-installScopeEnv` 11、`api-wsdEntry` 2);修前紅(= run01 之碼,子行程不傳環境副本且無安裝後驗證)12 案紅;變異 M0~M14 共 15 個皆被抓到;npm 設定探測 22 案(`npm_config_include`／`production`／`dev`／`also` 及使用者層、全域層、安裝目錄內設定檔會抵消 `--omit=dev`,呼叫端專案 `.npmrc` 不會被讀到);eslint 變更行 0 error(`install.mjs:137` 為既有舊問題).報告:`C:\opensrcOper\dnow\20261030151214\agent-out\run02-修正報告.md`.

2026-10-30(任務 20261030151214 run01,Gitea #27 掃描範圍限定 dependencies):**全套 `npm test`(`--lock`)154 通過/0 失敗**(兩次,約 1 分 40 秒;原 144 + 新增 10 案);修前紅(暫將 `NPM_INSTALL_ARGS` 改回修前值)6 案紅〔`api-installScope` 3、`api-scanScope` 1、`api-wsdEntry` 2〕;變異 M1、M2、M4~M8 皆被抓到(M2 於初版夾具存活,補 `peer-only` 後被抓);真實驗收(替身專案,真 syft/grype/osv-scanner,不含 ex-sbom):SBOM 65→60 元件、npm 套件清單 57 項不變、`esbuild.exe`／`clipboard_*.exe`／Go 標準庫不在、`libvips`／`term-size.exe`／`vue` 仍在、grype 62→3、osv-scanner 2 個套件→1 個;eslint 變更行 0 error(檔內既有 20 個舊問題未動).報告:`C:\opensrcOper\dnow\20261030151214\agent-out\run01-修正報告.md`.

2026-10-30(run03,埠之監聽者之身分確認改 wsemi):**全套 `npm test`(`--lock`)144 通過/0 失敗**(兩次:修改後與最終碼;run01、run02 為 107/8 等);修前探測(真實 0.0.0.0 監聽之子程序 5 次)舊作法身分確認成功 2/5、wsemi `useBoth` 5/5;修前整合案(`WScanDep.test.mjs` 之 `captureExSbom` 組,修前工作樹之複本)4 次執行次次有失敗案(8/3、7/4、1/4〔含 hook 連帶〕、10/1),修後 3 次 11/0 全綠;新增與改動之 `unit-exsbom`、`api-exsbomPort` 42 通過;變異 M1~M11 皆被抓到(基準 42/0);eslint 0 error.報告:`C:\opensrcOper\dnow\20261029214736\agent-out\run03-修正報告.md`.

2026-10-30(run02,Gitea #24 同類):受影響之九個測試檔(含新增 `unit-proc`、`unit-scanTimeout`、`unit-report`、`api-scanTimeout`)序列跑 62 通過/0 失敗;全套 `npm test` 一次 107 通過/8 失敗,8 項皆 ex-sbom 身分確認受 TCP 表異常影響(含其連帶).變異 X1~X12、M7、M9、M11 皆被抓到(M7/M9/M11 補得 log).真實 syft/grype/osv-scanner 經新 `runScan` 與修正前等價(1364 元件、grype 53、osv 22).報告:`C:\opensrcOper\dnow\20261029214736\agent-out\run02-修正報告.md`.

2026-10-30(run01,Gitea #24):全套 `npm test` 三次(75/8、84/5、78/5 通過/失敗),新增與改動之測試皆綠;殘餘失敗皆為既有之 captureExSbom 案受上列 TCP 表異常影響.`WScanDep.test.mjs` 序列跑 11/2(新案全綠,紅者為「只綁 127.0.0.1」與「清除前次殘留」).變異 12 個(M1~M12)皆被抓到;對照組皆綠.修正後 WScanDep 對真實含循環專案(string.prototype.trim,4 個回邊)產出截圖與剔除清單.報告:`C:\opensrcOper\dnow\20261029214736\agent-out\run01-修正報告.md`.

2026-10-29(bin-scandep 輪):離線受影響測試全綠(見該輪報告 `C:\opensrcOper\dnow\20261028054319\agent-out\bin-scandep-修正報告.md`);真實網路 `ensureBins` 取得四檔並校驗通過;`node C:/opensrcOper/tools/scan-bins.mjs --only w-scan-dep` 為 OK.
