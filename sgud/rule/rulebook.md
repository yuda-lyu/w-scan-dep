# 規則帳本

本檔為套件設計與開發階段之規則帳本(藍圖),為要求程式碼須長成什麼樣,或由規格產出之測試(項目/說明/流程)有哪些,包含軸、單一擁有者、已知限制、破壞性變更紀錄,以及對應是哪些測試檔案或指令等,由agent自行編列、擴充與維護.當前已做到哪些記於`sgud/state/state.md`.過長時依類型拆為`rulebook_<類型>.md`,本檔只留索引.

## 索引

| 條目 | 內容 | 位置 |
| --- | --- | --- |
| R-BIN-ENSURE-01 | 外部執行檔之存放、下載、校驗與離線(摘要,指回制式規格) | 本檔 |
| §2 前置條件 | 開發時不可放寬之處:ex-sbom 服務埠、身分確認、工作目錄、分析失敗偵測、防火牆(2026-10-29 自 `sgud/proc/process.md` 搬入) | 本檔 |
| R-EXSBOM-FAIL-01 | ex-sbom 之任何失敗只作廢截圖;截圖期間意外結束之錯誤訊息附 log 之結束原因(Gitea #24 一建議 2、二) | 本檔 |
| R-EXSBOM-CYCLE-01 | 上傳 ex-sbom 前剔除構成相依循環之關係並回傳剔除者(Gitea #24 一建議 1;上游 ex-sbom v0.2.0 之限制) | 本檔 |
| R-NPM-TIMEOUT-01 | npm install 之時限與逾時之樹狀結束(Gitea #24 三) | 本檔 |
| R-SCAN-TIMEOUT-01 | syft、grype、osv-scanner 之單次時限與逾時之樹狀結束(Gitea #24 三之同類;主控裁定 2026-10-30 run02) | 本檔 |
| R-EXSBOM-PORT-01 | ex-sbom 服務埠之監聽者之身分確認改用 wsemi `execProcessPortPidsSync`(useBoth),不自行解析 netstat;選埠全表快照之 netstat 解析不看狀態欄(2026-10-30 run03,wsemi 1.9.32 報告 §6 第 3 列) | 本檔 |

## R-BIN-ENSURE-01 外部執行檔之存放、下載、校驗與離線

**規格正本**:`C:\opensrcOper\dspec\外部執行檔之存放下載校驗與離線.md`(主控維護,條號 S/M/D/O/E/T 皆指該檔;本節只摘要與記本套件之落實,不重述).共用實作:wsemi `fsEnsureBins`(1.9.27+).

本套件為 **C 類、主幹模式**(`mode: "floating"`,登記於主控帳本 G10):掃描工具須保持新版(使用者 2026-10-28 選),故清單放本 repo 主幹 `bin/manifest.json`,執行時取最新清單,更新工具版本只須推 GitHub,不須發布套件;npm 包內帶同一份作為取不到主幹清單時之基準清單.

### 規則(程式碼須長成什麼樣)

1. **套件端只做三件事**(E2):①提供清單 `bin/manifest.json`(由 `toolg/genBinManifest.mjs` 產生,不手寫);②經 `src/ensureBins.mjs` 取得路徑後啟動;③主函數以靜態屬性 `WScanDep.ensureBins` 匯出(不加具名匯出).不得另寫下載、快取、鏡像、校驗、解壓;不得有 `postinstall`(D1).
2. **清單項**:廠商發布之版本標籤資產網址(`/releases/download/<tag>/…`,不得 `releases/latest`,M2),壓縮檔與解出之執行檔各記 sha256 與大小,`note` 寫明核對依據(廠商 checksums,或「首次下載自算」與日期,M3);repo 內不放任何廠商檔(S3),`bin/` 只有 `manifest.json`.
3. **不入 npm 包**:`.npmignore` 有 `/bin/*`、`!/bin/manifest.json`、`/bin-cache/`、`/test/_tmp/`;`.gitignore` 有 `/bin-cache/`(S1、S5).
4. **所啟動之執行檔一律為 `ensureBins` 回傳之路徑**(`<快取>/<sha256>/<檔名>`);執行期之資料交換檔不寫執行檔所在夾(ex-sbom 之工作目錄為 `fdOut/exsbom-work/<pid>-<6 碼>`,`src/exsbom.mjs`;scan 產物在 `fdOut/scan`).
5. **工具取得先於 `npm install`**:取不到(離線無快取、校驗不符)即中止,不待安裝數分鐘後才失敗(`src/WScanDep.mjs` 之 `await ensureBins(…)`;其前只有 `W_NPM_INSTALL_TIMEOUT` 與三個掃描工具時限環境變數之格式驗證,見 R-NPM-TIMEOUT-01、R-SCAN-TIMEOUT-01).
6. **快取位置不可在 `fdOut` 之 `test`/`pics`/`exsbom-work` 內**(`assertToolsOutside`,`src/layout.mjs:23`):`test` 為 syft 掃描目標,工具放其內會被編入 SBOM;`pics`、`exsbom-work` 每次清除.
7. **`WScanDep` 不接受第三參數**(原 `opt.fdTools` 已移除,原則 14 不留相容層):傳入即 reject,訊息指向 `W_BIN_CACHE`.
8. **`floatingManifestUrl` 不轉傳**(清單信任錨為 GitHub 主幹,M5).
9. rollup UMD 之 external/globals 含 `url`、`crypto`、`stream`、`stream/promises`、`os`(及 wsemi 所用之 `fs`、`path`、`child_process`),`toolg/gDistRollup.mjs`.

### 盤點指令與站點全集

| 盤點指令(可重跑) | 預期 | 判準 |
| --- | --- | --- |
| Grep `releases/latest\|api\.github\.com` 於 `src/` | 無 | 已套(改造前 `src/download.mjs:20` 為 `releases/latest`,已刪) |
| Grep `\bfetch\(` 於 `src/` | 僅 `src/exsbom.mjs`(`probeTitle` 對 127.0.0.1/[::1] 探測 ex-sbom 就緒,非下載) | 已套/刻意不套(本機探測) |
| Grep `postinstall` 於 `package.json`、`scripts/` | 無 | 已套 |
| Grep `spawn(\|spawnSync(` 於 `src/` | proc.mjs(`runTool`:syft/grype/osv 之 `spawn`,路徑來自 `tools[…].exePath`,由 scan.mjs 呼叫;`killTree`:逾時之 taskkill;2026-10-30 起 scan.mjs 不再直接 `spawnSync`)、exsbom.mjs(ex-sbom,路徑來自 `tools['ex-sbom'].exePath`)、install.mjs(npm install 之 `spawn`;2026-10-29 自 WScanDep.mjs 移入)、updatelist.mjs(npm ls)、exsbom.mjs 之系統指令(netstat、netsh、tasklist、taskkill) | 已套(執行檔路徑皆源自 `ensureBins`) |
| `node C:/opensrcOper/tools/scan-bins.mjs --only w-scan-dep` | `OK w-scan-dep: 有清單;用 fsEnsureBins` | 已套 |
| `npm pack --dry-run --json` | 無 exe/zip/dll;`bin/` 只有 `bin/manifest.json` | 已套(T1,`test/unit-binManifest.test.mjs`) |

改造前(HEAD `8529d52`)站點全集與改後對照(`file:line`):

| 站點 | 改前 | 改後 |
| --- | --- | --- |
| 查最新版 | `src/download.mjs:19-27` `fetchLatestRelease`(GitHub API `releases/latest`) | 刪;清單 `bin/manifest.json`(版本標籤網址) |
| 下載 | `src/download.mjs:29-35` `downloadTo`(`fetch`+`writeFile`,無校驗) | 刪;wsemi `fsDownloadFileVerify`(經 `fsEnsureBins`) |
| 解壓 | `src/download.mjs:38-48` `unzipAndFindExe`(`spawnSync` bsdtar) | 刪;`fsEnsureBins` 解壓並校驗 `extract` |
| 版本夾改名 | `src/download.mjs:70-92` `installVerDir` | 刪;`fsEnsureBins` 原子更名進快取 |
| 取得單一/全部工具 | `src/download.mjs:95-148` `ensureTool`、`ensureAllTools`;呼叫端 `src/WScanDep.mjs:144` | 刪;`src/WScanDep.mjs:141` `await ensureBins({ onProgress })` |
| 啟動路徑 | `src/scan.mjs` 之 `runScan`、`src/WScanDep.mjs`(`tools[…].exePath`) | 同行不變,`tools` 來自 `readToolVersions(bins)`(`src/toolVersions.mjs`),路徑即 `ensureBins` 回傳 |
| 共用工具夾 | `src/config.mjs:11` `TOOLS_DIR`、`src/layout.mjs:15-35` `opt.fdTools`/`toolsDir` | 刪;`W_BIN_CACHE`/`cacheDir`,`assertToolsOutside` |
| 資產比對 | `src/config.mjs:24-57` `TOOLS[].matchAsset/kind` | 刪;`TOOLS` 只留 `key/repo/exeName`;資產名在 `toolg/genBinManifest.mjs` 之 `VENDORS` |

### 對應測試(規格 §8)

| 規格項 | 測試檔 | 說明 |
| --- | --- | --- |
| T1 | `test/unit-binManifest.test.mjs` | `npm pack --dry-run`:先放誘餌檔(`bin/__decoy__.exe`、`bin-cache/…`、`test/_tmp/…`),包內無執行檔,`bin/` 只有 `manifest.json` |
| T2(廠商檔改驗網址) | `test/unit-binManifest.test.mjs` | 每項為廠商 repo 之版本標籤資產網址,非 `releases/latest`;sha256/size/extract/note 俱全;repo 內無廠商檔 |
| M1/M2 schema | `test/unit-binManifest.test.mjs` | `fsEnsureBins` 離線空快取得 `E_OFFLINE_MISSING`(非 `E_MANIFEST`) |
| T3 | `test/api-ensureBins.test.mjs` | 本機 HTTP 伺服器扮 GitHub(主幹清單與標籤資產):首次下載→校驗→快取;第二次只取清單、不再下載資產;離線零請求 |
| T4 | 同上 | 同長度竄改、短少、解出檔雜湊錯、404 → `E_HASH_MISMATCH`/`E_SIZE_MISMATCH`/`E_HTTP`,不留檔 |
| T5 | 同上 | `W_BIN_MIRROR` 本地資料夾:離線取得;鏡像檔被竄改→`E_OFFLINE_MISSING`;連網時鏡像優先於 GitHub |
| T6 | 同上 | `W_BIN_OFFLINE=1` 無快取無鏡像→`E_OFFLINE_MISSING`,訊息含檔名、sha256、大小、應放路徑 |
| T7 | 同上 | 快取檔同長度竄改、截短→重新取得 |
| T8 | 同上 | 主幹清單 404、非 JSON、schema 錯→用基準清單 |
| 套件根與 cwd 無關、不轉傳 `floatingManifestUrl` | 同上 | 子行程於他處 cwd 載入;傳入非本 repo 之網址仍取標準主幹清單 |
| 主函數類入口 | `test/api-wsdEntry.test.mjs` | 攔截全域 `fetch`(斷言除本機迴圈位址外未被呼叫)與 `child_process.spawn/spawnSync`(斷言啟動者為 `ensureBins` 回傳之快取路徑、工作目錄為 `exsbom-work`);取得先於 `npm install`(2026-10-29 起 npm install 經 `spawn`);快取在 `fdOut/test` 內被拒;第三參數被拒;靜態屬性匯出 |
| 版本推得 | `test/unit-toolVersions.test.mjs` | 以 sha256 比對基準清單與主幹清單副本取得版本標籤;不符為 `unknown` |
| 工具位置防呆 | `test/unit-layout.test.mjs` | `assertToolsOutside` |
| 更新工具 | `test/unit-genBinManifest.test.mjs` | 本機假 GitHub API:標籤網址、checksums 與 API digest 雙重核對、`--only`/`--tag`、拒絕 draft/prerelease/無可核對來源 |

執行方式:`npm test`(全套,含需連網之 `test/WScanDep.test.mjs`「test」案——完整掃描,首次會下載 162MB 並以新快取路徑啟動 ex-sbom,Windows 防火牆會詢問一次);離線受影響測試:`npx mocha --no-parallel "test/unit-*.test.mjs" "test/api-*.test.mjs" --timeout 180000`.

已知限制:廠商檔之真實 sha256/size 無法離線驗證(測試只驗清單形式與流程);由 `toolg/genBinManifest.mjs` 於產生時以廠商 checksums 與 GitHub API digest 雙重核對,並於 2026-10-29 以真實網路跑 `ensureBins` 取得四個檔、解壓並校驗通過(見報告).

## 2. 前置條件

(2026-10-29 自 `sgud/proc/process.md` 搬入,節號與標題不變;防火牆一條因執行檔路徑改為快取而更新)

- **ex-sbom 服務埠（2026-10-03 起自動選用）**：自 18080 起依序至 18180，取第一個未被監聽（任一位址）且非系統保留之埠（`src/config.mjs`、`src/exsbom.mjs` `startExSbom`），不必再淨空 8080。刻意避開 8080（前端開發伺服器常用，掃描期間占用會使其無法啟動）。ex-sbom 讀 `PORT` 環境變數（v0.2.0 `main.go:56-59`），本套件會覆寫呼叫端已設之 `PORT`。
  - **身分確認**：就緒須「頁面標題為 ex-sbom」且「該埠之監聽 PID 恰為本次子程序」。理由（實測）：埠被占用時 ex-sbom 印 bind 錯誤後以**離開碼 0** 結束；只綁 127.0.0.1 之服務可與 ex-sbom（綁 0.0.0.0、[::]）**同埠並存**——只認標題會連到別人。就緒前子程序結束即換下一個埠，最多 5 次；截圖期間子程序結束即中止截圖（2026-10-29 起 `WScanDep` 只作廢截圖、掃描結果照常寫出，見 R-EXSBOM-FAIL-01；「該埠可能已被他掃描接手」之防護不變）。
  - 區間內被占用之埠會記錄占用者 PID 與程式名（不自動結束他人程序）。
  - **曾有之限制（2026-10-30 run03 已解，見 R-EXSBOM-PORT-01）**：身分確認原依作業系統 TCP 表（自行解析 `netstat -ano`）。Windows 11 26300（KB5127936）之系統 TCP 狀態值錯誤，`netstat -ano` 整列漏列新起之監聽（本機實測新起之監聽約半數不在輸出中）、對外連線反列 LISTENING，使就緒或截圖完成時之確認誤判：漏列他服務之 127.0.0.1 監聽列而連到它，或漏列 ex-sbom 自身而判為「監聽者已非本次」。2026-10-30 起身分確認改用 wsemi `execProcessPortPidsSync(port, { useBoth: true })`（netstat 與 `Get-NetTCPConnection` 取聯集），不再自行解析 netstat。
- **Windows 防火牆**：ex-sbom 以 `r.Run(":" + port)` 監聽全部網路介面（v0.2.0 `main.go:79`，無法設定只綁本機），防火牆依**執行檔完整路徑**對每個新路徑詢問一次並建 TCP/UDP 兩條規則（本機連接埠為「任一」，故改埠不會再詢問，實測）。選「取消」（封鎖）掃描照常完成——連線走本機迴圈位址（實測：本機 `test/output/tools` 之 ex-sbom 為封鎖規則，掃描與截圖照常）；選「允許」則掃描期間對私人與公用網路開放。
  - **2026-10-29 起執行檔路徑為 `<快取>/<sha256>/ex-sbom.exe`**（預設 `<套件根>/bin-cache/`，或 `W_BIN_CACHE`）：同一版本只在第一次詢問；ex-sbom 換版（sha256 變）即新路徑、再詢問一次。
  - **agent 實跑掃描時，ex-sbom 只能從已有規則之路徑執行**：舊版遺留之 `test/output/tools/ex-sbom/<版>/ex-sbom.exe` 已有規則（`test/WScanDep.test.mjs` 之 `captureExSbom` 案在快取尚無 ex-sbom 時沿用之）；`ensureBins` 快取內之新路徑首次執行會跳詢問、留下規則——勿在 agent 自動化中首次啟動（2026-10-02 曾因驗收用了新路徑 `tmp/accept/out/tools`，留下兩條「允許」規則）。
- **ex-sbom 工作目錄（2026-10-03 修正）**：ex-sbom 把上傳之 SBOM 以原檔名寫入其工作目錄（v0.2.0 `util/file/temp_file.go:34`），處理完才刪且不檢查刪除結果（`internal/service/sbom/spdx_sbom.go:316`；實測刪除成敗不定，ex-sbom 存活時副本常被其自身占用）。現以 `fdOut/exsbom-work/<pid>-<6 碼>` 為其工作目錄，ex-sbom 結束後才刪；開始時只清名稱相符且建立者已不存在之舊子夾（`src/exsbom.mjs` `cleanStaleWork`，2026-10-30 起匯出供測試；被占用者記警告略過。確定性測試：`test/unit-exsbom.test.mjs`〈exsbom cleanStaleWork〉，占用者以 `test/tools/holdDir.mjs` 模擬——待占用者印出 cwd 並以改名被拒確認確被持有才呼叫，不以延時同步，另有「占用者啟動後 1500 毫秒才進入該目錄」案證明不依賴 spawn 回傳即持有；經真 ex-sbom 之整合案為 `test/WScanDep.test.mjs`「清除前次殘留之工作子夾…」，受本機 TCP 表異常影響）。修正前副本落在呼叫端 cwd（本 repo 根目錄之 `syft.spdx.json` 即此來源，已列 .gitignore），並會覆寫、甚至刪除呼叫端 cwd 中之同名檔。此亦使執行期資料不寫入執行檔所在之快取夾（R-BIN-ENSURE-01 規則 4）。
  - 推測（未實測）：內嵌之 osv 掃描可能依 SBOM 所在目錄讀取 `osv-scanner.toml`；修正前會吃到呼叫端 cwd 之設定，修正後不會。
- **ex-sbom 分析失敗之偵測**：ex-sbom 分析失敗時仍回 200、畫面呈「無漏洞」（`spdx_sbom.go:253-267`、`create.go:125-127`）。本套件讀其 log（`exsbom-work/<子夾>/ex-sbom.log`），見副本寫入失敗、SBOM 解析或處理失敗、漏洞掃描失敗即 throw；LEV 查詢失敗只警告。throw 由 `captureExSbom` reject，`WScanDep` 標 `result.json` 之 `exsbom.ok=false`（R-EXSBOM-FAIL-01）。
- **ex-sbom 隨 node 結束**：node 不論如何結束（含 `taskkill /F` 不加 `/T`、Ctrl+C、崩潰），ex-sbom 都會一併結束——libuv 以 Job Object 管理非 detached 子程序（2026-10-03 實測）。故不會留下 ex-sbom 孤兒，最多留下工作子夾（下次掃描清除）。
- 需連外：GitHub（主幹清單與廠商 releases 資產，首次使用；可由 `W_BIN_MIRROR`/`W_BIN_OFFLINE` 改為離線）、npm registry（安裝掃描目標之相依）、grype/osv 漏洞資料庫。
- 需 playwright 之 chromium（本套件相依 `playwright`）；ex-sbom 截圖跑無頭獨立 profile，與使用者瀏覽器無關。

## R-EXSBOM-FAIL-01 ex-sbom 之失敗只作廢截圖;意外結束之訊息附 log 之結束原因

來源:Gitea #24(`建議w-scan-dep修正.md`,提出端 cgsmdb)一之建議 2、二;主控裁定 2、4、6(2026-10-29).

### 規則

1. `captureExSbom` 之呼叫點只有一處(`src/WScanDep.mjs:181`),包在 try 內;任何 reject 皆只作廢截圖:`result.json` 之 `exsbom.ok=false`、`exsbom.error=<訊息>`、`overview=null`、`components=[]`、`levelSummary=[]`,刪除 `fdOut/pics`(上次與本次殘缺之截圖皆不留),`result.md` 寫「ex-sbom 截圖失敗,本次無截圖」;syft/grype/osv-scanner 之結果、`result.md`、`待更新套件.md` 照常寫出,`WScanDep` 仍 resolve `'ok'`.
2. 「就緒後子程序結束即中止」與「回傳前重驗埠之監聽者」兩道防護不得移除(該埠可能已被他掃描接手);只是其後果由「整份作廢」改為「只作廢截圖」.
3. `result.json` 之 `exsbom` 鍵固定為 `ok, error, overview, components, levelSummary, removedRelationships`(成功與失敗同形);頂層鍵不變.
4. ex-sbom 子程序結束之原因一律取自其 log 之本次嘗試區段(`exitReasonFromLog`,`src/exsbom.mjs:166`):最後一個行首之 `fatal error:`/`panic:` 行(含其前至多 2 行 `runtime:` 說明)及其後 20 行;無則末 3 個非空行;每行 300 字、總長 1500 字上限.訊息另附離開碼或訊號.頁面操作先失敗時,先等子程序結束事件至多 2 秒再判斷(避免服務消失之頁面錯誤蓋過結束原因).`result.md` 附原因首行與摘錄前 6 行;`待更新套件.md` 註明 ex-sbom 判定之套件未納入.
5. 擇「錯誤訊息附摘錄」而不保留工作子夾:子夾於下次掃描被 `cleanStaleWork` 清除不可靠;原因隨 `exsbom.error` 流到呼叫端;維持「正常結束時 `exsbom-work` 不存在」.

### 盤點指令與站點全集

| 盤點指令(可重跑) | 預期 | 判準 |
| --- | --- | --- |
| Grep `captureExSbom\(` 於 `src/` | 只有 `src/WScanDep.mjs:181`(try 內) | 已套 |
| Grep `logReason\(` 於 `src/exsbom.mjs` | 定義 `:219`;使用 `:299`(就緒前結束)、`:311`(未就緒)、`:428`(截圖期間結束) | 已套(三個「子程序結束/未就緒」之站點皆附 log 摘錄) |
| Grep `本次結果作廢` 於 `src/` | 無(已改「本次截圖作廢」) | 已套 |
| `captureExSbom` 之 reject 站點(Grep `throw new Error` 於 `src/exsbom.mjs`) | workRoot 未指定、SBOM 無法解析、無可用之埠、連續 5 次啟動失敗、查詢埠之監聽者失敗(`portListeners` 拋錯,R-EXSBOM-PORT-01;2026-10-30 前為 netstat 失敗)、分析 SBOM 失敗(log fatal)、截圖完成時埠之監聽者已非本次、截圖期間意外結束、playwright 等候逾時 | 皆經 `WScanDep` 之同一 catch(已套) |

### 對應測試

| 項目 | 測試檔 | 說明 |
| --- | --- | --- |
| WScanDep 層:ex-sbom 截圖期間結束 | `test/api-wsdEntry.test.mjs`「should keep the syft, grype and osv-scanner results…」 | 扮演 ex-sbom 之 `test/tools/fakeExSbom.mjs` 於瀏覽器請求後以 Go 之 stack overflow 輸出結束(離開碼 2);斷言 resolve `'ok'`、三種掃描結果、`exsbom.ok=false`、error 含離開碼與 log 之 fatal error、上次截圖已刪、`exsbom-work` 已刪、`result.md` 註明 |
| WScanDep 層:ex-sbom 無法啟動 | 同檔「should obtain the tools by ensureBins before npm install…」 | 攔截 ex-sbom 之 spawn 拋錯 → `exsbom.ok=false` |
| 真 ex-sbom 之 stack overflow 訊息 | `test/WScanDep.test.mjs`「ex-sbom 於截圖期間因 stack overflow 結束…」 | `opt.breakCycles:false` 重現上游缺陷;訊息含 `離開碼 2`、`fatal error: stack overflow`、`getSpdxDependencyDepthMap`,長度 < 2000 |
| 被結束時訊息含離開碼 | 同檔「就緒後 ex-sbom 結束時立即中止…」 | |
| 摘錄函數 | `test/unit-exsbom.test.mjs`〈exsbom exitReasonFromLog〉 | runtime 說明行、panic、只看本次區段、長度上限 |
| 完整掃描之截圖成功 | `test/WScanDep.test.mjs`「test」 | 失敗不再 reject,故斷言 `exsbom.ok===true` |

## R-EXSBOM-CYCLE-01 上傳 ex-sbom 前剔除構成相依循環之關係

來源:Gitea #24 一之建議 1;主控裁定 2、3.上游缺陷(ex-sbom v0.2.0 `internal/service/sbom/spdx_sbom.go:140` `getSpdxDependencyDepthMap` 不記錄已走過之節點,遇循環無限遞迴、`fatal error: stack overflow`、離開碼 2)依專案原則 15 在本套件繞過,**不回報上游**.

### 規則

1. 建圖須與上游一致(2026-10-29 實讀 v0.2.0 原始碼):每筆 `relationships` 為 `spdxElementId → relatedSpdxElement` 之邊、**不看關係類型**;識別碼去 `SPDXRef-` 前綴(外部文件參照取文件名);一端為 `DOCUMENT`、`DocumentRoot-*`、`File-*` 者略過.不得只處理 `DEPENDENCY_OF`.
2. 以深度優先(堆疊迭代,不用遞迴)找回邊:起點先為入度 0 之節點(同上游),再補走其餘;同一對節點之重複關係各自判定.剔除後之圖須無循環.入度 0 之節點走不到之循環亦剔除(刻意):上游之根依 map 走訪順序隨機、其後另補根(`getRootComponents`,定義未讀),只剔除可達者無法保證任何走訪皆不無限遞迴;代價是該循環之節點在拓撲中可能成為第 0 級.可達之循環被剔除之回邊,其指向之節點仍保有樹邊,不會因剔除而變成新根.
3. 無循環時上傳原檔;有剔除時把剔除後之 JSON 寫入本次工作子夾之 `upload/<原檔名>` 再上傳,**syft 之原檔不動**(grype 與 osv-scanner 不受影響).
4. 剔除者回傳為 `removedRelationships: [{ from, to, relationshipType, spdxElementId, relatedSpdxElement }]`(from/to 為 `名稱@版本`,查無套件時為識別碼);無循環為 `[]`;`captureExSbom` 失敗時附於錯誤物件,`WScanDep` 寫入 `result.json`(失敗且尚未算出時為 `null`),`result.md` 附註(截圖成功時).
5. `opt.breakCycles:false` 只供測試重現上游缺陷.

### 盤點指令與站點全集

| 盤點指令(可重跑) | 預期 | 判準 |
| --- | --- | --- |
| Grep `setInputFiles` 於 `src/` | 只有 `src/exsbom.mjs:457`,上傳 `uploadPath` | 已套(上傳者即剔除後之檔) |
| Grep `breakDependencyCycles` 於 `src/` | 定義 `src/exsbom.mjs:102`;使用 `captureExSbom` 一處 | 已套 |

### 對應測試

| 項目 | 測試檔 | 說明 |
| --- | --- | --- |
| 真 ex-sbom:含循環之 SBOM 產出截圖 | `test/WScanDep.test.mjs`「含相依循環之 SBOM…」 | fixture `test/fixtures/cycle.spdx.json`(es-abstract ⇄ string.prototype.trim,has-symbols 自入度 0 走到循環;版本與相依皆經 npm registry 查證);斷言截圖、semver 卡片、剔除清單、原檔不變 |
| 無循環不剔除 | 同檔「無循環之 SBOM 不剔除任何關係…」 | |
| 演算法 | `test/unit-exsbom.test.mjs`〈exsbom breakDependencyCycles〉 | 以 Kahn 拓撲排序獨立判定剔除後無循環;自我循環、三節點循環、重複關係、不看類型、略過 DOCUMENT/DocumentRoot/File、不可達循環、深度 5 萬之鏈 |
| WScanDep 層:失敗時仍列剔除者 | `test/api-wsdEntry.test.mjs` | 見 R-EXSBOM-FAIL-01 |

## R-EXSBOM-PORT-01 ex-sbom 服務埠之監聽者之身分確認(wsemi `execProcessPortPidsSync`)

來源:主控派工 run03(2026-10-30);wsemi 1.9.32 `execProcessPortPids`/`execProcessPortPidsSync`(報告 `C:\opensrcOper\dnow\20261030064553\agent-out\run01-修正報告.md` §6 第 3 列)。背景:本機(及 SEMI-WIN-DEV2;Windows 11 26300 + KB5127936)之系統回報 TCP 連線狀態值錯誤,`netstat -ano` 整列漏列新起之監聽、對外連線反列 LISTENING;以 netstat 判斷「誰在監聽某埠」者皆誤判(run01、run02 之全套因此 8 案未綠,主控經驗第三十七節)。

### 規則

1. 「誰在監聽某埠」之判斷(就緒、截圖完成時之重驗、關閉後之釋放確認)一律經 `src/exsbom.mjs` 之 `portListeners(port, opt)`／`ownsPort(port, pid, opt)` → wsemi `execProcessPortPidsSync(port, { useBoth: true })`;**不自行解析 netstat**。Windows 下 wsemi 先 netstat、查無或失敗再以 `Get-NetTCPConnection -LocalPort` 確認,`useBoth` 兩者皆查取聯集(netstat 有列出時預設不再查 PowerShell,會漏掉同埠並存之 127.0.0.1 服務);`useBoth` 不可被呼叫端之 `opt` 覆寫(`...opt` 在其前)。
2. **查詢失敗即拋錯**(`查詢埠 N 之監聽者失敗:<wsemi 之原因>`,原因取自 `opt.onTrace` 之 `settle.msg`);空陣列才是「已確認無人」,不可以失敗代替。`launchOnce` 之 catch 先結束本次子程序再拋出(不留下占埠之子程序);`captureExSbom` 回傳前重驗之失敗經既有 catch 只作廢截圖(R-EXSBOM-FAIL-01 規則 1);`finally` 之釋放確認失敗時不宣稱「埠已釋放」(只影響 log 訊息)。
3. PID 為數字(`Set<number>`);身分確認成立條件為集合**恰為** `{本次子程序之 PID}`。
4. `opt` 僅供測試注入 `{ exec, platform, timeout }`(`exec` 為 spawnSync 形 `(prog, args, { src, timeout, maxBuffer }) => { status, stdout, error }`,以 `src`〔`netstat`、`powershell`、`lsof`〕分派固定輸出;範例 `test/tools/portExecKit.mjs`)。
5. 同步呼叫(wsemi 之同步版,阻塞事件迴圈);本 OS 上新起之監聽與無人之埠每次約 0.8～1 秒(`Get-NetTCPConnection` 之 PowerShell 5.1 冷啟動)。ex-sbom 為獨立行程,不受阻塞影響;每次擷取之呼叫數為就緒時 1 次(就緒輪詢中每輪標題探測成功後各 1 次)＋回傳前重驗 1 次＋結束後釋放確認 1 次。
6. **選埠用之全表快照 `listeningPorts()`／`parseNetstat` 仍為 netstat**:wsemi 只提供單一埠之查詢、無全表,逐埠查詢每次約 1 秒、不適用於掃描整個埠區間(18080～18180)。其漏列只會使選埠多選到實際被占用之埠,而 ex-sbom 於被占用之埠 bind 失敗即結束(「子程序於就緒前結束」)或身分確認不符,皆換埠重試(`MAX_ATTEMPTS` 5 次、`tried` 不重試同埠)。`parseNetstat` 只以外部位址 `0.0.0.0:0`／`[::]:0` 判定監聽,**不看狀態欄**(2026-10-30 移除 `LISTENING` 之或條件:對外連線反列 LISTENING 不再被當成監聽;方向安全——只會少迴避不存在之占用)。

### 盤點指令與站點全集

| 盤點指令(可重跑) | 預期 | 判準 |
| --- | --- | --- |
| Grep `netstat` 於 `src/` | 只有 `src/exsbom.mjs` 之 `parseNetstat`、`listeningPorts`(選埠全表快照)與註解 | 已套(身分確認不再經 netstat 解析) |
| Grep `listeningPorts\(` 於 `src/` | 定義與 `startExSbom` 之 `opt.snapshot \|\| listeningPorts`(選埠)一處 | 已套(`ownsPort` 與 `finally` 之釋放確認已改 `portListeners`) |
| Grep `ownsPort\(\|portListeners\(` 於 `src/` | `launchOnce` 就緒(`ownsPort`)、`captureExSbom` 回傳前重驗(`ownsPort`)、`finally` 釋放確認(`portListeners`) | 已套(3 處站點皆 useBoth、失敗語意如規則 2) |
| Grep `LISTENING` 於 `src/` | 只有註解 | 已套(不看狀態欄) |

### 對應測試

| 項目 | 測試檔 | 說明 |
| --- | --- | --- |
| 判定與失敗語意(替身) | `test/unit-exsbom.test.mjs`〈exsbom portListeners 與 ownsPort(身分確認)〉 | spawnSync 形之 `opt.exec`(`test/tools/portExecKit.mjs`);恰為本次子程序才 ok、**netstat 漏列而 Get-NetTCPConnection 有**、他服務只在其中一個來源(useBoth 聯集)、無人為空集合不拋錯、不依狀態欄(含對外連線反列 LISTENING)、去重、他埠之列(前綴/後綴相同)不混入、`useBoth` 不可被蓋掉、各種失敗(皆不可執行、PowerShell 逾時/離開碼/無法解析、useBoth 下 PowerShell 失敗不以 netstat 之部分結果代替、exec 拋錯、埠號不合法)皆拋錯含原因 |
| 選埠快照不看狀態欄 | 同檔〈exsbom 選埠與 log 分類〉之 `parseNetstat` 兩案 | 對外連線反列 LISTENING 不收;狀態字錯誤(CLOSED、FIN_WAIT_1)之萬用位址列仍收 |
| 真實環境 | `test/api-exsbomPort.test.mjs` | 真實 netstat、Get-NetTCPConnection 與真實監聽行程(`test/tools/holdPort.mjs`,埠 8991～8996,只綁本機迴圈位址):認得子程序 PID、結束後空集合、同埠並存之他監聽者(127.0.0.1 與 127.0.0.2)、無人之埠;`startExSbom` 以 `NODE_OPTIONS=--import` 預載 `fakeExSbom` 扮 ex-sbom:新起之監聽經真實查詢確認而就緒;在真實 `child_process.spawnSync` 接縫注入 netstat/powershell 失敗 → `startExSbom` 拋錯且埠上不留子程序 |
| 經真 ex-sbom 之整合案(run01、run02 之 8 案) | `test/WScanDep.test.mjs`〈captureExSbom〉、`test/api-wsdEntry.test.mjs` 之崩潰案 | 全套 `npm test` |

### 已知缺口

- `captureExSbom` 之 `finally` 釋放確認之 log 訊息(「已關閉,埠已釋放」／「可能未完全關閉」)無測試(需整個截圖流程含 playwright 才走到)。
- 回傳前重驗(`captureExSbom` 內之 `ownsPort`)之「查詢失敗」分支無直接測試;失敗語意由 `portListeners` 之單元測試與 `startExSbom` 之 fail-closed 案(同一函數)涵蓋。
- Linux/macOS 之 lsof 路徑(wsemi 內)本機未實跑:本套件之 netstat/netsh/tasklist/taskkill 本即只支援 Windows。

## R-NPM-TIMEOUT-01 npm install 之時限

來源:Gitea #24 三;主控裁定 5.

### 規則

1. `npm install` 只經 `src/install.mjs` 之 `npmInstall`(非同步 `spawn`,`shell:true`,`windowsHide`);逾時以 `taskkill /F /T /PID <cmd.exe>` 結束**整個子行程樹**(只結束 cmd.exe 時 npm 之 node 續跑),回驗子行程已結束後拋 `npm install 逾時(超過 … 未完成),已結束安裝子行程樹;可設環境變數 W_NPM_INSTALL_TIMEOUT(秒)調整時限`.等待、樹狀結束、環境變數解析之共用實作在 `src/proc.mjs`(`waitChild`、`killTree`、`timeoutMsFromEnv`;2026-10-30 自 install.mjs 抽出,與 R-SCAN-TIMEOUT-01 共用).
2. 時限只由環境變數 `W_NPM_INSTALL_TIMEOUT`(秒,正數,至多 2147483——超過 2^31-1 毫秒時 `setTimeout` 會改為 1 毫秒)調整;`WScanDep` 不接受第三參數(R-BIN-ENSURE-01 規則 7).預設 1200 秒(實測 2000 套件約 4 分鐘,取約 5 倍).值不合法時於任何下載與寫入前拋錯(`src/WScanDep.mjs` 開頭之 `npmInstallTimeoutMs()`),不靜默改用預設.逾時後等子行程結束之計時器於結束時清除(不拖住呼叫端結束);taskkill 失敗時至少結束 cmd.exe,訊息寫「未確認成功」.
3. 非 0 結束之訊息維持 `npm install 失敗(exit N)`.

### 盤點指令與站點全集

| 盤點指令(可重跑) | 預期 | 判準 |
| --- | --- | --- |
| Grep `npm install` 於 `src/`(程式碼) | 只有 `src/install.mjs` 之 `npmInstall` | 已套 |
| 同類(連網之外部指令無時限):Grep `spawnSync\(` 於 `src/scan.mjs`、`src/updatelist.mjs` | `scan.mjs` 無 `spawnSync`;syft、grype(可能更新漏洞資料庫)、osv-scanner(查 osv.dev)已改經 `runTool` 加時限(2026-10-30 run02,見 R-SCAN-TIMEOUT-01) | **已套**(三工具);`updatelist.mjs` 之 npm ls(`spawnSync`)**刻意不套**:只讀本機 node_modules、不連網 |

### 對應測試

| 項目 | 測試檔 | 說明 |
| --- | --- | --- |
| 逾時與樹狀結束 | `test/api-npmInstall.test.mjs` | 真實 npm 對 `test/tools/hangRegistry.mjs`(接受連線永不回應,埠 8985);時限 15 秒;斷言訊息、不早於時限、registry 確有連線、其後所有連線皆被關閉(npm 行程已結束) |
| 正常完成與非 0 結束 | 同上 | 無相依之安裝於時限內完成;壞 package.json 為 `npm install 失敗(exit N)` |
| 環境變數之解析 | `test/unit-npmInstallTimeout.test.mjs` | 預設、正數秒、非正數拋錯 |
| WScanDep 之串接 | `test/api-wsdEntry.test.mjs`「should stop npm install with a timeout error from W_NPM_INSTALL_TIMEOUT…」「should reject a W_NPM_INSTALL_TIMEOUT that is not a positive number…」 | 時限 5 秒之真實 npm 對無回應 registry(埠 8987)→ 逾時、未進入掃描;格式錯誤 → 未取工具、未建 fdOut |

## R-SCAN-TIMEOUT-01 syft、grype、osv-scanner 之單次時限

來源:Gitea #24 三之同類;主控裁定(run01 §10-②,2026-10-30):三工具之 `spawnSync` 比照 R-NPM-TIMEOUT-01 加時限.

### 規則

1. 三工具只經 `src/scan.mjs` 之 `run` → `src/proc.mjs` 之 `runTool`(非同步 `spawn`,不經 shell,`stdio: ['ignore','pipe','pipe']`,`windowsHide`;stdout/stderr 以 Buffer 收集後 utf8 解碼,上限 64 MB,超過結束子行程並拋 `<工具> 執行錯誤: 輸出超過 … 位元組`;`spawn` 同步拋錯與 `error` 事件同樣包成 `<工具> 執行錯誤: …`).以 `exit` 判定結束(已結束者不再 taskkill,避免對已被重用之 PID 動手),其後最多再等 2 秒讓輸出串流收尾(子孫行程仍握著管道時不無限等).不得再用 `spawnSync`(`spawnSync` 之 `timeout` 只結束直接子行程、且阻塞事件迴圈).`runSyft`、`runGrype`、`runOsv`、`runScan` 因而為非同步(`runSyft` 原為同步函式,深層匯入者須 `await`).
2. 時限為**單次執行**(osv-scanner 對 markdown 與 json 各跑一次,各自計時),由環境變數(秒,十進位正數〔可含小數、指數;不收 `0x10` 等進位寫法〕,換算後至少 1 毫秒、至多 2147483 秒;與 `W_NPM_INSTALL_TIMEOUT` 同風格,共用 `timeoutMsFromEnv`)各自調整:`W_SYFT_TIMEOUT`(預設 3600)、`W_GRYPE_TIMEOUT`(預設 1800)、`W_OSV_SCANNER_TIMEOUT`(預設 600).值不合法時於任何下載與寫入前拋錯(`WScanDep` 開頭之 `scanTimeoutsMs()`,與 `npmInstallTimeoutMs()` 同處),不靜默改用預設;`WScanDep` 不接受第三參數(R-BIN-ENSURE-01 規則 7).`runSyft`/`runGrype`/`runOsv` 之末參數 `timeoutMs` 與 `runScan` 之 `timeouts` 供內部與測試傳入(未傳時讀該工具自己的環境變數,不讀他工具的).
3. 預設依實測訂定(2026-10-30,真實專案 1364 個元件、865 個頂層套件):

   | 工具 | 實測 | 預設 | 倍數(對實測最大值) |
   | --- | --- | --- | --- |
   | syft | 首次(新裝檔案,冷)81.2 秒;其後 6.5、6.2 秒;**本機被他程序占滿〔CPU 88%〕時 519 秒**(經 `runScan` 實跑,CPU 時間僅 14 秒餘為等待) | 3600 秒 | 6.9 |
   | grype | 冷資料庫(全新 `GRYPE_DB_CACHE_DIR`,下載加掃描)86.1 秒;暖 2.8、2.8、2.9 秒;機器忙碌時暖資料庫 4 秒 | 1800 秒 | 20.9 |
   | osv-scanner(單次;markdown/json 各 3 次) | 2.6~3.5 秒(機器忙碌時 2.6、3.2 秒) | 600 秒 | 171 |

   預設皆明顯大於實測最大值(`test/unit-scanTimeout.test.mjs` 斷言 ≥ 5 倍).**syft 最初訂 600 秒,被同日機器忙碌時之實測 519 秒推翻(僅差 15%),改 3600 秒**;時限只為擋「卡住」,取寬的代價僅是真卡住時多等.grype:冷啟動下載資料庫之時間隨網路速度成比例,取 20 倍;osv-scanner 實測極短,取 10 分鐘以免因 osv.dev 偶發慢而誤判.機器忙碌時 syft 之耗時可差 80 倍以上(6 秒 → 519 秒),預設不可貼近任何一次實測.
4. 逾時以 `taskkill /F /T /PID <工具>`(本身亦有 15 秒上限)結束**整個子行程樹**;時限邊界上工具剛好自行結束(taskkill 回 128 找不到行程)視為正常結束、不報逾時.回驗已結束後拋 `<工具> 逾時(超過 … 未完成),已結束 <工具> 子行程樹;可設環境變數 <變數名>(秒)調整時限`(taskkill 失敗時訊息寫「未確認成功」並至少結束該行程).逾時使 `WScanDep` 整個 reject(與工具失敗〔非 0 離開碼〕同:不寫出 `result.*`);其後之工具不啟動.
5. 非 0 離開碼仍由呼叫端判斷(`syft 失敗 (code N)`、`grype 失敗 (code N)`、`osv-scanner` 之 0/1/128 為正常),訊息不變.

### 盤點指令與站點全集

| 盤點指令(可重跑) | 預期 | 判準 |
| --- | --- | --- |
| Grep `spawnSync\(` 於 `src/scan.mjs` | 無 | 已套 |
| Grep `runTool\(` 於 `src/` | 定義在 `src/proc.mjs`;呼叫只有 `src/scan.mjs` 之 `run`(syft 一處、grype 一處、osv-scanner 兩處〔markdown、json〕,皆經 `run`) | 已套(4 次呼叫皆有時限) |
| Grep `W_SYFT_TIMEOUT\|W_GRYPE_TIMEOUT\|W_OSV_SCANNER_TIMEOUT` 於 `src/`、`README.md` | `src/scan.mjs` 之 `SCAN_TIMEOUTS`;`src/WScanDep.mjs` 註解與 JSDoc;README 引用區塊〈掃描工具時限〉(在〈外部執行檔〉節之前)與〈Breaking changes〉 | 已套 |
| 同類(其餘外部指令無時限):Grep `spawnSync\(` 於 `src/` | `updatelist.mjs` 之 `npm ls`(本機唯讀);`exsbom.mjs` 之 netstat/netsh/tasklist/taskkill(本機系統指令,瞬間完成) | **刻意不套**(不連網、不依外部服務回應) |

### 對應測試

| 項目 | 測試檔 | 說明 |
| --- | --- | --- |
| 逾時與樹狀結束(syft、grype 各一;osv-scanner 見下列 WScanDep 層) | `test/api-scanTimeout.test.mjs` | 替身 `test/tools/hangTool.mjs`(以 `node.exe` 加 `NODE_OPTIONS=--import` 扮演,連上 `hangRegistry`〔埠 8988〕後永遠等待,另啟 detached 孫行程亦連線);時限 8 秒(須長於兩個 node 啟動並連線);斷言訊息全文、不早於時限、根與孫行程皆曾連線、其後連線全數關閉.osv-scanner 之第一個參數 `-L` 使 node.exe 於載入 preload 前即以離開碼 9 結束,替身無法接住,故不在本檔 |
| 各工具各用自己的環境變數 | 同上 | `W_SYFT_TIMEOUT` 不合法不影響 grype;`runScan` 以傳入之 `timeouts` 為準且 syft 逾時即中止、不啟動後續工具 |
| 預設與環境變數解析 | `test/unit-scanTimeout.test.mjs`、`test/unit-proc.test.mjs`(`timeoutMsFromEnv`、`fmtMs`、`within`) | 預設 3600/1800/600 秒且 ≥ 實測最大值 5 倍;環境變數名;非正數、非十進位數字(`0x10`)、不足 1 毫秒(`1e-7`)、超過 2147483 秒拋錯 |
| `runTool` 基本行為 | `test/unit-proc.test.mjs`〈runTool〉、〈waitChild, killNote〉 | 收集 stdout/stderr(多位元組字元逐位元組分段輸出仍完整)、非 0 離開碼不拋錯、傳入之 env、執行檔不存在、輸出超量、計時器於先解決時清除、時限邊界上自行結束(taskkill 128)不報逾時、`killNote` 措辭 |
| WScanDep 之串接 | `test/api-wsdEntry.test.mjs`「should stop with a timeout error naming <工具> from <變數> …」(syft、grype、osv-scanner 三案)、「should reject a syft, grype or osv-scanner time limit that is not a positive number…」 | 攔截 `spawn`,卡住之工具改啟動 `hangTool.mjs`(埠 8989,時限 8 秒);逾時訊息、樹狀結束、後續工具未啟動、無 `result.json`;不合法值於取工具前拒絕;掃描工具之呼叫序列斷言為 `['npm','tool','tool','tool','tool','spawn']`(以 `spawnSync` 啟動者記為 `spawnSync`,序列不符即失敗) |
