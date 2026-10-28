# 規則帳本

本檔為套件設計與開發階段之規則帳本(藍圖),為要求程式碼須長成什麼樣,或由規格產出之測試(項目/說明/流程)有哪些,包含軸、單一擁有者、已知限制、破壞性變更紀錄,以及對應是哪些測試檔案或指令等,由agent自行編列、擴充與維護.當前已做到哪些記於`sgud/state/state.md`.過長時依類型拆為`rulebook_<類型>.md`,本檔只留索引.

## 索引

| 條目 | 內容 | 位置 |
| --- | --- | --- |
| R-BIN-ENSURE-01 | 外部執行檔之存放、下載、校驗與離線(摘要,指回制式規格) | 本檔 |
| §2 前置條件 | 開發時不可放寬之處:ex-sbom 服務埠、身分確認、工作目錄、分析失敗偵測、防火牆(2026-10-29 自 `sgud/proc/process.md` 搬入) | 本檔 |

## R-BIN-ENSURE-01 外部執行檔之存放、下載、校驗與離線

**規格正本**:`C:\opensrcOper\dspec\外部執行檔之存放下載校驗與離線.md`(主控維護,條號 S/M/D/O/E/T 皆指該檔;本節只摘要與記本套件之落實,不重述).共用實作:wsemi `fsEnsureBins`(1.9.27+).

本套件為 **C 類、主幹模式**(`mode: "floating"`,登記於主控帳本 G10):掃描工具須保持新版(使用者 2026-10-28 選),故清單放本 repo 主幹 `bin/manifest.json`,執行時取最新清單,更新工具版本只須推 GitHub,不須發布套件;npm 包內帶同一份作為取不到主幹清單時之基準清單.

### 規則(程式碼須長成什麼樣)

1. **套件端只做三件事**(E2):①提供清單 `bin/manifest.json`(由 `toolg/genBinManifest.mjs` 產生,不手寫);②經 `src/ensureBins.mjs` 取得路徑後啟動;③主函數以靜態屬性 `WScanDep.ensureBins` 匯出(不加具名匯出).不得另寫下載、快取、鏡像、校驗、解壓;不得有 `postinstall`(D1).
2. **清單項**:廠商發布之版本標籤資產網址(`/releases/download/<tag>/…`,不得 `releases/latest`,M2),壓縮檔與解出之執行檔各記 sha256 與大小,`note` 寫明核對依據(廠商 checksums,或「首次下載自算」與日期,M3);repo 內不放任何廠商檔(S3),`bin/` 只有 `manifest.json`.
3. **不入 npm 包**:`.npmignore` 有 `/bin/*`、`!/bin/manifest.json`、`/bin-cache/`、`/test/_tmp/`;`.gitignore` 有 `/bin-cache/`(S1、S5).
4. **所啟動之執行檔一律為 `ensureBins` 回傳之路徑**(`<快取>/<sha256>/<檔名>`);執行期之資料交換檔不寫執行檔所在夾(ex-sbom 之工作目錄為 `fdOut/exsbom-work/<pid>-<6 碼>`,`src/exsbom.mjs`;scan 產物在 `fdOut/scan`).
5. **工具取得先於 `npm install`**:取不到(離線無快取、校驗不符)即中止,不待安裝數分鐘後才失敗(`src/WScanDep.mjs:141`).
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
| Grep `spawn(\|spawnSync(` 於 `src/` | scan.mjs(syft/grype/osv,路徑來自 `tools[…].exePath`)、exsbom.mjs(ex-sbom,路徑來自 `tools['ex-sbom'].exePath`)、WScanDep.mjs(npm install)、exsbom.mjs 之系統指令(netstat、netsh、tasklist、taskkill) | 已套(執行檔路徑皆源自 `ensureBins`) |
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
| 啟動路徑 | `src/scan.mjs:117-119`、`src/WScanDep.mjs:150`(`tools[…].exePath`) | 同行不變,`tools` 來自 `readToolVersions(bins)`(`src/toolVersions.mjs`),路徑即 `ensureBins` 回傳 |
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
| 主函數類入口 | `test/api-wsdEntry.test.mjs` | 攔截全域 `fetch`(斷言未被呼叫)與 `child_process.spawn/spawnSync`(斷言啟動者為 `ensureBins` 回傳之快取路徑、工作目錄為 `exsbom-work`);取得先於 `npm install`;快取在 `fdOut/test` 內被拒;第三參數被拒;靜態屬性匯出 |
| 版本推得 | `test/unit-toolVersions.test.mjs` | 以 sha256 比對基準清單與主幹清單副本取得版本標籤;不符為 `unknown` |
| 工具位置防呆 | `test/unit-layout.test.mjs` | `assertToolsOutside` |
| 更新工具 | `test/unit-genBinManifest.test.mjs` | 本機假 GitHub API:標籤網址、checksums 與 API digest 雙重核對、`--only`/`--tag`、拒絕 draft/prerelease/無可核對來源 |

執行方式:`npm test`(全套,含需連網之 `test/WScanDep.test.mjs`「test」案——完整掃描,首次會下載 162MB 並以新快取路徑啟動 ex-sbom,Windows 防火牆會詢問一次);離線受影響測試:`npx mocha --no-parallel "test/unit-*.test.mjs" "test/api-*.test.mjs" --timeout 180000`.

已知限制:廠商檔之真實 sha256/size 無法離線驗證(測試只驗清單形式與流程);由 `toolg/genBinManifest.mjs` 於產生時以廠商 checksums 與 GitHub API digest 雙重核對,並於 2026-10-29 以真實網路跑 `ensureBins` 取得四個檔、解壓並校驗通過(見報告).

## 2. 前置條件

(2026-10-29 自 `sgud/proc/process.md` 搬入,節號與標題不變;防火牆一條因執行檔路徑改為快取而更新)

- **ex-sbom 服務埠（2026-10-03 起自動選用）**：自 18080 起依序至 18180，取第一個未被監聽（任一位址）且非系統保留之埠（`src/config.mjs`、`src/exsbom.mjs` `startExSbom`），不必再淨空 8080。刻意避開 8080（前端開發伺服器常用，掃描期間占用會使其無法啟動）。ex-sbom 讀 `PORT` 環境變數（v0.2.0 `main.go:56-59`），本套件會覆寫呼叫端已設之 `PORT`。
  - **身分確認**：就緒須「頁面標題為 ex-sbom」且「該埠之監聽 PID 恰為本次子程序」。理由（實測）：埠被占用時 ex-sbom 印 bind 錯誤後以**離開碼 0** 結束；只綁 127.0.0.1 之服務可與 ex-sbom（綁 0.0.0.0、[::]）**同埠並存**——只認標題會連到別人。就緒前子程序結束即換下一個埠，最多 5 次；截圖期間子程序結束即中止。
  - 區間內被占用之埠會記錄占用者 PID 與程式名（不自動結束他人程序）。
- **Windows 防火牆**：ex-sbom 以 `r.Run(":" + port)` 監聽全部網路介面（v0.2.0 `main.go:79`，無法設定只綁本機），防火牆依**執行檔完整路徑**對每個新路徑詢問一次並建 TCP/UDP 兩條規則（本機連接埠為「任一」，故改埠不會再詢問，實測）。選「取消」（封鎖）掃描照常完成——連線走本機迴圈位址（實測：本機 `test/output/tools` 之 ex-sbom 為封鎖規則，掃描與截圖照常）；選「允許」則掃描期間對私人與公用網路開放。
  - **2026-10-29 起執行檔路徑為 `<快取>/<sha256>/ex-sbom.exe`**（預設 `<套件根>/bin-cache/`，或 `W_BIN_CACHE`）：同一版本只在第一次詢問；ex-sbom 換版（sha256 變）即新路徑、再詢問一次。
  - **agent 實跑掃描時，ex-sbom 只能從已有規則之路徑執行**：舊版遺留之 `test/output/tools/ex-sbom/<版>/ex-sbom.exe` 已有規則（`test/WScanDep.test.mjs` 之 `captureExSbom` 案在快取尚無 ex-sbom 時沿用之）；`ensureBins` 快取內之新路徑首次執行會跳詢問、留下規則——勿在 agent 自動化中首次啟動（2026-10-02 曾因驗收用了新路徑 `tmp/accept/out/tools`，留下兩條「允許」規則）。
- **ex-sbom 工作目錄（2026-10-03 修正）**：ex-sbom 把上傳之 SBOM 以原檔名寫入其工作目錄（v0.2.0 `util/file/temp_file.go:34`），處理完才刪且不檢查刪除結果（`internal/service/sbom/spdx_sbom.go:316`；實測刪除成敗不定，ex-sbom 存活時副本常被其自身占用）。現以 `fdOut/exsbom-work/<pid>-<6 碼>` 為其工作目錄，ex-sbom 結束後才刪；開始時只清名稱相符且建立者已不存在之舊子夾。修正前副本落在呼叫端 cwd（本 repo 根目錄之 `syft.spdx.json` 即此來源，已列 .gitignore），並會覆寫、甚至刪除呼叫端 cwd 中之同名檔。此亦使執行期資料不寫入執行檔所在之快取夾（R-BIN-ENSURE-01 規則 4）。
  - 推測（未實測）：內嵌之 osv 掃描可能依 SBOM 所在目錄讀取 `osv-scanner.toml`；修正前會吃到呼叫端 cwd 之設定，修正後不會。
- **ex-sbom 分析失敗之偵測**：ex-sbom 分析失敗時仍回 200、畫面呈「無漏洞」（`spdx_sbom.go:253-267`、`create.go:125-127`）。本套件讀其 log（`exsbom-work/<子夾>/ex-sbom.log`），見副本寫入失敗、SBOM 解析或處理失敗、漏洞掃描失敗即 throw；LEV 查詢失敗只警告。
- **ex-sbom 隨 node 結束**：node 不論如何結束（含 `taskkill /F` 不加 `/T`、Ctrl+C、崩潰），ex-sbom 都會一併結束——libuv 以 Job Object 管理非 detached 子程序（2026-10-03 實測）。故不會留下 ex-sbom 孤兒，最多留下工作子夾（下次掃描清除）。
- 需連外：GitHub（主幹清單與廠商 releases 資產，首次使用；可由 `W_BIN_MIRROR`/`W_BIN_OFFLINE` 改為離線）、npm registry（安裝掃描目標之相依）、grype/osv 漏洞資料庫。
- 需 playwright 之 chromium（本套件相依 `playwright`）；ex-sbom 截圖跑無頭獨立 profile，與使用者瀏覽器無關。
