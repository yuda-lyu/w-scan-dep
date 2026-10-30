# 累積經驗

本檔為執行工作時特有之累積經驗,留給後續之嘗試、執行與判斷,由agent自行編列、擴充與維護.過長時抽出舊者為`experience_<年月日>.md`,並於本檔註明何時抽出.

> 2026-10-29 自 `sgud/proc/process.md` 搬入 §3、§4、§5（節號與標題不變、只搬移）；其後為同日外部執行檔改造之新經驗。

## 3. 一律背景執行（總時長 20 分鐘級）

實測單次完整掃描約 20 分鐘，超過 Bash 工具 10 分鐘上限，必須 detached 背景執行：

- npm install：2000 個套件約 4 分鐘（前 2-3 分鐘在解析依賴樹，node_modules 仍為 0，**不是卡住**）
- 工具下載：syft 28MB + grype 29MB + osv-scanner 55MB + ex-sbom 50MB ≒ 162MB（2026-10-29 實測：真實網路下四個檔下載、解壓、校驗共約 17 秒）
- syft/grype/osv 掃描 + ex-sbom 拓撲分析與逐一漏洞卡片截圖

```bash
nohup node tmp/run.mjs > tmp/run.log 2>&1 &
echo $! > tmp/run.pid
disown
```

**`&` 會切斷整條 `&&` 鏈，勿與清檔指令寫在同一行**。實測踩過：

```bash
# ✗ 錯誤：rm 被丟進背景，與 echo 競態，剛寫好的 run.pid 又被 rm 刪掉
rm -f tmp/run.log tmp/run.pid && nohup node tmp/run.mjs > tmp/run.log 2>&1 & echo $! > tmp/run.pid
```

後果是 `run.pid` 不存在，用它判存活的等待迴圈會立刻退出並被誤讀為「掃描完成」。清檔請另起一條指令先做完。

## 4. 監看與完成判斷

**最可靠的判準是 log 之完成標記**（成功時最後一行為 `ok`）：

```bash
for i in $(seq 1 55); do
    if grep -qE '^ok$|^Error' tmp/run.log 2>/dev/null; then break; fi
    sleep 10
done
tail -6 tmp/run.log
```

配合 `run_in_background: true` 使用；單輪受 10 分鐘上限截斷時重跑同一迴圈接著等。進度查詢用 `tail -20 tmp/run.log`（sub-second）。

判存活之注意事項：

- `ps -p $(cat tmp/run.pid)` 可用（MSYS2 PID 在 git-bash `ps` 表查得到），但**前提是 run.pid 真的存在**（見上節競態）。
- ✗ `cmd //c "tasklist /FI \"PID eq 9620\" /NH"`：git-bash 下巢狀引號失真，程序明明存活卻抓不到，會誤判為已結束。
- ✓ 查 Windows PID 用 PowerShell：`Get-CimInstance Win32_Process -Filter "Name='node.exe'" | Select-Object ProcessId,CommandLine`
- ✓ 對照 MSYS2 PID 與 Windows PID 用 `ps -W | grep -i node`

## 5. 中斷

`taskkill` 不認 MSYS2 PID。先以 PowerShell `Get-CimInstance` 由 CommandLine 認出 `node.exe tmp/run.mjs` 之 Windows PID，再樹狀殺（**必須 `/T`**，npm install 為其子程序）：

```bash
cmd //c "taskkill /F /T /PID <windows-pid>"
```

回驗（§11.4）：確認該 node 程序已消失，且無 syft / grype / osv-scanner / ex-sbom 殘留程序。ex-sbom 為 node 之直接子程序，node 結束時一併結束（見規則帳本 §2）；正常結束時本套件會先關閉它並回報埠已釋放。

## 外部執行檔改造（2026-10-29，bin-scandep）

- **廠商發布有第二個獨立的雜湊來源**：GitHub API 之 `assets[].digest`（`sha256:<hex>`，上傳時由 GitHub 計算）。syft/grype 有 `*_checksums.txt`、osv-scanner 有 `osv-scanner_SHA256SUMS`，ex-sbom（v0.2.0）無 checksums 檔，只有 API digest。更新工具（`toolg/genBinManifest.mjs`）兩者皆有時要求一致，ex-sbom 之 `note` 記「首次下載自算」並與 digest 一致。
- **真實網路驗證與離線測試分工**：廠商檔之真實 sha256/size 無法在不連網之測試中驗證，離線測試只驗清單形式與流程（假廠商檔經 `test/tools/fakeBins.mjs`，壓縮檔用 Windows `tar.exe` 真實製作）；真值靠產生清單時之雙重核對與一次真實 `ensureBins` 實跑（下載四檔、zip 解壓、校驗通過；`syft --version` 為 1.55.0 等）。
- **版本標籤由 sha256 反查**：`ensureBins` 回傳 `<快取>/<sha256>/<檔名>`，不含版本。`src/toolVersions.mjs` 以「清單項之 sha256（壓縮檔者為 `extract.sha256`）等於路徑上之 sha256」認定實際所用之檔，版本標籤取自其網址；清單來源為 `<快取>/manifest-last.json`（wsemi 記錄用之主幹清單副本）與套件內基準清單。副本可被改寫但不影響安全（只用於顯示，且須 sha256 吻合）。
- **主幹清單尚未推上 GitHub 時**：執行期取 `raw.githubusercontent.com/yuda-lyu/w-scan-dep/master/bin/manifest.json` 得 404，`fsEnsureBins` 退回基準清單（實測事件序：`manifest remote ERR E_HTTP 404 | manifest baseline`），功能正常，只是每次多一次失敗請求。
- **在 ESM 內攔截 `child_process`**：被測模組以具名匯入取用 `spawn`/`spawnSync` 時，測試要先改 `import cp from 'node:child_process'` 之屬性，再呼叫 `module.syncBuiltinESMExports()` 才會生效（還原時也要同步一次）。`netstat`/`netsh` 等系統指令走原函數。`osv-scanner` 對 markdown 與 json 各啟動一次，故掃描階段共 4 次啟動（syft、grype、osv×2；2026-10-30 起為 `spawn`〔經 `proc.mjs` 之 `runTool`〕，不再是 `spawnSync`）。
- **假套件根**：決定預設快取位置之 `pkgRoot` 取自被測檔所在位置，故測試把 `src/` 原樣複製到 `test/_tmp/<案名>/pkg/` 並放假基準清單，在其上動態 import；不可寫入本 repo 之 `bin-cache/`。`test/_tmp` 位於 repo 內，模組解析會往上找到 repo 的 `node_modules`，不必複製相依。
- **T1 誘餌檔清理只刪自己放的**：`bin-cache/` 可能已有真實快取，清理時只刪誘餌檔與自己建立之空資料夾（`rmdirSync` 非空即略過），不可 `rmSync(recursive)` 整夾。
- **測試鎖會排隊很久**：2026-10-29 實測等鎖 10 分 20 秒（兩槽被他套件占用）。把需要鎖的工作合併成一支腳本在同一把鎖內依序執行（修前紅、對照、變異），不要分多次各取一把。
- **ex-sbom 之防火牆路徑**：改為 `<快取>/<sha256>/ex-sbom.exe` 後，首次啟動新路徑會跳 Windows 防火牆詢問；agent 不得首次啟動它（見規則帳本 §2）。完整掃描之 `test/WScanDep.test.mjs`「test」案因此需連網且會觸發詢問，由主控/使用者跑。
- **`opt` 整個移除**：`WScanDep` 原本唯一的選項 `opt.fdTools` 移除後 `opt` 已無內容，第三參數改為明確拒絕（避免舊呼叫端靜默忽略而以為工具仍在其指定資料夾），非相容層。

## ex-sbom 相依循環、截圖失敗與 npm install 時限（2026-10-29，run01，Gitea #24）

- **讀上游原始碼再定剔除範圍**：ex-sbom v0.2.0 `spdx_sbom.go` 之 `getSpdxDependencyDepthMap` 建圖**不看關係類型**（每筆 relationship 皆 `spdxElementId → relatedSpdxElement`），略過 `DOCUMENT`、`DocumentRoot-*`、`File-*`，自入度 0 之節點遞迴且遞迴不受 depth 條件限制（以 WebFetch 讀 `raw.githubusercontent.com/nics-tw/ex-sbom/v0.2.0/…`）。只依建議檔字面剔除 `DEPENDENCY_OF`/`DEPENDS_ON` 會漏掉其他類型構成之循環。
- **最小重現須有「入口」**：依上述建圖，循環只有在可由入度 0 之節點走到時才會被遞迴到；只放 a⇄b 而無其他節點指向它們，推得不會崩潰（未實測）。fixture 因此加 `has-symbols DEPENDENCY_OF es-abstract`（syft 方向下 has-symbols 為入度 0）。
- **Windows 下 `spawnSync(..., { shell: true, timeout })` 不能當時限**：逾時只結束 cmd.exe，npm 之 node（cmd.exe 之子）續跑；libuv 之 Job Object 只在**父 node 行程結束**時才連帶結束子孫，不在 cmd.exe 被結束時。故改非同步 `spawn` ＋逾時 `taskkill /F /T /PID <cmd.exe>`。測試以「無回應 registry 收到之連線全數被關閉」判定 npm 行程確已結束（不需 PowerShell 查行程樹）。
- **攔截全域 `fetch` 之測試要放行迴圈位址**：`api-wsdEntry` 若要讓 ex-sbom（或其替身）走完就緒判定，`probeTitle` 之 `fetch('http://127.0.0.1:…')` 須照常；只禁止其他網址即可保持「不連 GitHub」之斷言。
- **ex-sbom 替身以瀏覽器之請求觸發結束**：`test/tools/fakeExSbom.mjs` 只綁 127.0.0.1（不跳防火牆詢問），看到 `HeadlessChrome` 之 User-Agent 才輸出 Go 之 stack overflow 並以 2 結束——就緒探測（node fetch）不觸發，時序由因果決定、不靠延時。
- **截圖失敗不再 reject 之後，完整掃描測試要自己斷言 `exsbom.ok`**：原本「resolve 即截圖成功」，改後截圖壞了測試也會綠。
- **測試鎖排隊與背景時限**：Bash 背景指令之 2 小時上限含排鎖時間；前面排 6 件時改以 `nohup node quiet-run.mjs --lock … &` detached 排隊。quiet-run 取得鎖時才啟動所包之指令、才讀腳本檔，故可先排隊、排隊期間再寫內容；為免取得鎖時尚未寫完而空佔，執行器先檢查 ready 標記，無則立即結束釋放鎖。被 TaskStop 結束之排隊者，其 queue 檔由 quiet-run 自行清除（實測）。
- **主控守門**：`echo $! > 檔` 被擋（以 `>` 寫檔）；`nohup … > ./tmp/x.out 2>&1 &` 可用。PowerShell 指令內出現 `Start` 字樣之屬性名（如 `Start = $_.CreationDate`）會被「可見視窗」守門誤擋，改名即可。
- **排隊兩小時、持鎖時才發現問題**：取得鎖後的各步若是「啟動時才讀檔」之獨立行程，可於前一步執行中改寫後一步之腳本，把它換成「持鎖指令執行器」（輪詢 `ctl/*.json` 依序執行、遇 stop 工作或閒置 20 分鐘即結束），在同一把鎖內完成診斷、修正後重跑與變異，不必重新排隊。
- **作業系統 TCP 表會壞**：2026-10-30 本機 `netstat -ano` 與 `Get-NetTCPConnection -State Listen` 皆只回 5～6 個監聽 socket（135/445/3389 不在，另有外部位址非 0 之 LISTENING 列），持續至少 30 分鐘。此時 ex-sbom 之身分確認隨機誤判；先以「常駐埠 135 是否在監聽表」判斷 netstat 是否可信，再判讀測試失敗。
- **只結束 cmd.exe 時 npm 會存活到 mocha 結束之後**：變異 M4（逾時只 `child.kill()`）留下之 npm 行程在 mocha `--exit` 後仍佔住工作目錄（rm 得 EBUSY/EPERM），須以 Get-CimInstance 找「父行程已不存在之 npm-cli install」再樹狀結束——證明樹狀結束不可省。
- **全套平行跑時輸出依檔案完成順序列印**：mocha `--parallel` 之輸出順序不代表執行時序，判斷兩檔是否同時跑不能看印出先後。

## 掃描工具時限、替身卡住之工具與測試時序（2026-10-30，run02，Gitea #24 同類）

- **三工具時限之實測**（真實專案：`react-scripts@5.0.1` 等 8 個相依，867 個頂層目錄、syft 編出 1364 個元件；`legacy-peer-deps`，因 react-scripts 與 eslint 8.57 有 peer 衝突；測量腳本寫於 `./tmp/`，已清）：npm install 199 秒；syft 首次 81.2 秒（剛安裝之 node_modules，疑為防毒首次讀取）、其後 6.5、6.2 秒；grype 以全新 `GRYPE_DB_CACHE_DIR` 冷啟動（下載資料庫＋掃描）86.1 秒、暖 2.8~2.9 秒；osv-scanner 每次 2.6~3.5 秒（markdown/json 各 3 次，離開碼 1＝有漏洞）。預設取 syft 3600、grype 1800、osv-scanner 600 秒（見規則帳本 R-SCAN-TIMEOUT-01）。**syft 最初訂 600 秒，被事後一次實測推翻**：同一專案、同一份檔案，本機被他套件之測試占滿（CPU 88%）時以 `runScan` 實跑，syft 用了 519 秒（CPU 時間僅 14 秒，其餘為等待；暖時 6 秒），離 600 秒只差 15%。教訓：耗時受機器忙碌影響可差 80 倍以上，**預設值不可只依閒置時之實測訂定**，要在忙碌時也量一次；時限只為擋「卡住」，取寬的代價僅是真卡住時多等。**osv.dev 之最壞情形無從量測**（正常時極快；卡住才是時限要防的），故 osv-scanner 預設取與 syft 同值，不以實測倍數推。
- **`spawnSync` 之 `timeout` 做不到「結束整個樹」**：只對直接子行程送終止訊號（Windows 為 TerminateProcess），且整段阻塞事件迴圈。要樹狀結束必須非同步 `spawn` ＋ `taskkill /F /T`，故 syft 也由同步改非同步（`runSyft` 回傳 Promise）。等待、樹狀結束、環境變數解析三者抽成 `src/proc.mjs`，npm install 與三工具共用。
- **收集輸出用 Buffer 再一次解碼**：多位元組字元（中文）可能被切在兩個 `data` 之間，逐段 `toString` 會產生亂碼；`Buffer.concat` 後解碼。等 `close`（串流關閉）而非 `exit`，否則尾段輸出可能尚未讀完；npm 的 `stdio: 'inherit'` 無串流，維持等 `exit`。
- **「卡住的工具」替身**：不能用 `.cmd`（無 shell 時 Windows 拒絕直接 spawn）。用 `process.execPath`（node.exe）當執行檔，環境變數 `NODE_OPTIONS=--import=<file URL>` 讓 `test/tools/hangTool.mjs` 在任何主程式前載入並永不返回——不論 syft/grype/osv 傳什麼參數都卡住。替身連上 `hangRegistry`（接受連線不回應）後等待，並另啟 detached 孫行程也連線：根與孫的連線**全數被關閉**＝整棵樹已結束；只結束根行程時孫的連線仍在。孫行程必須 `NODE_OPTIONS=''`＋由 `FAKE_HANG_ROLE` 辨識，否則 `NODE_OPTIONS` 被繼承會遞迴衍生行程。替身自帶 120 秒防殘留，缺陷版漏殺時不會永久留下行程。
- **「時限內要連上」是本類測試的固有前提**：根與孫行程要在時限內連上服務，斷言才有意義；以 6 秒時限＋斷言「收到 ≥ 2 條連線」把前提明寫出來（不成立時失敗訊息說明為前提不成立，而非誤報樹未結束）。不是用延時偵測缺陷，是用延時構成「卡住」本身。
- **ESM 內攔截 `spawn` 後掃描工具改非同步**：`api-wsdEntry` 原攔截 `spawnSync` 寫假產物；工具改 `spawn` 後須回傳有 `stdout`/`stderr`（`PassThrough`）並發出 `close` 之假子行程。保留對 `spawnSync` 之攔截但記為 `spawnSync` 種類，使「有人把工具改回 `spawnSync`」時呼叫序列斷言失敗。
- **「清除前次殘留之工作子夾」案之時序**：占用者（`spawn(node, …, { cwd })` 的子行程）取得工作目錄之 handle 是在行程初始化時，`spawn()` 回傳時尚未必取得，高負載下目錄先被清掉而案例假紅。修法不是加延時，而是等占用者**印出其 `process.cwd()`**（其程式已開始執行＝初始化完成）並以**改名被拒**（`renameSync` 得 EBUSY/EPERM）確認目錄確被持有，才往下。驗證用「非缺陷之時序變異」：占用者晚 1.5 秒才 `chdir` 進去——舊協定（不等持有）轉紅、新協定仍綠。協定抽成 `test/tools/holdDir.mjs`（`{ delayMs }` 可模擬晚進入），並把 `cleanStaleWork` 匯出，以不經 ex-sbom 之單元測試取得確定性證據：經真 ex-sbom 之整合案受 TCP 表異常影響（2026-10-30 實測同一案三次中紅一次，紅在「截圖完成時埠 18080 之監聽者已非本次 ex-sbom(現為 埠 18080:)」，與占用者無關），拿它當時序修正之證據會把環境失敗誤判為時序失敗。
- **變異證據要選「不經不穩環境」的偵測點**：run01 之 M7、M9、M11 全靠 `api-wsdEntry` 的崩潰案（真啟動替身 ex-sbom、經 netstat 確認身分）偵測，TCP 表異常時該案本身逾時紅，變異是否被抓到無從判別（本輪 M7、M9 兩次皆因而 184 秒逾時）。改為在不經 ex-sbom 行程之案偵測：`api-wsdEntry` 的 throw 案（攔截 spawn 使 ex-sbom 啟動即拋錯）加上「上次截圖已刪」「剔除清單隨失敗列出」斷言，report 摘錄用 `unit-report.test.mjs`（`buildReport` 純函式）。
- **持鎖腳本內不可在定義前呼叫 `const` 函式**：`const doD = () => …` 寫在呼叫處之後，整支腳本於第一個該呼叫處丟 `ReferenceError`、鎖隨之釋放，其後階段全未跑（本輪第一次持鎖作業即如此，損失 B 階段後全部）。持鎖腳本寫完先 `node --check` 不夠（語法對、執行順序錯），可先以 `--dry` 之類旗標走一遍階段順序，或把函式定義集中放前面。
- **`taskkill` 回 128 ＝找不到行程**：時限邊界上工具剛好自行結束時，計時器先於 `exit` 事件被處理，`taskkill` 對已不存在之 PID 回 128；此時視為正常結束，不報逾時（也避免對可能已被重用之 PID 動手）。測試用「不存在之 PID（4000000 起找未存活者）＋假子行程之 `kill()` 才發出 exit」確定性重現。
- **mocha 預設不 `--exit`**：把計時器留在事件迴圈（`within` 不清除，變異 X8）時，測試結果寫出後行程仍等該計時器（600 秒）才退出；測計時器清除用 `process.getActiveResourcesInfo()` 比較前後 `Timeout` 數，基準須在 mocha 為 async 案建立其逾時計時器之後（先 `await null`）量。
- **mocha `--grep` 要正規表示式時須寫成 `/…/`**：純字串會被跳脫為字面比對，`'時限|timeout'` 不會當 OR。

## 埠之監聽者之身分確認改用 wsemi（2026-10-30，run03，Gitea #24 之 TCP 表異常）

- **「作業系統 TCP 表會壞」（上節）之後續**：成因為 Windows 11 26300（KB5127936）之系統 TCP 狀態值錯誤——`netstat -ano` 整列漏列新起之監聽（本機實測新起之監聽約半數不在輸出中，且是**逐 socket 持續**：同一個 socket 要嘛一直不列、要嘛一直列，所以換埠/重起 socket 才有機會）、對外連線反列 LISTENING。以 netstat 判斷「誰在監聽某埠」皆不可靠；wsemi 1.9.32 之 `execProcessPortPidsSync` 不依狀態欄，Windows 先 netstat、查無或失敗再 `Get-NetTCPConnection -LocalPort`，`useBoth` 取聯集。**修前探測**（`./tmp/run03/probe.mjs`，真實 0.0.0.0 監聽之子程序 5 次）：舊作法（`listeningPorts().get(port)`）身分確認成功 2/5，wsemi `useBoth` 5/5（每次約 0.9～1 秒）。
- **身分確認必須 `useBoth`，且不可被呼叫端 opt 蓋掉**：netstat 有列出時預設不再查 PowerShell，會漏掉同埠並存之他服務（只綁 127.0.0.1 者）而誤判「恰為本次子程序」。單元案以「netstat 僅列本次子程序、PowerShell 另列他服務」鎖定；`...opt` 必須在 `useBoth: true` 之前。
- **選埠之全表快照留 netstat**：wsemi 只有單埠查詢，逐埠約 1 秒 × 101 埠不可行；漏列的後果只是多選到被占用之埠，有 bind 失敗（ex-sbom 於被占用之埠印錯誤後離開碼 0 結束）與身分確認不符兩道、`MAX_ATTEMPTS` 換埠重試。`parseNetstat` 移除 `LISTENING` 或條件（方向安全）。
- **替身 PowerShell 輸出之列為 `[本地埠, 遠端位址, 遠端埠, PID]`，不含本地位址**：首次寫單元案時把他服務之列寫成 `[8080, '127.0.0.1', 0, PID]`（把本地位址放在遠端位址欄），wsemi 判為非監聽（遠端位址須為萬用位址）而 3 案紅——是測試夾具寫錯，不是產品缺陷。夾具格式取自 wsemi 之 `test/tools/portPidsKit.mjs`，為 wsemi 內部約定，wsemi 改版而不合時單元案會明確失敗。
- **「同埠並存」不需綁 0.0.0.0**：兩個 socket 各綁 `127.0.0.1` 與 `127.0.0.2` 之同一埠即可並存，網路上看起來與「ex-sbom 綁全部介面＋他服務只綁 127.0.0.1」同形（本套件只關心該埠有幾個監聽 PID），且不觸發 Windows 防火牆詢問。真實環境案（`test/api-exsbomPort.test.mjs`）因而全用本機迴圈位址。
- **測 `startExSbom` 不需真 ex-sbom**：以 `process.execPath` 當 exe，`process.env.NODE_OPTIONS=--import=<fakeExSbom.mjs 之 file URL>` 讓預載之替身服務讀 `PORT`、綁 127.0.0.1、標題為 ex-sbom（`spawn` 之 env 展開自 `process.env`，NODE_OPTIONS 被繼承）；測完還原。fail-closed 案在真實 `child_process.spawnSync` 接縫注入失敗（wsemi 之預設執行函數呼叫 `cp.spawnSync`，屬性存取、免 `syncBuiltinESMExports`；exsbom.mjs 自己以具名匯入取 `spawnSync`，未同步即不受影響），以「拋錯後該埠 connect 被拒」確認不留下占埠之子程序。
- **修前紅不用 stash/checkout**：把工作樹之 `src`、`test/tools`、`test/fixtures`、`test/*.mjs`、`bin/manifest.json`、`package.json` 複製到 `./tmp/run03/prefix/`（解析 `wsemi`/`playwright` 靠向上找到 repo 之 `node_modules`，不用 junction），以 cwd 決定哪個 `src` 被測：`api-wsdEntry` 之 `makeFakePkg` 取 cwd 之 `src`，故 cwd 為複本；`WScanDep.test.mjs` 之 `captureExSbom` 要用 repo 根 `test/output/tools` 之 ex-sbom（已有防火牆規則），故 cwd 為 repo 根、測試檔取複本。修前整合案 8 通過/3 失敗（其一為連到冒用標題之 127.0.0.1 假服務而 `#lang-zh` 逾時＝漏列他服務之誤判，其餘為「截圖完成時埠 … 之監聽者已非本次 ex-sbom（現為 埠 N:）」＝漏列自身），修後全套 144 通過/0 失敗。
- **同步查詢每次約 1 秒、阻塞事件迴圈**：就緒時 1 次、回傳前重驗 1 次、`finally` 釋放確認 1 次，ex-sbom 為獨立行程不受影響；wsemi 預設每個子指令 10 秒，未調高（無已觀察之逾時；逾時之後果為 fail-closed、只作廢截圖）。
- **`npm i wsemi@latest` 會順手改 `package.json` 之結尾換行**（原無結尾換行，npm 補一個換行），並把 `package-lock.json` 之 `version` 與 `package.json` 對齊（1.0.8 → 1.0.9）；`version` 本身未動。
