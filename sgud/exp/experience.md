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
- **在 ESM 內攔截 `child_process`**：被測模組以具名匯入取用 `spawn`/`spawnSync` 時，測試要先改 `import cp from 'node:child_process'` 之屬性，再呼叫 `module.syncBuiltinESMExports()` 才會生效（還原時也要同步一次）。`netstat`/`netsh` 等系統指令走原函數。`osv-scanner` 對 markdown 與 json 各啟動一次，故掃描階段 `spawnSync` 共 4 次（syft、grype、osv×2）。
- **假套件根**：決定預設快取位置之 `pkgRoot` 取自被測檔所在位置，故測試把 `src/` 原樣複製到 `test/_tmp/<案名>/pkg/` 並放假基準清單，在其上動態 import；不可寫入本 repo 之 `bin-cache/`。`test/_tmp` 位於 repo 內，模組解析會往上找到 repo 的 `node_modules`，不必複製相依。
- **T1 誘餌檔清理只刪自己放的**：`bin-cache/` 可能已有真實快取，清理時只刪誘餌檔與自己建立之空資料夾（`rmdirSync` 非空即略過），不可 `rmSync(recursive)` 整夾。
- **測試鎖會排隊很久**：2026-10-29 實測等鎖 10 分 20 秒（兩槽被他套件占用）。把需要鎖的工作合併成一支腳本在同一把鎖內依序執行（修前紅、對照、變異），不要分多次各取一把。
- **ex-sbom 之防火牆路徑**：改為 `<快取>/<sha256>/ex-sbom.exe` 後，首次啟動新路徑會跳 Windows 防火牆詢問；agent 不得首次啟動它（見規則帳本 §2）。完整掃描之 `test/WScanDep.test.mjs`「test」案因此需連網且會觸發詢問，由主控/使用者跑。
- **`opt` 整個移除**：`WScanDep` 原本唯一的選項 `opt.fdTools` 移除後 `opt` 已無內容，第三參數改為明確拒絕（避免舊呼叫端靜默忽略而以為工具仍在其指定資料夾），非相容層。
