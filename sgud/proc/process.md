# 處理要點

依賴套件漏洞掃描套件（syft / grype / osv-scanner / ex-sbom），僅支援 Windows。
本檔記錄使用方式與執行流程；開發時不可放寬之規則見 `sgud/rule/rulebook.md`，實測踩過之坑見 `sgud/exp/experience.md`，現況見 `sgud/state/state.md`。

> 2026-10-29 整理：本檔原為主控自 `CLAUDE.md` 搬入之全文，已依類搬移（節號與標題不變、只搬移）：
> - §2 前置條件 → `sgud/rule/rulebook.md`（開發時不可放寬之處）
> - §3 一律背景執行、§4 監看與完成判斷、§5 中斷 → `sgud/exp/experience.md`（實測踩坑與操作經驗）
> - 本檔保留 §1、§6、§7、§8（使用方式、重跑行為、產出、結果判讀）；其中 §1、§6、§7 依 2026-10-29 外部執行檔改造（`opt.fdTools` 與 `fdOut/tools` 移除）更新了內容。

## 1. 執行方式

API 為 `WScanDep(fpIn, fdOut)`：`fpIn` 傳 package.json 檔路徑或其所在資料夾，`fdOut` 傳輸出資料夾。**不接受第三參數**（原 `opt.fdTools` 於 2026-10-29 移除，傳入即 reject）；掃描工具存於 `ensureBins` 快取（預設 `<套件根>/bin-cache/`，可由環境變數 `W_BIN_CACHE` 改位置、多個專案共用），見 README〈外部執行檔〉。快取位置若落在 `fdOut` 之 `test`、`pics`、`exsbom-work` 內會 throw（`src/layout.mjs` `assertToolsOutside`）。

同時掃描多個專案：須以**不同 node 程序**且**不同 fdOut** 執行（2026-10-03 起支援）。同一程序內並行不支援（npm install、syft 等為同步呼叫，會阻塞另一掃描之計時與瀏覽器操作）；同一 fdOut 並行不支援（test、scan、pics 互相覆蓋）。

- 專案內建入口：`g.mjs`（`./test/prj/package.json` → `./test/output`），`node g.mjs`
- 臨時掃描他案之 package.json：於 `tmp/` 建 runner，避免污染 `test/`

```js
// tmp/run.mjs
import wsd from '../src/WScanDep.mjs'
async function test() {
    let r = await wsd('./tmp/package.json', './tmp/output')
    console.log(r)
}
test().catch((err) => { console.log(err) })
```

部署前預先取得掃描工具（離線部署）：`wsd.ensureBins()`（或深層匯入 `src/ensureBins.mjs`），步驟見 README〈外部執行檔〉。更新工具版本（維護者）：`node toolg/genBinManifest.mjs`（`--dry-run`、`--only`、`--tag`），推 `bin/manifest.json` 到 GitHub 主幹即生效。

## 6. 重跑同一 fdOut：程式已自動清除會污染結果之舊產物

2026-10-02 起（修正前 1.0.5 重跑會沿用 `fdOut/test` 之舊 lock 與 node_modules，掃到上一次之相依樹），各產物重跑行為：

| 產物 | 重跑時 |
| --- | --- |
| `fdOut/test` 之 `package-lock.json`、`node_modules` | 安裝前自動刪除並回驗（`src/install.mjs`）；刪不掉（被占用）即 throw 中止。`test/` 內其他檔不刪 |
| `fdOut/scan` 之 osv 產物 | 執行前自動刪除；osv-scanner 離開碼非 0/1/128 即 throw（`src/scan.mjs` `runOsv`） |
| `fdOut/scan` 之 syft/grype 產物 | 成功即覆寫，失敗即 throw |
| `fdOut/pics` | ex-sbom 就緒後才整夾刪除重建（啟動失敗時保留上次之截圖，`src/exsbom.mjs` `captureExSbom`） |
| `fdOut/exsbom-work` | ex-sbom 之工作目錄；每次掃描一個專用子夾，結束後刪除，空了即刪根；刪不掉只警告（交付前手動刪）。開始時清除建立者已不存在之舊子夾 |
| `result.json`、`result.md`、`待更新套件.md` | 成功即覆寫；中途失敗時舊檔留存但函式 reject |
| 掃描工具（`ensureBins` 快取） | 刻意保留：快取命中亦校驗大小與 SHA-256，符合即直接用（省 162MB 與數分鐘）；不符則刪除重取。下載、解壓、校驗皆由 wsemi `fsEnsureBins` 處理，於快取夾內暫存夾完成後才原子更名（中斷不會留下殘缺執行檔）；舊 sha256 之目錄不自動清（要清自行刪 `bin-cache/<sha256>/`） |

故重跑不需手動清檔。若掃描中途失敗，`result.*` 為上一次之內容，勿當本次結果交付。

## 7. 產出

於 `fdOut`：

| 路徑 | 內容 |
| --- | --- |
| `result.json` | 檢測數據（工具版本標籤、osv/grype 結果、截圖相對路徑、連鎖更新清單） |
| `result.md` | 掃描報告，圖以 `./pics/` 相對路徑引用 |
| `待更新套件.md` | 連鎖更新清單，依底層自有套件分組 |
| `pics/*.png` | ex-sbom 拓撲總覽 + 各漏洞套件彈窗截圖 |
| `scan/` | syft SBOM（spdx/cdx）、grype.json、osv.json 與兩份文字報告 |
| `test/` | 複製 package.json 全新安裝之掃描目標 |
| `exsbom-work/` | 正常結束時不存在；若殘留（刪除失敗會警告）為暫存，交付前刪除 |

2026-10-29 起不再產出 `tools/`（掃描工具在 `ensureBins` 快取，不隨 `fdOut` 交付；要提供工具給業主請另交付 `W_BIN_CACHE` 資料夾）。`result.md` 與 `pics/` 為相對路徑對應，整個 `fdOut` 可直接搬移交付。

## 8. 結果判讀

- 三項工具資料庫不同，結果本就不一致；報告已做去重彙整。
- `xlsx`、`vue` 於 `src/config.mjs` 之 `PACKAGE_NOTES` 有人工說明（xlsx 屬 osv-scanner 誤報、vue2 屬框架升級議題），命中時自動附入報告，且不列入連鎖更新清單。
- 自有套件判別為 `w-*` 前綴與 `wsemi`（`src/config.mjs` `SELF_OWNED`），決定「待更新套件.md」之分組起點；日後有其他命名於此擴充。

## 指引要求文件(sgud)

本套件之指引要求文件依全域設定之 sgud 配置(2026-10-22 起,`sgud/` 納入 git 版控、不入 npm 包;本檔與 `CLAUDE_settings.md` 等 `CLAUDE*.md` 仍不入版控):[經驗類]`sgud/exp/experience.md`、[處理要點類]`sgud/proc/process.md`、[規則帳本類]`sgud/rule/rulebook.md`(藍圖)、[狀態類]`sgud/state/state.md`(現況:各功能做到哪裡、對應之規則帳本條目與測試檔、已知缺口與待辦、最近一次驗證或發布之版本;接續工作先讀,完成一項功能或結束一輪工作時即更新,只記現況、不寫過程).過長時之抽出與分拆(含 `state_<類型>.md`)依全域設定.
