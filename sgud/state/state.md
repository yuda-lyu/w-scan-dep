# 狀態

本檔記載當前已開發功能之最新狀態:各功能做到哪裡、對應之規則帳本條目與測試檔、已知缺口與待辦、最近一次驗證或發布之版本.只記現況,不寫過程(過程見 `sgud/exp/experience.md`).規則帳本為藍圖(`sgud/rule/rulebook.md`),兩者比對即知尚未做到者.

套件:`w-scan-dep` 1.0.8(`package.json` version 未動;外部執行檔改造待主控跑全套並發布).

## 功能現況

| 功能 | 狀態 | 規則帳本 | 測試 |
| --- | --- | --- | --- |
| 依賴掃描主流程 `WScanDep(fpIn, fdOut)`:npm install → syft/grype/osv-scanner → ex-sbom 截圖 → `result.json`/`result.md`/`待更新套件.md` | 完成;**不接受第三參數**(`opt.fdTools` 已於 2026-10-29 移除) | §2 前置條件、R-BIN-ENSURE-01 規則 5、7 | `test/WScanDep.test.mjs`(完整掃描,需連網、首次啟動新快取路徑之 ex-sbom 會觸發防火牆詢問)、`test/api-wsdEntry.test.mjs` |
| 掃描工具取得 `src/ensureBins.mjs`(`WScanDep.ensureBins` 靜態屬性) | 完成:wsemi `fsEnsureBins` 主幹模式;快取 `<套件根>/bin-cache/`,`W_BIN_CACHE`/`W_BIN_MIRROR`/`W_BIN_OFFLINE` | R-BIN-ENSURE-01 | `test/api-ensureBins.test.mjs`(T3~T8)、`test/api-wsdEntry.test.mjs` |
| 清單 `bin/manifest.json`(floating,4 項) | 完成:syft v1.55.0、grype v0.121.0、osv-scanner v2.7.0、ex-sbom v0.2.0(2026-10-29 由 `toolg/genBinManifest.mjs` 產生,廠商 checksums 與 GitHub API digest 核對) | R-BIN-ENSURE-01 規則 2 | `test/unit-binManifest.test.mjs`(T1、T2、schema) |
| 更新工具 `toolg/genBinManifest.mjs` | 完成:查最新版、下載資產與 checksums、核對、寫清單;`--dry-run`、`--only`、`--tag` | R-BIN-ENSURE-01 | `test/unit-genBinManifest.test.mjs` |
| 工具版本標籤推得 `src/toolVersions.mjs` | 完成:由快取路徑 sha256 反查清單 | R-BIN-ENSURE-01 | `test/unit-toolVersions.test.mjs` |
| 工具位置防呆 `assertToolsOutside`(`src/layout.mjs`) | 完成 | R-BIN-ENSURE-01 規則 6 | `test/unit-layout.test.mjs`、`test/api-wsdEntry.test.mjs` |
| ex-sbom 驅動(服務埠、身分確認、工作目錄、log 判定) | 完成(未動) | §2 | `test/WScanDep.test.mjs` 之 `captureExSbom`、`test/unit-exsbom.test.mjs` |
| 重跑清除上次安裝殘留 | 完成(未動) | — | `test/unit-clearNpmState.test.mjs` |
| osv-scanner 執行與離開碼 | 完成(未動) | — | `test/unit-runOsv.test.mjs` |

## 已知缺口與待辦

- **`bin/manifest.json` 尚未推上 GitHub 主幹**(本輪不得 commit/push):推上前執行期取主幹清單得 404,退回 npm 包內基準清單(功能正常);推上並發布後主幹模式才完整生效.
- 未發布:`dist/`、`docs/` 為發布時自動產製,本輪未重編(UMD 已以暫存輸出驗證 external/globals 與 default 匯出形態).
- 完整掃描(`test/WScanDep.test.mjs`「test」案)需連網與 npm registry,且首次以快取新路徑啟動 ex-sbom(Windows 防火牆詢問),本輪 agent 未跑,由主控/使用者跑.
- 離線部署之版本一致性:離線(`W_BIN_OFFLINE=1`)用基準清單,其版本為該 npm 包發布時之版本;連網機器若取到較新之主幹清單,兩邊版本不同(README〈外部執行檔〉已說明作法).
- 舊版遺留之 `test/output/tools/`(已 gitignore)仍被 `captureExSbom` 測試在快取尚無 ex-sbom 時沿用(該路徑已有防火牆規則);快取有 ex-sbom 後改用快取.

## 最近一次驗證

2026-10-29(bin-scandep 輪):離線受影響測試全綠(見該輪報告 `C:\opensrcOper\dnow\20261028054319\agent-out\bin-scandep-修正報告.md`);真實網路 `ensureBins` 取得四檔並校驗通過;`node C:/opensrcOper/tools/scan-bins.mjs --only w-scan-dep` 為 OK.
