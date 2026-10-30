# w-scan-dep
A scanner for dependencies in nodejs.

![language](https://img.shields.io/badge/language-JavaScript-orange.svg) 
[![npm version](http://img.shields.io/npm/v/w-scan-dep.svg?style=flat)](https://npmjs.org/package/w-scan-dep) 
[![license](https://img.shields.io/npm/l/w-scan-dep.svg?style=flat)](https://npmjs.org/package/w-scan-dep) 
[![npm download](https://img.shields.io/npm/dt/w-scan-dep.svg)](https://npmjs.org/package/w-scan-dep) 
[![npm download](https://img.shields.io/npm/dm/w-scan-dep.svg)](https://npmjs.org/package/w-scan-dep) 
[![jsdelivr download](https://img.shields.io/jsdelivr/npm/hm/w-scan-dep.svg)](https://www.jsdelivr.com/package/npm/w-scan-dep)

## Documentation
To view documentation or get support, visit [docs](https://yuda-lyu.github.io/w-scan-dep/WScanDep.html).

## Installation

### Using npm(ES6 module):
```alias
npm i w-scan-dep
```

#### Example for collection
> **Link:** [[dev source code](https://github.com/yuda-lyu/w-scan-dep/blob/master/g.mjs)]
```alias
import wsd from 'w-scan-dep'

async function test() {

    let fpIn = './test/prj/package.json'
    let fdOut = './test/output'

    let r = await wsd(fpIn, fdOut)
    console.log(r)
    // => 'ok'

    // 產出於fdOut:
    //   result.json 檢測數據(含各工具版本、osv/grype掃描結果、ex-sbom截圖相對路徑與成敗、連鎖更新清單)
    //   result.md 掃描報告
    //   待更新套件.md 連鎖更新清單
    //   pics/*.png ex-sbom拓撲總覽與各漏洞套件截圖(截圖失敗時無)

    // 截圖是否成功(截圖失敗時仍回傳'ok'):
    // let j = JSON.parse(fs.readFileSync(`${fdOut}/result.json`, 'utf8'))
    // if (!j.exsbom.ok) console.log('ex-sbom截圖失敗', j.exsbom.error)

}
test()
    .catch((err) => {
        console.log(err)
    })
```

> ex-sbom 截圖失敗：ex-sbom 之任何失敗(啟動失敗、截圖期間意外結束、分析 SBOM 失敗等)只作廢截圖，`WScanDep` 仍回傳 `'ok'` 並寫出 syft、grype、osv-scanner 之結果；`result.json` 之 `exsbom.ok` 為 `false`、`exsbom.error` 為原因(截圖期間意外結束時附 `ex-sbom.log` 中 `fatal error`／`panic` 及其後數行，總長至多約 1500 字)，`fdOut/pics` 刪除，`result.md` 註明「ex-sbom 截圖失敗」並附原因與摘錄，`待更新套件.md` 註明未納入 ex-sbom 之判定。是否採用無截圖之結果由呼叫端決定。

> ex-sbom v0.2.0 之限制與本套件之處置：ex-sbom 計算相依層級(上游 `internal/service/sbom/spdx_sbom.go` 之 `getSpdxDependencyDepthMap`)時不記錄已走過之節點，SBOM 之相依關係含循環(npm 常見，如 `es-abstract` 與 `string.prototype.trim` 互相依賴)即無限遞迴，以 `fatal error: stack overflow` 結束。本套件於交給 ex-sbom 前，在 SBOM 之副本中剔除構成循環之關係(依 ex-sbom 之建圖以深度優先找出回邊；syft 原檔不動，grype 與 osv-scanner 不受影響，只影響拓撲截圖之層級)，剔除者列於 `result.json` 之 `exsbom.removedRelationships`(`[{ from, to, relationshipType, spdxElementId, relatedSpdxElement }]`，表示原 SBOM 中「from relationshipType to」之關係；無循環為 `[]`，截圖失敗且尚未算出時為 `null`)，`result.md` 亦附註。此缺陷不向上游回報，由本套件繞過。

> npm install 時限：全新安裝相依之 `npm install` 預設 20 分鐘未完成即結束整個安裝子行程樹並 reject(訊息含「npm install 逾時」)；以環境變數 `W_NPM_INSTALL_TIMEOUT=<秒>` 調整(正數，可含小數，至多 2147483；值不合法時於任何下載與寫入前 reject)。

> 掃描工具時限：syft、grype、osv-scanner 亦各有**單次執行**之時限，逾時即結束該工具之整個子行程樹並 reject(訊息含「逾時」與工具名，如 `syft 逾時(超過 10 分鐘未完成),已結束 syft 子行程樹;可設環境變數 W_SYFT_TIMEOUT(秒)調整時限`；此時不寫出 `result.json`、`result.md`，其後之工具不啟動)。以環境變數各自調整(秒，正數，可含小數，至多 2147483；值不合法時於任何下載與寫入前 reject)：
>
> | 工具 | 環境變數 | 預設 | 備註 |
> |---|---|---|---|
> | syft | `W_SYFT_TIMEOUT` | 3600 秒(60 分鐘) | 實測 1364 個元件之專案：暖 6 秒、冷(剛安裝之檔案)81 秒；本機被他程序占滿(CPU 88%)時曾達 519 秒，故預設取寬 |
> | grype | `W_GRYPE_TIMEOUT` | 1800 秒(30 分鐘) | 首次執行須下載漏洞資料庫，實測冷資料庫 86 秒、其後約 3 秒；網路慢時請調高 |
> | osv-scanner | `W_OSV_SCANNER_TIMEOUT` | 600 秒(10 分鐘) | 對 markdown 與 json 各跑一次，各自計時；實測每次 3.5 秒內(需連 osv.dev) |

> 服務埠：ex-sbom 自 18080 起自動選用 18080～18180 中第一個可用之埠，不需關閉占用 8080 之程式。同時掃描多個專案時，須以不同 node 程序、不同 `fdOut` 執行。就緒須確認「該埠之監聽者恰為本次啟動之 ex-sbom」(只認頁面標題會連到同埠並存之他服務)，確認經 `wsemi` 之 `execProcessPortPidsSync`(Windows 為 `netstat` 與 `Get-NetTCPConnection` 取聯集)，每次約 1 秒；查詢本身失敗時不當成「沒人占用」，而是中止啟動(ex-sbom 之失敗只作廢截圖，見下)。

> Windows 防火牆：ex-sbom 執行時監聽全部網路介面，防火牆對每個新的執行檔路徑會詢問一次是否允許存取(改埠不會再詢問)。選「取消」即可，掃描只經本機連線、不受影響；選「允許」則掃描期間 ex-sbom 對網路開放。執行檔存於快取(見下節)，路徑隨 ex-sbom 版本(SHA-256)而定，同一版本只在第一次詢問；多個專案共用同一快取(`W_BIN_CACHE`)時亦只問一次。

> 僅支援 Windows：掃描工具（syft / grype / osv-scanner / ex-sbom）為 Windows 版執行檔。

## 外部執行檔

本套件執行時需要下列外部執行檔，不含於 npm 包，皆為廠商於其 GitHub Releases 發布之 Windows 版：

| 檔名 | 用途 | 來源 |
|---|---|---|
| syft.exe | 產生 SBOM | https://github.com/anchore/syft |
| grype.exe | 依 SBOM 掃描漏洞 | https://github.com/anchore/grype |
| osv-scanner.exe | 依 SBOM 掃描漏洞 | https://github.com/google/osv-scanner |
| ex-sbom.exe | 拓撲網頁與各漏洞套件截圖 | https://github.com/nics-tw/ex-sbom |

- 首次執行掃描時自動下載(或預先呼叫 `wsd.ensureBins()`)，以清單 `bin/manifest.json` 所載之 SHA-256 與大小校驗後存於 `<套件根>/bin-cache/`；之後自快取取得(亦校驗)。安裝時不下載。
- **主幹模式**：掃描工具須保持新版，故清單放於本 repo 主幹(`https://raw.githubusercontent.com/yuda-lyu/w-scan-dep/master/bin/manifest.json`)，執行時取最新清單，更新版本不須重新發布套件；取不到主幹清單(含離線)時用 npm 包內之基準清單。清單中每個檔為廠商發布之**版本標籤**資產網址(`/releases/download/<tag>/…`，非 `releases/latest`)，壓縮檔與解出之執行檔各記 SHA-256 與大小，`note` 寫明核對所依之廠商 checksums。
- 環境變數：
  - `W_BIN_CACHE=<資料夾>`：快取改放 `<資料夾>/w-scan-dep/`(套件所在之 `node_modules` 唯讀時使用，多個專案可共用同一資料夾；原 `opt.fdTools` 由此取代)。
  - `W_BIN_MIRROR=<資料夾或 http(s) 網址>`：內網鏡像，先找鏡像再連 GitHub；結構為 `<鏡像>/w-scan-dep/<sha256>/<檔名>`。鏡像之檔同樣以清單校驗，不符即不用。
  - `W_BIN_OFFLINE=1`：不連網，只用快取與鏡像(清單用 npm 包內之基準清單)；缺檔時錯誤(`E_OFFLINE_MISSING`)會列出缺哪些檔、sha256、大小與應放之完整路徑。
- 離線部署：
  1. 在可連網之電腦設 `W_BIN_CACHE=<空資料夾>`，呼叫 `wsd.ensureBins()` 一次(`import wsd from 'w-scan-dep'`)。
  2. 把該資料夾整個帶到內網電腦，設 `W_BIN_MIRROR=<該資料夾>`(全離線時另設 `W_BIN_OFFLINE=1`)。注意離線時用基準清單：其所載之版本為該 npm 包發布時之版本，連網機器若取到較新之主幹清單，兩邊所取得之版本會不同；要完全一致請在連網機器以同一版套件、`W_BIN_OFFLINE=1` 搭配 `W_BIN_MIRROR` 預先取得，或升到含新基準清單之套件版本。
- 掃描工具存於快取，**不在** `fdOut` 內(不再有 `fdOut/tools`)；快取位置若落在 `fdOut` 之 `test`、`pics` 或 `exsbom-work` 內會被拒絕(syft 會把 `test/` 內之工具編入 SBOM)。
- 更新工具版本(維護者，需連網)：`node toolg/genBinManifest.mjs`(`--dry-run` 只列差異、`--only syft,grype`、`--tag syft=v1.55.0`)，查各廠商最新版、下載資產與 checksums 並核對後寫入 `bin/manifest.json`，推 GitHub 主幹即生效。

## Breaking changes

### ex-sbom 截圖失敗之辨識、npm install 與掃描工具時限

- **ex-sbom 失敗不再使 `WScanDep` reject**：原本 ex-sbom 之任何失敗(含截圖期間意外結束、無可用之埠、分析 SBOM 失敗)使 `WScanDep` 整個 reject，syft、grype、osv-scanner 之結果不寫出；現改為只作廢截圖，仍 resolve `'ok'` 並寫出 `result.json`、`result.md`、`待更新套件.md`。**呼叫端辨識「截圖失敗」之方式**：讀 `result.json`，`exsbom.ok === false` 即截圖失敗，原因在 `exsbom.error`(此時 `exsbom.overview` 為 `null`、`exsbom.components` 與 `exsbom.levelSummary` 為 `[]`，`fdOut/pics` 已刪除)；不可再以「resolve 即有截圖」判斷。`result.md` 之 ex-sbom 段亦寫「ex-sbom 截圖失敗，本次無截圖」，綜合句只含 osv-scanner 與 grype。
- **`result.json` 之 `exsbom` 新增欄位**：鍵依序為 `ok`、`error`、`overview`、`components`、`levelSummary`、`removedRelationships`(原為 `overview`、`components`、`levelSummary`)。`removedRelationships` 為上傳 ex-sbom 前自 SBOM 副本剔除之循環關係(見上方〈ex-sbom v0.2.0 之限制與本套件之處置〉)。頂層鍵不變。
- **`npm install` 有時限**：預設 20 分鐘未完成即結束整個安裝子行程樹並 reject `npm install 逾時(超過 … 未完成)…`；安裝極慢之專案請設環境變數 `W_NPM_INSTALL_TIMEOUT=<秒>`。`W_NPM_INSTALL_TIMEOUT` 不為正數時於任何下載與寫入前 reject。npm install 改為非同步執行(原 `spawnSync` 會阻塞事件迴圈)。
- **syft、grype、osv-scanner 有時限**(同上之同類)：預設 syft 3600 秒、grype 1800 秒、osv-scanner 600 秒(皆為單次執行)，逾時即結束該工具之整個子行程樹並 reject `<工具> 逾時(超過 … 未完成)…`，不再無限等待(原本網路無回應或資料庫更新卡住時 `WScanDep` 永不結束)；環境變數 `W_SYFT_TIMEOUT`、`W_GRYPE_TIMEOUT`、`W_OSV_SCANNER_TIMEOUT`(秒)各自調整，不為正數時於任何下載與寫入前 reject。**呼叫端影響**：①慢網路或極大專案請預先調高(grype 首次須下載漏洞資料庫)；②`WScanDep` 因而可能多一種 reject(逾時)，且此時無 `result.*`，與工具失敗(非 0 離開碼)同；③三個工具改為非同步執行(原 `spawnSync` 會阻塞事件迴圈直到工具結束)，深層匯入 `src/scan.mjs` 者：`runSyft` 原為同步函式，現與 `runGrype`、`runOsv` 相同須 `await`，三者新增末參數 `timeoutMs`(該工具之時限毫秒)，`runScan` 新增末參數 `timeouts`(`{ syft, grype, 'osv-scanner' }` 各工具時限毫秒之物件)，未傳時讀各自的環境變數。
- 深層匯入 `src/exsbom.mjs` 之 `captureExSbom`：回傳新增 `removedRelationships`；截圖期間意外結束之錯誤訊息由「…本次結果作廢」改為「…意外結束(離開碼 N),本次截圖作廢;ex-sbom.log 摘錄:…」；失敗時錯誤物件帶已算出之 `removedRelationships`。
- **埠之監聽者之身分確認改用 `wsemi` 之 `execProcessPortPidsSync`**(須 `wsemi` ≥ 1.9.32)：Windows 11 26300(KB5127936)之系統 TCP 狀態值錯誤，`netstat -ano` 會整列漏列新起之監聽、對外連線反列 LISTENING，原自行解析 netstat 之確認因而隨機誤判(漏列 ex-sbom 自身即「截圖完成時埠 N 之監聽者已非本次 ex-sbom」，漏列同埠並存之他服務即連到它)；現改查 `netstat` 與 `Get-NetTCPConnection` 之聯集。**呼叫端影響**：①每次確認約 1 秒(同步呼叫；每次擷取約 3 次)；②深層匯入 `src/exsbom.mjs` 者：新增匯出 `portListeners(port, opt)` 與 `ownsPort(port, pid, opt)`(`ownsPort` 原為內部函式)，查詢失敗拋 `查詢埠 N 之監聽者失敗:…`(原為 `netstat 執行失敗:…`)；`parseNetstat` 不再把狀態欄為 `LISTENING` 而外部位址非 `0.0.0.0:0`／`[::]:0` 之列(對外連線)當成監聽，只用於選埠之快照(`listeningPorts`)。

### 外部執行檔改造

- 移除 `opt.fdTools` 與 `fdOut/tools/`：`WScanDep(fpIn, fdOut)` 不再接受第三參數(傳入即 reject)；掃描工具改存於快取，要共用或改位置請設環境變數 `W_BIN_CACHE`(或預先呼叫 `wsd.ensureBins({ cacheDir })`)。原 `fdOut/tools/` 隨產出交付業主之作法取消。
- 掃描工具不再於每次執行時查 GitHub API 取 `releases/latest`，改依 `bin/manifest.json`(版本標籤網址，校驗 SHA-256 與大小)；`result.json` 之 `tools` 仍為各工具之版本標籤，但取自清單。
- 工具之取得移到 `npm install` 之前：工具取不到(離線無快取、校驗不符等)時立即中止，不待安裝掃描目標相依數分鐘後才失敗。
- 移除 `src/download.mjs`(`ensureTool`、`ensureAllTools`、`installVerDir`)及其深層匯入點；改用 `wsd.ensureBins()`(或深層匯入 `w-scan-dep/src/ensureBins.mjs`)，回傳 `{ [檔名]: 絕對路徑 }`，失敗時 reject 帶 `code` 之 Error。
- ex-sbom 等執行檔之路徑由 `<fdTools>/<工具>/<版本>/…` 改為 `<快取>/<sha256>/<檔名>`，Windows 防火牆對新路徑會再詢問一次。
- 新增相依 `wsemi`(`fsEnsureBins`)。