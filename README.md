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
    //   result.json 檢測數據(含各工具版本、osv/grype掃描結果、ex-sbom截圖相對路徑、連鎖更新清單)
    //   result.md 掃描報告
    //   待更新套件.md 連鎖更新清單
    //   pics/*.png ex-sbom拓撲總覽與各漏洞套件截圖

}
test()
    .catch((err) => {
        console.log(err)
    })
```

> 服務埠：ex-sbom 自 18080 起自動選用 18080～18180 中第一個可用之埠，不需關閉占用 8080 之程式。同時掃描多個專案時，須以不同 node 程序、不同 `fdOut` 執行。

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

- 移除 `opt.fdTools` 與 `fdOut/tools/`：`WScanDep(fpIn, fdOut)` 不再接受第三參數(傳入即 reject)；掃描工具改存於快取，要共用或改位置請設環境變數 `W_BIN_CACHE`(或預先呼叫 `wsd.ensureBins({ cacheDir })`)。原 `fdOut/tools/` 隨產出交付業主之作法取消。
- 掃描工具不再於每次執行時查 GitHub API 取 `releases/latest`，改依 `bin/manifest.json`(版本標籤網址，校驗 SHA-256 與大小)；`result.json` 之 `tools` 仍為各工具之版本標籤，但取自清單。
- 工具之取得移到 `npm install` 之前：工具取不到(離線無快取、校驗不符等)時立即中止，不待安裝掃描目標相依數分鐘後才失敗。
- 移除 `src/download.mjs`(`ensureTool`、`ensureAllTools`、`installVerDir`)及其深層匯入點；改用 `wsd.ensureBins()`(或深層匯入 `w-scan-dep/src/ensureBins.mjs`)，回傳 `{ [檔名]: 絕對路徑 }`，失敗時 reject 帶 `code` 之 Error。
- ex-sbom 等執行檔之路徑由 `<fdTools>/<工具>/<版本>/…` 改為 `<快取>/<sha256>/<檔名>`，Windows 防火牆對新路徑會再詢問一次。
- 新增相依 `wsemi`(`fsEnsureBins`)。