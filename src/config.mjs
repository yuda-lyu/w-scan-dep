// 全域設定:路徑錨點,掃描工具定義,已知套件說明
// 路徑錨點採「腳本所在資料夾」(fileURLToPath),使掃描工具之產物一律落在
// 本掃描專案資料夾,不隨呼叫者 cwd 飄移(§10.1 場景 B:套件自帶工作資料)。
import { fileURLToPath } from 'node:url'
import { dirname, join, resolve } from 'node:path'

const __dirname = dirname(fileURLToPath(import.meta.url))
export const ROOT = resolve(__dirname, '..')          // 掃描專案根目錄

// 產出目錄(皆錨定於 ROOT)
export const OUTPUT_DIR = join(ROOT, 'output')        // syft / grype / osv 產物
export const SHOTS_DIR = join(ROOT, 'shots')          // ex-sbom 截圖
export const TMP_DIR = join(ROOT, 'tmp')              // 暫存(§11.2)

// ex-sbom 網頁服務埠:自 FIRST 起依序選用第一個可用者(ex-sbom 讀 PORT 環境變數,v0.2.0 main.go:56-59)。
// 刻意避開 8080:為前端開發伺服器常用埠(Vue CLI、webpack-dev-server 自動找埠亦自 8080 往上),
// 掃描期間占用會使其無法啟動(2026-10-03,見 建議w-scan-dep修正.md 與三審複審)
export const EXSBOM_PORT_FIRST = 18080
export const EXSBOM_PORT_LAST = 18180

// 掃描工具(外部執行檔):key、廠商 repo(報告引用)、執行檔名(須與 bin/manifest.json 之 name 相同)。
// 取得方式(來源網址、sha256、大小)不在此定義,見 ensureBins.mjs 與 bin/manifest.json;更新版本用 toolg/genBinManifest.mjs。
export const TOOLS = [
    { key: 'syft', repo: 'anchore/syft', exeName: 'syft.exe' },
    { key: 'grype', repo: 'anchore/grype', exeName: 'grype.exe' },
    { key: 'osv-scanner', repo: 'google/osv-scanner', exeName: 'osv-scanner.exe' },
    { key: 'ex-sbom', repo: 'nics-tw/ex-sbom', exeName: 'ex-sbom.exe' },
]

// 掃描範圍(2026-10-30,建議w-scan-dep調整.md〔Gitea #27〕,使用者裁定):掃描對象為網頁前後端服務或編譯出之應用程式(app),
// 只算 dependencies 所提供者(程式碼與其所附之執行檔);devDependencies 之開發與建置工具不在範圍(不是服務,也不會包入 app 執行,
// 其風險由執行機自行掃描或以防毒軟體處理)。值寫入 result.json 之 scope,說明句寫入 result.md
export const SCAN_SCOPE = 'dependencies'
export const SCAN_SCOPE_NOTE = '僅 dependencies（正式相依樹，含其所附之執行檔）；devDependencies 之開發與建置工具不在範圍內（其風險由執行機自行掃描或以防毒軟體處理）'

// 已知套件之人工說明(領域知識,非掃描器輸出)。
// 報告產製時,若掃描結果命中對應套件名,則附上此說明段落。
// vue 之 Vue2 已知漏洞表由使用者提供之截圖(image-3.png)轉為 markdown 表格。
export const PACKAGE_NOTES = {
    xlsx: {
        heading: '【xlsx 套件說明】',
        body: [
            'xlsx 套件現名 SheetJS（https://cdn.sheetjs.com/），雖已許久未有更新，但實際已修復漏洞。' +
            '此外，xlsx 新版現已不發送上 npm，故得要通過指定 cdn 才能安裝使用。' +
            '實際新版卻被 osv-scanner 報錯，主要是誤報，因 osv-scanner 資料庫是基於 npm，' +
            'npm 上最新只有舊版，故會偵測出此套件有漏洞，但亦無法修復（因 npm 沒有更新版）。' +
            '改用 grype 偵測，此資料庫有針對 xlsx 去特殊標注，故 xlsx 新版不會被偵測報告成漏洞套件。',
        ].join(''),
    },
    vue: {
        heading: '【vue 套件/框架說明】',
        body: [
            '目前高放全系統都使用 vue（2.7.16），此為 vue2 最新版。' +
            '其被提報之漏洞主要是中低風險漏洞，詳情如下表 1：',
            '',
            '表 1 Vue2 已知漏洞',
            '',
            '| 漏洞 | 觸發條件 | 情境 |',
            '| --- | --- | --- |',
            '| **ReDoS**<br>CVSS：3.7（Low） | 攻擊者需能注入惡意 Vue 模板 | **幾乎不受影響**：模板是開發者寫的，使用者無法控制 |',
            '| **XSS via prototype pollution**<br>CVSS：4.2（Medium） | 需先有 prototype pollution 入口 | **風險低**：除非其他依賴有 prototype pollution 漏洞可串聯 |',
            '',
            '若欲修復此 2 漏洞，仍須待之後進行大規模之底層重構，才有辦法讓高放主系統由 vue2 升 vue3 版。',
        ].join('\n'),
    },
}

// 報告參考之官方工具說明連結
export const GUIDE_URL = 'https://material.nics.nat.gov.tw/material/maintainable/Guide_to_SBOM_and_OSV_Tools/'

// 自有套件判別(用於「待更新套件」清單:定位漏洞應於哪個自有套件內修復)。
// 本專案自有套件命名為 w-* 前綴與 wsemi。若日後有其他命名可在此擴充。
export const SELF_OWNED = (name) => /^w-/.test(name) || name === 'wsemi'
