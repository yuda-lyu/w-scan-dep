# 依賴套件掃描報告

## 掃描資訊

- 掃描日期：2026-11-06
- 掃描目標：`prj/package.json`
- 掃描範圍：僅 dependencies（正式相依樹，含其所附之執行檔）；devDependencies 之開發與建置工具不在範圍內（其風險由執行機自行掃描或以防毒軟體處理）。

本次掃描所使用之各工具版本（取自執行當下之主幹清單 bin/manifest.json 所載之廠商發布版本，下載後已校驗 SHA-256 與大小，供業主查核）：

| 工具 | 版本 | 來源 |
| --- | --- | --- |
| syft | v1.0.0 | https://github.com/anchore/syft |
| grype | v1.0.1 | https://github.com/anchore/grype |
| osv-scanner | v1.0.2 | https://github.com/google/osv-scanner |
| ex-sbom | v0.2.0 | https://github.com/nics-tw/ex-sbom |

## 一、依賴套件掃描技術
基於「SBOM 開源工具使用說明」所提及之工具進行範例系統之依賴套件掃描：
https://material.nics.nat.gov.tw/material/maintainable/Guide_to_SBOM_and_OSV_Tools/

1. 使用 syft 掃描範例系統安裝依賴
2. 使用 grype 與 osv-scanner 依照各自資料庫去判斷所依賴之風險套件

註：grype 未列於「Guide_to_SBOM_and_OSV_Tools」，但此為 syft 同家產品，資料庫 osv-scanner 相較更新比較完整。

## 二、掃描結果

osv-scanner 掃描如下：

| OSV URL | CVSS | Ecosystem | Package | Version | Fixed Version | Source |
| --- | --- | --- | --- | --- | --- | --- |
| https://osv.dev/GHSA-c2qf-rxjj-qqgw | 5.3 | npm | semver | 7.0.0 | 7.5.2 | test/package-lock.json |

grype 掃描結果：semver(7.0.0) → GHSA-c2qf-rxjj-qqgw [Medium]。

使用 ex-sbom 通過網頁呈現：

註：本次 SBOM 之相依關係含循環，ex-sbom（v0.2.0）無法處理含循環之相依關係，故交給 ex-sbom 之 SBOM 副本剔除 1 筆構成循環之關係（只影響下方拓撲之層級呈現，不影響 osv-scanner 與 grype 之結果）：string.prototype.trim@1.2.11 DEPENDENCY_OF es-abstract@1.24.2。

![ex-sbom 拓撲總覽](./pics/topology-overview.png)

![semver (7.0.0)](./pics/semver-7.0.0.png)

![vue (2.7.16)](./pics/vue-2.7.16.png)

ex-sbom(依其內建漏洞資料庫)判定為漏洞之套件共 2 個，分別為：semver(7.0.0)、vue(2.7.16)。

ex-sbom 拓撲分層漏洞概況：第 1 級(2)、第 2 級(1)。

綜合 osv-scanner、grype 與 ex-sbom 三項工具(各自資料庫不同)，本次被標注為漏洞之套件(以套件名去重)共 3 種：vue、xlsx、semver。

【xlsx 套件說明】

xlsx 套件現名 SheetJS（https://cdn.sheetjs.com/），雖已許久未有更新，但實際已修復漏洞。此外，xlsx 新版現已不發送上 npm，故得要通過指定 cdn 才能安裝使用。實際新版卻被 osv-scanner 報錯，主要是誤報，因 osv-scanner 資料庫是基於 npm，npm 上最新只有舊版，故會偵測出此套件有漏洞，但亦無法修復（因 npm 沒有更新版）。改用 grype 偵測，此資料庫有針對 xlsx 去特殊標注，故 xlsx 新版不會被偵測報告成漏洞套件。

【vue 套件/框架說明】

目前範例系統都使用 vue（2.7.16），此為 vue2 最新版。其被提報之漏洞主要是中低風險漏洞，詳情如下表 1：

表 1 Vue2 已知漏洞

| 漏洞 | 觸發條件 | 情境 |
| --- | --- | --- |
| **ReDoS**<br>CVSS：3.7（Low） | 攻擊者需能注入惡意 Vue 模板 | **幾乎不受影響**：模板是開發者寫的，使用者無法控制 |
| **XSS via prototype pollution**<br>CVSS：4.2（Medium） | 需先有 prototype pollution 入口 | **風險低**：除非其他依賴有 prototype pollution 漏洞可串聯 |

若欲修復此 2 漏洞，仍須待之後進行大規模之底層重構，才有辦法讓範例系統由 vue2 升 vue3 版。
