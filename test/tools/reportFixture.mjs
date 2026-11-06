//報告產製(buildReport)之夾具: 一份含 vue、xlsx、semver 被標注之掃描結果, 供 unit-report.test.mjs 與產生 golden 共用
//資料皆為虛構之輸入, 唯 semver@7.0.0 之 GHSA-c2qf-rxjj-qqgw 為真實公告(與 test/fixtures/vuln.spdx.json 同), vue、xlsx 之編號為真實之 CVE 但不顯示於報告(僅作 osv 套件之欄位)

export const target = 'prj/package.json'
export const date = '2026-11-06'
export const picsPrefix = './pics/'

export const toolVersions = {
    'syft': { version: 'v1.0.0' },
    'grype': { version: 'v1.0.1' },
    'osv-scanner': { version: 'v1.0.2' },
    'ex-sbom': { version: 'v0.2.0' },
}

export const scan = {
    osv: {
        mdText: '| OSV URL | CVSS | Ecosystem | Package | Version | Fixed Version | Source |\n| --- | --- | --- | --- | --- | --- | --- |\n| https://osv.dev/GHSA-c2qf-rxjj-qqgw | 5.3 | npm | semver | 7.0.0 | 7.5.2 | test/package-lock.json |',
        packages: [
            { name: 'vue', version: '2.7.16', vulns: [{ id: 'CVE-2024-9506' }] },
            { name: 'xlsx', version: '0.20.3', vulns: [{ id: 'CVE-2023-30533' }] },
            { name: 'semver', version: '7.0.0', vulns: [{ id: 'GHSA-c2qf-rxjj-qqgw' }] },
        ],
    },
    grype: {
        matches: [
            { name: 'semver', version: '7.0.0', id: 'GHSA-c2qf-rxjj-qqgw', severity: 'Medium' },
        ],
    },
}

//ex-sbom 截圖成功: 總覽圖、各漏洞套件截圖(vue、semver)、拓撲分層概況、剔除之循環關係
export const exsbomOk = {
    ok: true,
    error: null,
    overviewShot: 'C:/x/pics/topology-overview.png',
    componentShots: [
        { name: 'vue', version: '2.7.16', ids: ['CVE-2024-9506'], shot: 'C:/x/pics/vue-2.7.16.png' },
        { name: 'semver', version: '7.0.0', ids: ['GHSA-c2qf-rxjj-qqgw'], shot: 'C:/x/pics/semver-7.0.0.png' },
    ],
    summary: [
        { title: '第 1 級（直接相依）', badge: '2' },
        { title: '第 2 級', badge: '1' },
    ],
    removedRelationships: [
        { from: 'string.prototype.trim@1.2.11', to: 'es-abstract@1.24.2', relationshipType: 'DEPENDENCY_OF' },
    ],
}

//ex-sbom 截圖失敗(原因含 log 摘錄)
export const exsbomNg = {
    ok: false,
    error: 'ex-sbom(PID 1)於截圖期間意外結束(離開碼 2),本次截圖作廢;ex-sbom.log 摘錄:\nfatal error: stack overflow\nline2',
    overviewShot: null,
    componentShots: [],
    summary: [],
    removedRelationships: null,
}

export const base = { target, toolVersions, scan, date, picsPrefix }
