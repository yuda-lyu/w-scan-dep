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
    //   tools/ 本次掃描使用之工具執行檔(syft/grype/osv-scanner/ex-sbom,依版本存放)

}
test()
    .catch((err) => {
        console.log(err)
    })
```

#### Shared tools folder for multiple projects
```alias
let r = await wsd(fpIn, fdOut, { fdTools: './test/tools' })
```

> `opt.fdTools`：掃描工具之下載與版本快取改用該資料夾，多個輸出資料夾共用同一份，此時 `fdOut` 不產出 `tools/`；不可位於 `fdOut` 之 `test`、`pics` 或 `exsbom-work` 內。

> 服務埠：ex-sbom 自 18080 起自動選用 18080～18180 中第一個可用之埠，不需關閉占用 8080 之程式。同時掃描多個專案時，須以不同 node 程序、不同 `fdOut` 執行。

> Windows 防火牆：ex-sbom 執行時監聽全部網路介面，防火牆對每個新的執行檔路徑會詢問一次是否允許存取(改埠不會再詢問)。選「取消」即可，掃描只經本機連線、不受影響；選「允許」則掃描期間 ex-sbom 對網路開放。共用工具資料夾後，同一版本只在第一次詢問。

> 僅支援 Windows：掃描工具（syft / grype / osv-scanner / ex-sbom）皆自 GitHub latest release 下載 Windows 版執行檔。