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
import wsm from 'w-scan-dep'

async function test() {

    let fpIn = './test/prj/package.json'
    let fdOut = './test/output'
    let opt = { install: true }

    let r = await wsm(fpIn, fdOut, opt)
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

> 僅支援 Windows：掃描工具（syft / grype / osv-scanner / ex-sbom）皆自 GitHub latest release 下載 Windows 版執行檔。