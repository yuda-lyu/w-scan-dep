import wsd from './src/WScanDep.mjs'
// import wsd from './dist/w-scan-dep.umd.js'


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


//node g.mjs
