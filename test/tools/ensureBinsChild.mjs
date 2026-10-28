//測試輔助(子行程): 於他處工作目錄載入指定之ensureBins.mjs並離線呼叫, 輸出{ cwd, code, cachePath }(JSON, 最後一行)
//用法: node ensureBinsChild.mjs <ensureBins.mjs之絕對路徑>
import { pathToFileURL } from 'url'

let mod = await import(pathToFileURL(process.argv[2]).href)
let err = null
try {
    await mod.default({ offline: true, mirror: '' })
}
catch (e) {
    err = e
}
let miss = err && err.missing && err.missing[0] ? err.missing[0] : {}
console.log(JSON.stringify({ cwd: process.cwd(), code: err && err.code, cachePath: miss.cachePath }))
