//測試輔助(子行程): 於假套件根載入其src/ensureBins.mjs(原樣複製之被測程式), 以本機假伺服器為來源取得全部工具, 逐行輸出wsemi之onTrace事件(JSON), 最後一行輸出結果
//用法: node ensureBinsLockChild.mjs <假套件根之ensureBins.mjs絕對路徑> <快取資料夾> <伺服器埠> [totalMs]
//輸出: 每行一個JSON; 事件行為{ ev: {...} }, 最後一行為{ done: true, paths } 或 { done: true, error: <code>, message }
//api-ensureBinsLock.test.mjs以多個本行程同時取得同一個空快取, 驗證跨程序只下載一次; totalMs給了即傳給fsEnsureBins(用以對照鎖檔之limitMs與預算算式)
import { pathToFileURL } from 'url'
import { mkFetch } from './fakeBins.mjs'

let [fpEnsure, cacheDir, port, totalMs] = process.argv.slice(2)
let mod = await import(pathToFileURL(fpEnsure).href)
let fetch = mkFetch(Number(port), [])
let out = (o) => process.stdout.write(`${JSON.stringify(o)}\n`)

let res = null
try {
    let opt = {
        cacheDir,
        fetch,
        mirror: '',
        offline: false,
        onTrace: (ev) => {
            out({ ev })
        },
    }
    if (totalMs) {
        opt.totalMs = Number(totalMs)
    }
    let paths = await mod.default(opt)
    res = { done: true, paths }
}
catch (err) {
    res = { done: true, error: (err && err.code) || 'E_UNKNOWN', message: err && err.message }
}
out(res)
