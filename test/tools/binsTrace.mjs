//測試輔助(不帶.test.中綴): 判讀binsAcquire.mjs之makeTraceSink所寫之事件檔(JSONL, 每行{ pid, t, type, ... }), 判定各執行檔是否只下載一次(R-BIN-ENSURE-01 規則 10)
//用法(驗收: 清空快取後平行跑全套, 以事件而非全綠為準):
//  先刪除舊事件檔(只附加不清空, 舊事件會使冷快取判定為重複下載), 再 set WSD_TEST_BINS_TRACE=<事件檔>  後執行  npm test
//  node test/tools/binsTrace.mjs <事件檔> [--warm]      離開碼: 0 通過, 1 不通過, 2 用法錯誤(無檔案、無事件、解析失敗)
//  冷快取(預設)每個工具之'download'須恰1次; --warm(快取已備妥)須0次
//全綠不證明只下載一次(本機網速快時各自下載亦全綠), 只有事件(或計數)看得出
import fs from 'fs'
import { fileURLToPath } from 'url'
import { readBinManifest } from './binsAcquire.mjs'


//parseTrace, 事件檔文字 → 事件陣列(空行略過; 任一行無法解析即拋錯)
export function parseTrace(text) {
    let evs = []
    let lines = String(text).split(/\r?\n/)
    for (let i = 0; i < lines.length; i++) {
        let s = lines[i].trim()
        if (s === '') {
            continue
        }
        let ev = null
        try {
            ev = JSON.parse(s)
        }
        catch (err) {
            throw new Error(`trace line ${i + 1} is not JSON`)
        }
        if (ev === null || typeof ev !== 'object' || typeof ev.type !== 'string') {
            throw new Error(`trace line ${i + 1} has no type`)
        }
        evs.push(ev)
    }
    return evs
}


//judgeTrace, 事件陣列 → { ok, reasons, perName, pids }; perName[name]為各事件次數與觸及之行程數
export function judgeTrace(evs, { names, cold = true } = {}) {
    let perName = {}
    let get = (name) => {
        if (!perName[name]) {
            perName[name] = { download: 0, downloadPids: new Set(), lockWait: 0, lockWaitTimeout: 0, takeover: 0, skip: 0, fail: 0 }
        }
        return perName[name]
    }
    let pids = new Set()
    for (let ev of evs) {
        pids.add(ev.pid)
        if (typeof ev.name !== 'string') {
            continue
        }
        let r = get(ev.name)
        if (ev.type === 'download') {
            r.download++
            r.downloadPids.add(ev.pid)
        }
        else if (ev.type === 'lock-wait' && ev.phase === 'start') {
            r.lockWait++
        }
        else if (ev.type === 'lock-wait' && ev.phase === 'timeout') {
            r.lockWaitTimeout++
        }
        else if (ev.type === 'lock-takeover') {
            r.takeover++
        }
        else if (ev.type === 'lock-skip') {
            r.skip++
        }
        else if (ev.type === 'fail') {
            r.fail++
        }
    }
    let reasons = []
    for (let n of names) {
        let r = get(n)
        let want = cold ? 1 : 0
        if (r.download !== want) {
            reasons.push(`${n}: download ${r.download} times by ${r.downloadPids.size} process(es), expected ${want}`)
        }
        if (r.fail > 0) {
            reasons.push(`${n}: fail ${r.fail}`)
        }
        if (r.lockWaitTimeout > 0) {
            reasons.push(`${n}: lock-wait timeout ${r.lockWaitTimeout}`)
        }
        if (r.skip > 0) {
            reasons.push(`${n}: lock-skip ${r.skip} (the lock could not be created, so the download was not serialized)`)
        }
    }
    return { ok: reasons.length === 0, reasons, perName, pids: [...pids] }
}


//main, 命令列入口
function main(argv) {
    let warm = argv.includes('--warm')
    let fp = argv.find((v) => !v.startsWith('--'))
    if (!fp || !fs.existsSync(fp)) {
        console.error('usage: node binsTrace.mjs <trace.jsonl> [--warm]')
        return 2
    }
    let evs = []
    try {
        evs = parseTrace(fs.readFileSync(fp, 'utf8'))
    }
    catch (err) {
        console.error(err.message)
        return 2
    }
    if (evs.length === 0) {
        console.error('no trace events')
        return 2
    }
    let names = readBinManifest().files.map((f) => f.name)
    let r = judgeTrace(evs, { names, cold: !warm })
    console.log(`events ${evs.length}, processes ${r.pids.length}`)
    for (let n of names) {
        let v = r.perName[n]
        console.log(`${n}: download ${v.download} (processes ${v.downloadPids.size}), lock-wait ${v.lockWait}, takeover ${v.takeover}, skip ${v.skip}, fail ${v.fail}`)
    }
    for (let s of r.reasons) {
        console.log(`NG ${s}`)
    }
    console.log(r.ok ? 'OK' : 'NG')
    return r.ok ? 0 : 1
}

//isMain, 本檔是否為命令列入口; 兩側皆取真實路徑(經目錄連結或大小寫不同之路徑執行時, 不得靜默不執行而以離開碼 0 結束)
function isMain() {
    try {
        let a = fs.realpathSync(process.argv[1]).toLowerCase()
        let b = fs.realpathSync(fileURLToPath(import.meta.url)).toLowerCase()
        return a === b
    }
    catch (err) {
        return false
    }
}

if (process.argv[1] && isMain()) {
    process.exitCode = main(process.argv.slice(2))
}
