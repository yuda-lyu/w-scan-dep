//占用目錄之子行程(Windows 下行程之工作目錄無法刪除、改名): 供「被占用者略過」之測試模擬被占用
//子行程取得目錄之時機不由 spawn() 回傳決定(行程初始化後才持有工作目錄之 handle, 高負載下 spawn() 回傳時尚未持有), 故不以延時同步:
//待子行程印出其 cwd(其程式已開始執行, 表示行程初始化完成)並以改名被拒確認該目錄確被持有, 才回傳
import { spawn } from 'child_process'
import fs from 'fs'
import path from 'path'


//holdDir, 回傳 { child, stop }; stop()結束子行程並等其結束
//opt.delayMs>0: 子行程啟動後延遲該毫秒數才 chdir 進該目錄(模擬行程初始化慢), 供驗證呼叫端確實等「確被持有」而非假設 spawn() 回傳即已持有
export async function holdDir(dir, { delayMs = 0 } = {}) {
    let hold = 'console.log(process.cwd()); setTimeout(() => {}, 120000)' //120 秒僅為防殘留, 呼叫端以 stop() 結束
    let code = delayMs > 0 ? `setTimeout(() => { process.chdir(${JSON.stringify(dir)}); ${hold} }, ${delayMs})` : hold
    let child = spawn(process.execPath, ['-e', code], { cwd: delayMs > 0 ? path.dirname(dir) : dir, stdio: ['ignore', 'pipe', 'ignore'], windowsHide: true })
    let stop = async () => {
        child.kill()
        await new Promise((resolve) => (child.exitCode !== null || child.signalCode !== null ? resolve() : child.once('exit', resolve)))
    }
    try {
        let said = ''
        child.stdout.setEncoding('utf8') //路徑可含中文, 避免多位元組字元被切在兩塊之間
        await new Promise((resolve, reject) => {
            child.once('error', reject)
            child.once('exit', (c) => reject(new Error(`占用目錄之子行程於就緒前結束(離開碼 ${c})`)))
            child.stdout.on('data', (d) => {
                said += d
                if (said.includes('\n')) resolve()
            })
        })
        if (path.resolve(said.trim()).toLowerCase() !== path.resolve(dir).toLowerCase()) { //磁碟機代號大小寫不計
            throw new Error(`占用目錄之子行程之 cwd 為 ${said.trim()}, 非 ${dir}`)
        }
        let probe = `${dir}-probe`
        let held = false
        try {
            fs.renameSync(dir, probe)
        }
        catch (e) {
            held = ['EBUSY', 'EPERM', 'EACCES'].includes(e.code)
            if (!held) throw e
        }
        if (!held) {
            fs.renameSync(probe, dir)
            throw new Error('子行程已就緒但其工作目錄仍可改名:占用前提不成立')
        }
    }
    catch (e) {
        await stop()
        throw e
    }
    return { child, stop }
}
