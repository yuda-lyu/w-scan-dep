// 掃描目標之 npm 安裝狀態清除:重跑同一 fdOut 時,testDir 內上一次之 package-lock.json 與 node_modules
// 若殘留,npm install 會依舊鎖定檔並沿用已裝套件(僅刪 lock 亦不足),掃到的是「上一次相依樹+本次改動」,
// 不是 package.json 之當前解析結果(2026-10-02 修正,見 建議w-scan-dep修正.md)。
// 只刪 npm 產生之狀態,不刪整個 testDir:fdOut 若誤指專案根目錄,整夾刪除會刪到使用者之 ./test。
import { rm, access } from 'node:fs/promises'
import { join } from 'node:path'

export const NPM_STATE = ['package-lock.json', 'node_modules']

const exists = async (p) => {
    try {
        await access(p)
        return true
    }
    catch {
        return false
    }
}

const HINT = 'Windows 下多為檔案或資料夾被占用(編輯器、防毒、終端機停在其內、前次未結束之掃描程序),' +
    '請關閉占用程式或手動刪除後重跑;不以舊內容繼續掃描'

export async function clearNpmState(testDir) {
    for (const name of NPM_STATE) {
        const p = join(testDir, name)
        try {
            // maxRetries:防毒/索引短暫持有檔案時重試(EBUSY、EPERM、ENOTEMPTY)
            await rm(p, { recursive: true, force: true, maxRetries: 5, retryDelay: 200 })
        } catch (e) {
            throw new Error(`清除上次安裝殘留失敗:${p}(${e.code || e.message})。${HINT}`)
        }
        // 回驗:rm 未拋錯不代表已刪除
        if (await exists(p)) throw new Error(`清除上次安裝殘留後仍存在:${p}。${HINT}`)
    }
}
