// 掃描目標之 npm 安裝狀態清除:重跑同一 fdOut 時,testDir 內上一次之 package-lock.json 與 node_modules
// 若殘留,npm install 會依舊鎖定檔並沿用已裝套件(僅刪 lock 亦不足),掃到的是「上一次相依樹+本次改動」,
// 不是 package.json 之當前解析結果(2026-10-02 修正,見 建議w-scan-dep修正.md)。
// 只刪 npm 產生之狀態,不刪整個 testDir:fdOut 若誤指專案根目錄,整夾刪除會刪到使用者之 ./test。
// (2026-10-29 修正,見 建議w-scan-dep修正.md(Gitea #24)三:npm install 加時限,逾時即結束整個安裝子行程樹並拋錯,見 npmInstall)
import { rm, access } from 'node:fs/promises'
import { spawn } from 'node:child_process'
import { join } from 'node:path'
import { timeoutMsFromEnv, waitChild, killNote, fmtMs } from './proc.mjs'

export const NPM_STATE = ['package-lock.json', 'node_modules']

// npm install 時限之預設(秒):實測 2000 個套件之全新安裝約 4 分鐘(sgud/exp/experience.md §3),取約 5 倍容納較慢之網路與倉庫
export const NPM_INSTALL_TIMEOUT_DEFAULT = 20 * 60

// 時限(毫秒)取自環境變數 W_NPM_INSTALL_TIMEOUT(秒,正數,至多 2147483);未設為預設值,不合法即拋錯(不靜默改用預設)
export function npmInstallTimeoutMs(env = process.env) {
    return timeoutMsFromEnv('W_NPM_INSTALL_TIMEOUT', NPM_INSTALL_TIMEOUT_DEFAULT, env)
}

// 於 cwd 執行 npm install;倉庫或網路無回應時 npm 可能久候不止(2026-10-29 提出端曾等約 3.5 小時),
// 逾時即以 taskkill /T 結束整個子行程樹並拋出含「逾時」之錯誤。
// shell:true 時子行程為 cmd.exe,npm 之 node 為其子行程:只結束 cmd.exe 時 npm 仍續跑,故須樹狀結束
export async function npmInstall(cwd, { timeoutMs = NPM_INSTALL_TIMEOUT_DEFAULT * 1000 } = {}) {
    const child = spawn('npm install --no-audit --no-fund', { cwd, shell: true, stdio: 'inherit', windowsHide: true })
    const r = await waitChild(child, timeoutMs)
    if (r.timedOut) {
        throw new Error(`npm install 逾時(超過 ${fmtMs(timeoutMs)}未完成),${killNote(r, '安裝')};可設環境變數 W_NPM_INSTALL_TIMEOUT(秒)調整時限`)
    }
    if (r.error) throw new Error(`npm install 無法啟動(${r.error.code || r.error.message})`)
    if (r.code !== 0) throw new Error(`npm install 失敗(exit ${r.code})`)
}

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
