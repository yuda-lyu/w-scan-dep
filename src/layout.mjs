// fdOut 產物落點與掃描工具資料夾之決定與防呆。
// (2026-10-02 擴充 opt.fdTools: 工具下載與版本快取可改用指定之共用資料夾,多個 fdOut 共用同一份;
//  同版本之執行檔路徑因此固定。ex-sbom 監聽全部網路介面,Windows 防火牆依執行檔完整路徑詢問,
//  每換一個 fdOut 就多問一次;共用後只在每台機器、每個 ex-sbom 版本第一次詢問)
import { join, resolve, relative, isAbsolute, sep } from 'node:path'

// p 是否等於 dir 或位於 dir 之內(以路徑段判斷,非字串前綴;Windows 下 path.relative 不分大小寫)
function isWithin(p, dir) {
    const rel = relative(dir, p)
    return rel === '' || (rel !== '..' && !rel.startsWith('..' + sep) && !isAbsolute(rel))
}

export function resolveLayout(fdOut, opt) {
    if (opt !== undefined && opt !== null && typeof opt !== 'object') throw new Error(`opt 需為物件:${opt}`)
    const fdTools = opt?.fdTools
    if (fdTools !== undefined && fdTools !== null && typeof fdTools !== 'string') throw new Error(`opt.fdTools 需為資料夾路徑字串:${fdTools}`)

    const outDir = resolve(fdOut)
    const testDir = join(outDir, 'test') // 全新安裝之掃描目標(與 tools 分離, 避免 syft 編目掃描工具自身之 exe)
    const scanDir = join(outDir, 'scan') // syft/grype/osv 原始產物
    const picsDir = join(outDir, 'pics') // ex-sbom 截圖
    const exsbomDir = join(outDir, 'exsbom-work') // ex-sbom 工作目錄之根(每次掃描一個專用子夾,結束後刪除)
    const shared = !!fdTools
    // 掃描工具:未給 opt.fdTools 時放 fdOut/tools(隨 fdOut 交付業主);有給時改用該共用資料夾,fdOut 不產出 tools
    const toolsDir = shared ? resolve(fdTools) : join(outDir, 'tools')

    // test 為 syft 編目之掃描目標,工具放其內會被編入 SBOM;pics 每次掃描整夾刪除重建、exsbom-work 每次清除(exsbom.mjs)
    for (const [name, dir, why] of [
        ['test', testDir, '其為 syft 掃描目標,工具會被編入 SBOM'],
        ['pics', picsDir, '其每次掃描整夾刪除重建'],
        ['exsbom-work', exsbomDir, '其為 ex-sbom 工作目錄,每次掃描清除'],
    ]) {
        if (isWithin(toolsDir, dir)) throw new Error(`opt.fdTools 不可位於輸出資料夾之 ${name} 內(${why}):${toolsDir}`)
    }
    return { outDir, testDir, scanDir, picsDir, exsbomDir, toolsDir, shared }
}
