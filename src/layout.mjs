// fdOut 產物落點之決定與掃描工具位置之防呆。
// (2026-10-29 外部執行檔改依 bin/manifest.json 經 ensureBins 取得並存於快取(預設 <套件根>/bin-cache/,可由環境變數 W_BIN_CACHE 改位置),
//  不再有 opt.fdTools 與 fdOut/tools;工具位置改於取得後檢查,見 assertToolsOutside)
import { join, resolve, relative, isAbsolute, sep } from 'node:path'

// p 是否等於 dir 或位於 dir 之內(以路徑段判斷,非字串前綴;Windows 下 path.relative 不分大小寫)
function isWithin(p, dir) {
    const rel = relative(dir, p)
    return rel === '' || (rel !== '..' && !rel.startsWith('..' + sep) && !isAbsolute(rel))
}

export function resolveLayout(fdOut) {
    const outDir = resolve(fdOut)
    const testDir = join(outDir, 'test') // 全新安裝之掃描目標(與工具分離, 避免 syft 編目掃描工具自身之 exe)
    const scanDir = join(outDir, 'scan') // syft/grype/osv 原始產物
    const picsDir = join(outDir, 'pics') // ex-sbom 截圖
    const exsbomDir = join(outDir, 'exsbom-work') // ex-sbom 工作目錄之根(每次掃描一個專用子夾,結束後刪除)
    return { outDir, testDir, scanDir, picsDir, exsbomDir }
}

// 掃描工具(ensureBins 取得之絕對路徑)不可位於 fdOut 之 test、pics 或 exsbom-work 內:
// test 為 syft 編目之掃描目標,工具放其內會被編入 SBOM;pics 每次掃描整夾刪除重建、exsbom-work 每次清除(exsbom.mjs)
export function assertToolsOutside(exePaths, layout) {
    for (const [name, dir, why] of [
        ['test', layout.testDir, '其為 syft 掃描目標,工具會被編入 SBOM'],
        ['pics', layout.picsDir, '其每次掃描整夾刪除重建'],
        ['exsbom-work', layout.exsbomDir, '其為 ex-sbom 工作目錄,每次掃描清除'],
    ]) {
        for (const p of exePaths) {
            if (isWithin(resolve(p), dir)) {
                throw new Error(`掃描工具不可位於輸出資料夾之 ${name} 內(${why}):${p};請改以環境變數 W_BIN_CACHE 指向他處`)
            }
        }
    }
}
