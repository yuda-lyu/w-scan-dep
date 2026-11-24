//測試輔助(不帶.test.中綴, 不被runner當測試檔): 測試取得外部執行檔(syft、grype、osv-scanner、ex-sbom, 合計約170 MB)之唯一取得點(R-BIN-ENSURE-01 規則 10)
//
//why: mocha --parallel 下各測試檔分屬不同之worker行程; 需要真執行檔之測試(WScanDep.test.mjs、api-scanScope.test.mjs)若各自取得, 首次(快取為空)會同時下載同一批檔案,
//     且mocha預設之180秒時限遠低於下載預算(wsemi之重試與解壓上限)。故:
//     ①一律由本模組之ensureTestBins於需要執行檔之測試檔的before取得(一次取齊全部工具, 不分檔各取其需);
//     ②取得經src/ensureBins.mjs, 即wsemi 1.9.75起之fsEnsureBins(跨程序鎖: 同一快取只下載一次, 他方等候後讀快取; 事件'download'、'lock-wait'、'lock-takeover');
//        測試端直接匯入wsemi/src/fsEnsureBins.mjs(node_modules之單一副本), 不經dist(UMD之dist內嵌其建置時之wsemi, 升wsemi對其無效), 見unit-binsAcquire.test.mjs;
//     ③取得處之時限對齊下載預算(BIN_BUDGET_MS), 不沿用mocha之180秒。
//
//下載預算之算法(同wsemi fsEnsureBinsCore.mjs之lockBudget, wsemi 1.9.75):
//  每個單一檔: 下載次數n × totalMs + 解壓批數x × (totalMs + KILL_WAIT_MS) + min(totalMs, 60000)
//    無鏡像: 直接下載之檔(osv-scanner、ex-sbom) n=1,x=0; 壓縮檔(syft、grype之zip) n=1,x=1; 有鏡像(W_BIN_MIRROR非空)每個來源先試鏡像再試廠商網址, 下載次數多算
//  工具依清單順序逐一取得, 故全部工具之預算為各檔之和, 另加取主幹清單之上限(stallMs)
//  totalMs明給600000(即wsemi預設, 不縮短: 縮短會使慢速網路下之測試比實際使用更易逾時; 以最大之osv-scanner 59 MB計, 600000毫秒約需96 KB/s, 300000毫秒則需約192 KB/s),
//  KILL_WAIT_MS為5000, stallMs為30000(wsemi預設)
//  例(本套件清單, 無鏡像): 2×(600000+(600000+5000)+60000) + 2×(600000+60000) + 30000 = 3880000 毫秒(約64.7分鐘)
//  此為「每次嘗試都耗盡上限」之最壞情形(取得失敗多半為連線錯誤, 數秒內即reject, 不耗盡上限); 網路正常時數十秒即完成。
//  等候他程序持有之鎖亦以同一預算為上限(他方持有者逾此仍未完成即E_LOCK_TIMEOUT); 持有者之鎖檔owner.json之limitMs即同一算式之值(api-ensureBinsLock.test.mjs逐檔對照)
import fs from 'fs'
import path from 'path'
import { fileURLToPath } from 'url'
import ensureBins from '../../src/ensureBins.mjs'


const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..', '..')

//明給wsemi fsEnsureBins之opt.totalMs(每次下載、每批解壓之整體上限, 毫秒); 與wsemi預設同值(600000), 不縮短
export const BIN_TOTAL_MS = 600000

//wsemi之取主幹清單上限(opt.stallMs預設值; 本模組不改)
export const BIN_STALL_MS = 30000

//wsemi之解壓逾時後等其結束之毫秒數(KILL_WAIT_MS)
export const BIN_KILL_WAIT_MS = 5000

//wsemi之持鎖寬裕上限(min(totalMs, 60000)之60000)
const SLACK_MS = 60000

//清單單一檔項允許之欄位: 其餘(parts分割檔、檔案組等)會改變預算之算法, 出現即拋錯而不是低估
const ENTRY_KEYS = ['name', 'url', 'sha256', 'size', 'extract', 'note']
const EXTRACT_KEYS = ['type', 'member', 'sha256', 'size']


//readBinManifest, 讀本套件之基準清單(bin/manifest.json)
export function readBinManifest() {
    return JSON.parse(fs.readFileSync(path.join(ROOT, 'bin', 'manifest.json'), 'utf8'))
}


//calcBinBudgetMs, 依清單與下載上限推得取得全部工具之預算(毫秒); mirror為true時每個來源先試鏡像
export function calcBinBudgetMs(manifest, { totalMs = BIN_TOTAL_MS, mirror = false } = {}) {
    if (!manifest || !Array.isArray(manifest.files) || manifest.files.length === 0) {
        throw new Error('manifest.files must be a non-empty array')
    }
    if (manifest.bundles !== undefined) {
        throw new Error('unsupported manifest key [bundles]: the budget formula does not cover bundles')
    }
    let m = mirror ? 1 : 0
    let sum = BIN_STALL_MS
    for (let f of manifest.files) {
        let ks = Object.keys(f).filter((k) => !ENTRY_KEYS.includes(k))
        if (ks.length > 0) {
            throw new Error(`unsupported manifest entry key(s) [${ks.join(',')}]: the budget formula covers only single files and zip/tgz members`)
        }
        let n = 0
        let x = 0
        if (f.extract) {
            let eks = Object.keys(f.extract).filter((k) => !EXTRACT_KEYS.includes(k))
            if (eks.length > 0) {
                throw new Error(`unsupported manifest extract key(s) [${eks.join(',')}]`)
            }
            n = m + (m + 1)
            x = 1
        }
        else {
            n = m + 1
        }
        sum += n * totalMs + x * (totalMs + BIN_KILL_WAIT_MS) + Math.min(totalMs, SLACK_MS)
    }
    return sum
}


//BIN_BUDGET_MS, 取得全部工具之時限(毫秒), 無鏡像; 由本套件之基準清單推得
export const BIN_BUDGET_MS = calcBinBudgetMs(readBinManifest())


//makeTraceSink, 環境變數WSD_TEST_BINS_TRACE指定檔案時, 把wsemi之onTrace事件逐行(JSONL)附加於該檔(含pid與時刻), 供驗收「只下載一次」; 未設時回傳null(不傳onTrace)
export function makeTraceSink(fp = process.env.WSD_TEST_BINS_TRACE) {
    if (typeof fp !== 'string' || fp === '') {
        return null
    }
    return (ev) => {
        try {
            fs.appendFileSync(fp, `${JSON.stringify({ pid: process.pid, t: Date.now(), ...ev })}\n`)
        }
        catch (err) {
            //記錄失敗不影響取得
        }
    }
}


//ensureTestBins, 取得全部掃描工具(syft、grype、osv-scanner、ex-sbom), 回傳{ [檔名]: 絕對路徑 }
//於mocha之before(或it)內呼叫並傳入this(ctx): 該hook之時限改為BIN_BUDGET_MS; opt.ensure供單元測試替身(預設為src/ensureBins.mjs, 其實作即wsemi之fsEnsureBins)
export async function ensureTestBins(ctx, opt = {}) {
    let ensure = typeof opt.ensure === 'function' ? opt.ensure : ensureBins
    let mirror = typeof process.env.W_BIN_MIRROR === 'string' && process.env.W_BIN_MIRROR !== ''
    let budget = calcBinBudgetMs(readBinManifest(), { totalMs: BIN_TOTAL_MS, mirror })
    if (ctx && typeof ctx.timeout === 'function') {
        ctx.timeout(budget)
    }
    let o = { totalMs: BIN_TOTAL_MS }
    let sink = makeTraceSink()
    if (sink) {
        o.onTrace = sink
    }
    return ensure(o)
}
