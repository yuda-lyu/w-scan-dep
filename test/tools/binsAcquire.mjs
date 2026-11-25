//測試輔助(不帶.test.中綴, 不被runner當測試檔): 測試取得外部執行檔(syft、grype、osv-scanner、ex-sbom, 合計約170 MB)之唯一取得點(R-BIN-ENSURE-01 規則 10)
//
//why: mocha --parallel 下各測試檔分屬不同之worker行程; 需要真執行檔之測試(WScanDep.test.mjs、api-scanScope.test.mjs)若各自取得, 首次(快取為空)會同時下載同一批檔案,
//     且mocha預設之180秒時限遠低於下載預算(wsemi之重試與解壓上限)。故:
//     ①一律由本模組之ensureTestBins於需要執行檔之測試檔的before取得(一次取齊全部工具, 不分檔各取其需);
//     ②取得經src/ensureBins.mjs, 即wsemi 1.9.75起之fsEnsureBins(跨程序鎖: 同一快取只下載一次, 他方等候後讀快取; 事件'download'、'lock-wait'、'lock-takeover');
//        測試端直接匯入wsemi/src/fsEnsureBins.mjs(node_modules之單一副本), 不經dist(UMD之dist內嵌其建置時之wsemi, 升wsemi對其無效), 見unit-binsAcquire.test.mjs;
//     ③取得處之時限(BIN_HOOK_MS)取自wsemi 1.9.76起之fsEnsureBinsBudget(與鎖之持有與等候上限同一算式, 單一來源), 不自寫算式, 不沿用mocha之180秒。
//
//時限之取得法(規格: 外部執行檔之存放下載校驗與離線(制式規格)§6 E5-3):
//  單一行程取得全部工具之預算 = fsEnsureBinsBudget('bin/manifest.json', { pkgRoot: 本套件根, totalMs: BIN_TOTAL_MS }); 鏡像(W_BIN_MIRROR)與離線(W_BIN_OFFLINE)由wsemi自環境變數讀取, 與fsEnsureBins之取得同源
//  並行(mocha --parallel之多個worker同時取得同一快取)時, 等候者最壞要先等他方(上限即該預算)、他方失敗才自行取得, 故hook時限取該預算之BIN_PARALLEL_FACTOR(2)倍
//  totalMs明給600000(即wsemi預設, 不縮短: 縮短會使慢速網路下之測試比實際使用更易逾時; 以最大之osv-scanner 59 MB計, 600000毫秒約需96 KB/s, 300000毫秒則需約192 KB/s); 預算與傳給fsEnsureBins之totalMs同為BIN_TOTAL_MS
//  此為「每次嘗試都耗盡上限」之最壞情形(取得失敗多半為連線錯誤, 數秒內即reject, 不耗盡上限); 網路正常時數十秒即完成。
//  等候他程序持有之鎖亦以同一預算為上限(他方持有者逾此仍未完成即E_LOCK_TIMEOUT); 持有者之鎖檔owner.json之limitMs即同一算式之值(api-ensureBinsLock.test.mjs以fsEnsureBinsBudget就壓縮檔與直接檔兩種形狀對照)
import fs from 'fs'
import path from 'path'
import { fileURLToPath } from 'url'
import fsEnsureBinsBudget from 'wsemi/src/fsEnsureBinsBudget.mjs'
import ensureBins from '../../src/ensureBins.mjs'


const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..', '..')

//本套件之基準清單(相對套件根); 與src/ensureBins.mjs交給fsEnsureBins者同一份(unit-binsAcquire.test.mjs對照)
export const BIN_MANIFEST = 'bin/manifest.json'

//明給wsemi fsEnsureBins與fsEnsureBinsBudget之opt.totalMs(每次下載、每批解壓之整體上限, 毫秒); 與wsemi預設同值(600000), 不縮短
export const BIN_TOTAL_MS = 600000

//並行取得之時限倍數: 等候者最壞要先等他方持有者(上限為一個預算), 他方失敗才自行取得(再一個預算)
export const BIN_PARALLEL_FACTOR = 2


//readBinManifest, 讀本套件之基準清單(bin/manifest.json)
export function readBinManifest() {
    return JSON.parse(fs.readFileSync(path.join(ROOT, BIN_MANIFEST), 'utf8'))
}


//binBudgetMs, 單一行程取得全部工具之預算(毫秒), 取自wsemi之fsEnsureBinsBudget(不自寫算式); o可給mirror、offline等(未給者由wsemi讀環境變數W_BIN_MIRROR、W_BIN_OFFLINE, 同fsEnsureBins); budget供單元測試替身
export function binBudgetMs(o = {}, budget = fsEnsureBinsBudget) {
    return budget(BIN_MANIFEST, { ...o, pkgRoot: ROOT, totalMs: BIN_TOTAL_MS })
}


//binHookMs, 並行取得時hook之時限(毫秒) = BIN_PARALLEL_FACTOR × binBudgetMs
export function binHookMs(o = {}, budget = fsEnsureBinsBudget) {
    return BIN_PARALLEL_FACTOR * binBudgetMs(o, budget)
}


//BIN_BUDGET_MS, 單一行程取得全部工具之預算(毫秒), 固定為無鏡像、連網之值; 由wsemi依本套件之基準清單推得
export const BIN_BUDGET_MS = binBudgetMs({ mirror: '', offline: false })


//BIN_HOOK_MS, 取得全部工具之hook時限(毫秒), 固定為無鏡像、連網之值(並行倍數已含)
export const BIN_HOOK_MS = BIN_PARALLEL_FACTOR * BIN_BUDGET_MS


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
//於mocha之before(或it)內呼叫並傳入this(ctx): 該hook之時限改為binHookMs()(fsEnsureBinsBudget之預算 × 並行倍數); opt.ensure、opt.budget供單元測試替身(ensure預設為src/ensureBins.mjs, 其實作即wsemi之fsEnsureBins; budget預設為wsemi之fsEnsureBinsBudget)
export async function ensureTestBins(ctx, opt = {}) {
    let ensure = typeof opt.ensure === 'function' ? opt.ensure : ensureBins
    let budget = typeof opt.budget === 'function' ? opt.budget : fsEnsureBinsBudget
    let hook = binHookMs({}, budget) //無mocha context時亦求取: 清單或選項無效時與取得同樣於下載前即拋錯
    if (ctx && typeof ctx.timeout === 'function') {
        ctx.timeout(hook)
    }
    let o = { totalMs: BIN_TOTAL_MS }
    let sink = makeTraceSink()
    if (sink) {
        o.onTrace = sink
    }
    return ensure(o)
}
