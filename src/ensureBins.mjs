// 取得本套件之外部執行檔(syft、grype、osv-scanner、ex-sbom):套件端唯一入口,實作為 wsemi 之 fsEnsureBins。
// 規格:外部執行檔之存放下載校驗與離線(制式規格)§6 E2;本套件不另寫下載、快取、鏡像、校驗與解壓。
import fsEnsureBins from 'wsemi/src/fsEnsureBins.mjs'
import { ROOT } from './config.mjs'

// 套件根(config.mjs 以本檔所在資料夾推得,不依賴工作目錄;src/ 與 dist/ 皆位於套件根之下一層)
const pkgRoot = ROOT

/**
 * 取得本套件之外部執行檔syft.exe、grype.exe、osv-scanner.exe、ex-sbom.exe: 首次使用時依bin/manifest.json下載(或自鏡像取得)，以其SHA-256與大小校驗後存於快取，之後自快取取得(亦校驗)
 *
 * 本套件為主幹模式(mode為floating): 先取GitHub主幹(master)之bin/manifest.json，取不到(含離線)時用npm包內之基準清單。各檔來源為廠商發布之版本標籤資產網址，不為releases/latest；更新版本不須發布套件，推送新清單即可(見toolg/genBinManifest.mjs)。
 * 實作為wsemi之fsEnsureBins，規格: 外部執行檔之存放下載校驗與離線(制式規格)§6。環境變數: W_BIN_CACHE(快取改放<W_BIN_CACHE>/w-scan-dep/)、W_BIN_MIRROR(鏡像，結構<鏡像>/w-scan-dep/<sha256>/<檔名>)、W_BIN_OFFLINE(1為離線)，見README〈外部執行檔〉
 *
 * @param {Object} [opt={}] 輸入設定物件，交wsemi之fsEnsureBins(names、cacheDir、mirror、offline、onProgress等)，pkgRoot固定為本套件根，floatingManifestUrl不轉傳
 * @returns {Promise} 回傳Promise，resolve回傳{ [檔名]: 絕對路徑 }，reject回傳帶code之Error(E_OFFLINE_MISSING、E_HASH_MISMATCH、E_EXTRACT等)
 * @example
 * import ensureBins from 'w-scan-dep/src/ensureBins.mjs'
 *
 * async function test() {
 *
 *     // 部署前預先取得(連網機器設W_BIN_CACHE=<資料夾>後執行，該資料夾即可作為離線鏡像W_BIN_MIRROR)
 *     let bins = await ensureBins()
 *
 *     console.log('bins', bins)
 *     // bins {
 *     //   'syft.exe': 'D:\\xxx\\node_modules\\w-scan-dep\\bin-cache\\<sha256>\\syft.exe',
 *     //   'grype.exe': '...', 'osv-scanner.exe': '...', 'ex-sbom.exe': '...'
 *     // }
 *
 * }
 * test()
 *     .catch((err) => {
 *         console.log('catch', err)
 *     })
 *
 */
function ensureBins(opt = {}) {

    // floatingManifestUrl 會改變清單之信任錨,不轉傳使用者之值(主幹清單網址由清單之 repo 與 manifestPath 決定)
    const { floatingManifestUrl, ...o } = opt || {} // eslint-disable-line no-unused-vars

    return fsEnsureBins('bin/manifest.json', { ...o, pkgRoot })
}

export default ensureBins
