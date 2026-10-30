//扮演「卡住」之外部掃描工具(syft、grype、osv-scanner): 連上無回應之服務(hangRegistry)後永遠等待, 不結束
//用法: 以process.execPath當執行檔, 環境變數NODE_OPTIONS=--import=<本檔之file URL>, 並設FAKE_HANG_PORT;
//preload先於任何主程式執行, 故不論被傳入何種參數(scan dir:... / sbom:... / -L ...)皆卡在此處
//行程樹: 根行程另啟一個detached之孫行程(亦連上同一服務並永遠等待), 驗證逾時時「整個子行程樹」皆被結束, 而非只結束根行程
//孫行程以本檔為主程式啟動(不帶NODE_OPTIONS, 避免遞迴衍生), 由FAKE_HANG_ROLE=grandchild辨識
import net from 'net'
import { spawn } from 'child_process'
import { fileURLToPath } from 'url'

const port = Number(process.env.FAKE_HANG_PORT)
const role = process.env.FAKE_HANG_ROLE || 'root'

const sock = net.connect(port, '127.0.0.1') //連上後等對方回應, 對方永不回應
sock.on('error', () => {})

if (role === 'root') {
    spawn(process.execPath, [fileURLToPath(import.meta.url)], {
        detached: true,
        stdio: 'ignore',
        windowsHide: true,
        env: { ...process.env, NODE_OPTIONS: '', FAKE_HANG_ROLE: 'grandchild' },
    }).unref()
}

setInterval(() => {}, 1 << 30) //保持行程存活
setTimeout(() => process.exit(0), 120000).unref() //防殘留: 被測物若漏結束本行程(缺陷), 最多再活2分鐘; 遠大於各案之時限, 不參與判定
await new Promise(() => {}) //preload內永不返回: 主程式(若有)不會執行
