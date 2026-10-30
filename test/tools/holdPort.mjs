//占用一個 TCP 埠之子程序(供 api-exsbomPort 測試): 於 argv[3] 位址(預設 127.0.0.1)監聽 argv[2] 埠, 就緒後於 stdout 印 listening, 之後等待被結束
//只綁本機迴圈位址(不觸發 Windows 防火牆詢問); 防殘留: 被測物若漏結束本行程(缺陷), 最多再活 2 分鐘
import net from 'net'

let port = Number(process.argv[2])
let host = process.argv[3] || '127.0.0.1'

let srv = net.createServer((s) => s.destroy())
srv.listen(port, host, () => {
    process.stdout.write('listening\n')
})
srv.on('error', (e) => {
    process.stderr.write(`listen error: ${e.code}\n`)
    process.exit(3)
})
setInterval(() => {}, 1 << 30)
setTimeout(() => process.exit(0), 120000).unref()
