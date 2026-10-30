//扮演ex-sbom之服務(供api-wsdEntry測試): 讀PORT, 只綁127.0.0.1(不觸發Windows防火牆詢問), 頁面標題為ex-sbom(通過就緒判定)
//瀏覽器(HeadlessChrome)取得頁面後, 依Go runtime之格式輸出fatal error: stack overflow並以離開碼2結束,
//重現ex-sbom v0.2.0遇相依循環之結束方式(上游internal/service/sbom/spdx_sbom.go:140); 由瀏覽器之請求觸發, 不依時間
import http from 'http'

let port = Number(process.env.PORT)
let crash = [
    'runtime: goroutine stack exceeds 1000000000-byte limit',
    'runtime: sp=0xc0205e0398 stack=[0xc0205e0000, 0xc0405e0000]',
    'fatal error: stack overflow',
    '',
    'runtime stack:',
    'runtime.throw({0x1b2c5e1?, 0x0?})',
    'runtime.newstack()',
    '',
    'goroutine 52 gp=0xc000602fc0 m=8 mp=0xc000500008 [running]:',
    'ex-sbom/internal/service/sbom.getSpdxDependencyDepthMap.func1({0xc0001b4f00, 0x2c}, 0x1e8479)',
    '',
].join('\n')

let srv = http.createServer((req, res) => {
    if (/HeadlessChrome/.test(req.headers['user-agent'] || '')) {
        res.on('finish', () => {
            process.stdout.write(crash, () => process.exit(2))
        })
    }
    res.end('<!doctype html><html><head><title>ex-sbom</title></head><body><button id="lang-zh">中文</button></body></html>')
})
srv.listen(port, '127.0.0.1', () => {
    process.stdout.write(`[GIN-debug] Listening and serving HTTP on 127.0.0.1:${port}\n`)
})
setTimeout(() => process.exit(0), 120000).unref() //防殘留: 被測物若漏結束本行程(缺陷), 最多再活2分鐘(否則占著埠使 mocha 無法結束); 遠大於各案之時限, 不參與判定
