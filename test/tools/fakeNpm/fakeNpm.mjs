//替身 npm(測試輔助, 不帶.test.中綴): 置於 PATH 前端, 使 shell 解析 `npm config list --json` 時啟動本檔(npm.cmd 轉呼叫), 用於模擬取得 npm 生效設定失敗之各形態
//模式由環境變數 FAKE_NPM_MODE 指定; FAKE_NPM_SECRET 為模擬之認證值(測試斷言它不得出現在錯誤訊息、log 與 fdOut):
//  exit1      離開碼 1, stderr 含認證值
//  garbage    stdout 為截斷之 JSON(含認證值)後離開碼 0
//  text       stdout 為非 JSON 文字(含認證值)
//  array      stdout 為 []
//  null       stdout 為 null
//  empty      stdout 為 {}(呼叫端無任何倉庫設定)
//  conf       stdout 為 FAKE_NPM_CONF 所給之 JSON 字串
//  hang       寫出自身 PID 至 FAKE_NPM_PIDFILE 後永不結束
//  其他       離開碼 2
const mode = process.env.FAKE_NPM_MODE || ''
const secret = process.env.FAKE_NPM_SECRET || 'FAKE-SECRET'
const out = (s) => process.stdout.write(s)

//只扮演 npm config(取呼叫端專案之倉庫設定); 其他子指令(如 install)一律立即失敗, 使被測碼誤用替身時快速紅燈, 而非卡住並遺留行程
if (process.argv[2] !== 'config') {
    process.stderr.write(`fakeNpm: only 'config' is simulated, got '${process.argv.slice(2).join(' ')}'\n`)
    process.exit(3)
}
else if (mode === 'exit1') {
    process.stderr.write(`npm error invalid config //registry.invalid/:_authToken=${secret}\n`)
    process.exit(1)
}
else if (mode === 'garbage') {
    out(`{"registry": "http://127.0.0.1:1/", "//registry.invalid/:_authToken": "${secret}`)
}
else if (mode === 'text') {
    out(`not json _authToken=${secret}\n`)
}
else if (mode === 'array') {
    out('[]')
}
else if (mode === 'null') {
    out('null')
}
else if (mode === 'empty') {
    out('{}')
}
else if (mode === 'conf') {
    out(process.env.FAKE_NPM_CONF || '{}')
}
else if (mode === 'hang') {
    const { writeFileSync } = await import('node:fs')
    if (process.env.FAKE_NPM_PIDFILE) writeFileSync(process.env.FAKE_NPM_PIDFILE, String(process.pid))
    setInterval(() => {}, 1000)
}
else {
    process.exit(2)
}
