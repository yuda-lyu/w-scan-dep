//portListeners、ownsPort 之測試共用: 與 child_process.spawnSync 同形之注入執行函數(wsemi execProcessPortPidsSync 之 opt.exec)與固定輸出之夾具。
//固定輸出之格式依 wsemi 1.9.32 之 execProcessPortPidsSync(netstat -ano 之表列; PowerShell 腳本以 WSEMI-PORTPIDS-BEGIN/END 夾住, 每列 `R <本地埠> <遠端位址> <遠端埠> <PID>`),
//範本見 wsemi 之 test/tools/portPidsKit.mjs; 該格式為 wsemi 內部約定, wsemi 改版而不合時此處之單元案會明確失敗(不會靜默通過)
import assert from 'assert'


//row, 組 netstat -ano 之一列(欄寬同 Windows); state 為 null 時不輸出狀態欄(狀態值錯誤時之缺欄形)
export function row(proto, local, remote, state, pid) {
    return `  ${proto.padEnd(7)}${local.padEnd(23)}${remote.padEnd(23)}${state === null ? '' : state.padEnd(16)}${pid}`
}

//BG, 他埠之背景列, 使輸出形同真實
export const BG = [
    row('TCP', '0.0.0.0:135', '0.0.0.0:0', 'LISTENING', '1356'),
    row('TCP', '192.168.1.10:51234', '140.82.112.3:443', 'ESTABLISHED', '7000'),
    row('TCP', '[::]:135', '[::]:0', 'LISTENING', '1356'),
    row('UDP', '0.0.0.0:5353', '*:*', null, '3100'),
]

//ns, 組 netstat -ano 之輸出(含背景列)
export function ns(rows = []) {
    return ['', 'Active Connections', '', '  Proto  Local Address          Foreign Address        State           PID', ...BG, ...rows].join('\r\n') + '\r\n'
}

//ps, 組 PowerShell 腳本之輸出; rows 為 [本地埠, 遠端位址, 遠端埠, PID]
export function ps(rows = []) {
    return ['WSEMI-PORTPIDS-BEGIN', ...rows.map((r) => `R ${r.join(' ')}`), 'WSEMI-PORTPIDS-END'].join('\r\n') + '\r\n'
}

//ok, err, 與 spawnSync 同形之結果
export function ok(stdout, status = 0) {
    return { status, stdout, error: null }
}
export function err(code) {
    let e = new Error(`spawn x ${code}`)
    e.code = code
    return { status: null, stdout: '', error: e }
}

//fakeExec, 注入之同步執行函數(spawnSync 形): outs 為 { netstat, powershell } 之結果, calls 記錄各次呼叫之資料來源(src)
export function fakeExec(outs, calls = []) {
    return (prog, args, o) => {
        calls.push(o.src)
        let r = outs[o.src]
        assert.strict.ok(r !== undefined, `unexpected src ${o.src}`)
        return r
    }
}
