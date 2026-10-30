//接受TCP連線但永不回應之本機服務, 扮演無回應之npm registry(npm_config_registry指向url)
//記錄已接受之連線數, 並可等待所有連線被對方關閉(對方行程結束時由作業系統關閉其socket)
import net from 'net'


export async function hangRegistry(port) {
    let accepted = 0
    let socks = new Set()
    let waiters = []
    let srv = net.createServer((s) => {
        accepted++
        socks.add(s)
        s.on('error', () => {})
        s.on('close', () => {
            socks.delete(s)
            if (socks.size === 0) waiters.splice(0).forEach((f) => f())
        })
    })
    await new Promise((resolve, reject) => {
        srv.once('error', reject)
        srv.listen(port, '127.0.0.1', resolve)
    })
    return {
        url: `http://127.0.0.1:${port}/`,
        accepted: () => accepted,
        open: () => socks.size,
        //等所有已接受之連線關閉, ms僅為防懸置之上限
        allClosed: (ms) => new Promise((resolve) => {
            if (socks.size === 0) return resolve(true)
            let t = setTimeout(() => resolve(false), ms)
            waiters.push(() => {
                clearTimeout(t)
                resolve(true)
            })
        }),
        close: async () => {
            for (let s of socks) s.destroy()
            await new Promise((resolve) => srv.close(resolve))
        },
    }
}
