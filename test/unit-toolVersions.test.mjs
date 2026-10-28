import fs from 'fs'
import path from 'path'
import assert from 'assert'
import { readToolVersions } from '../src/toolVersions.mjs'
import { TOOLS } from '../src/config.mjs'


//result.json 與報告記錄之工具版本: 由 ensureBins 回傳之快取路徑(<快取>/<sha256>/<檔名>)推得。
//以「清單項之 sha256(壓縮檔者為解出之檔)等於路徑上的 sha256」認定實際所用之檔, 版本標籤取自其廠商網址;
//清單來源為本次取得之主幹清單副本(<快取>/manifest-last.json)與套件內基準清單(bin/manifest.json)
describe(`readToolVersions`, function() {
    let fdt = path.resolve('./test/_tmp/toolVersions')
    let base = null
    let shaOf = (f) => (f.extract ? f.extract.sha256 : f.sha256)
    let tagOf = (f) => /\/releases\/download\/([^/]+)\//.exec(f.url)[1]
    let pathsOf = (cache, m) => Object.fromEntries(m.files.map((f) => [f.name, path.join(cache, shaOf(f), f.name)]))

    beforeEach(function() {
        fs.rmSync(fdt, { recursive: true, force: true })
        fs.mkdirSync(fdt, { recursive: true })
        base = JSON.parse(fs.readFileSync('bin/manifest.json', 'utf8'))
    })

    after(function() {
        fs.rmSync(fdt, { recursive: true, force: true, maxRetries: 5, retryDelay: 200 })
    })

    it(`should give the tag of the baseline manifest entry whose hash is the file in use`, async function() {
        let r = await readToolVersions(pathsOf(path.join(fdt, 'cache'), base))
        assert.strict.deepStrictEqual(Object.keys(r), TOOLS.map((t) => t.key))
        for (let t of TOOLS) {
            let f = base.files.find((v) => v.name === t.exeName)
            assert.strict.equal(r[t.key].version, tagOf(f), t.key)
            assert.strict.equal(r[t.key].exePath, path.join(fdt, 'cache', shaOf(f), t.exeName), t.key)
            assert.strict.equal(r[t.key].key, t.key)
        }
    })

    it(`should prefer the trunk manifest copy beside the cache, for a file newer than the baseline`, async function() {
        let cache = path.join(fdt, 'cache')
        let trunk = JSON.parse(JSON.stringify(base))
        let f = trunk.files.find((v) => v.name === 'syft.exe')
        f.url = f.url.replace(/\/v[^/]+\//, '/v99.0.1/')
        f.extract.sha256 = 'e'.repeat(64) //較基準清單新之檔
        fs.mkdirSync(cache, { recursive: true })
        fs.writeFileSync(path.join(cache, 'manifest-last.json'), JSON.stringify(trunk))
        let r = await readToolVersions(pathsOf(cache, trunk))
        assert.strict.equal(r.syft.version, 'v99.0.1')
        for (let t of TOOLS.filter((v) => v.key !== 'syft')) {
            let g = base.files.find((v) => v.name === t.exeName)
            assert.strict.equal(r[t.key].version, tagOf(g), t.key) //其餘與基準清單相同
        }
    })

    it(`should say unknown for a file that no manifest lists by hash, and ignore an entry that only shares the name or the url`, async function() {
        let cache = path.join(fdt, 'cache')
        let trunk = JSON.parse(JSON.stringify(base))
        trunk.files.find((v) => v.name === 'grype.exe').url = 'https://github.com/anchore/grype/releases/download/v77.0.0/x.zip' //同名但sha256不是所用之檔
        fs.mkdirSync(cache, { recursive: true })
        fs.writeFileSync(path.join(cache, 'manifest-last.json'), JSON.stringify(trunk))
        let paths = pathsOf(cache, base)
        paths['grype.exe'] = path.join(cache, 'f'.repeat(64), 'grype.exe')
        let r = await readToolVersions(paths)
        assert.strict.equal(r.grype.version, 'unknown')
        assert.strict.equal(r.syft.version, tagOf(base.files[0]))
    })

    it(`should not fail on a broken or non-manifest copy, falling back to the baseline`, async function() {
        let cache = path.join(fdt, 'cache')
        fs.mkdirSync(cache, { recursive: true })
        for (let text of ['<html>', '{}', '{"files":"x"}', '{"files":[null,1,{"name":"syft.exe"}]}']) {
            fs.writeFileSync(path.join(cache, 'manifest-last.json'), text)
            let r = await readToolVersions(pathsOf(cache, base))
            assert.strict.equal(r['ex-sbom'].version, tagOf(base.files[3]), text)
        }
    })

})
