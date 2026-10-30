//掃描範圍(只算 dependencies)之測試夾具: 假 registry 之套件與掃描目標之 package.json
//
//  scope-prj
//    dependencies:    prod-mid -> semver@7.0.0           (正式相依樹, semver 為傳遞相依)
//                     prod-ui  -> peer: peer-fw@^1.0.0, peer-only@^1.0.0   (正式套件之對等相依)
//    devDependencies: dev-tool -> semver@7.0.0, dev-only-sub@1.0.0   (開發工具: semver 同時在正式樹, dev-only-sub 只在開發樹)
//                     peer-fw@1.0.0                      (同時為 prod-ui 之對等相依: 如 vue 同為 devDependencies 與正式套件之對等相依)
//
//  應裝: prod-mid、prod-ui、semver、peer-fw(1.0.0, 即 devDependencies 所釘之版本)、peer-only(只是正式套件之對等相依, 未列於 devDependencies)
//  不應裝: dev-tool、dev-only-sub
export const scopePackages = {
    'semver': { '7.0.0': {} },
    'prod-mid': { '1.0.0': { dependencies: { semver: '7.0.0' } } },
    'prod-ui': { '1.0.0': { peerDependencies: { 'peer-fw': '^1.0.0', 'peer-only': '^1.0.0' } } },
    'peer-fw': { '1.0.0': {}, '1.1.0': {} },
    'peer-only': { '1.0.0': {} },
    'dev-tool': { '1.0.0': { dependencies: { 'semver': '7.0.0', 'dev-only-sub': '1.0.0' } } },
    'dev-only-sub': { '1.0.0': {} },
}

export const scopeProject = {
    name: 'scope-prj',
    version: '1.0.0',
    dependencies: { 'prod-mid': '1.0.0', 'prod-ui': '1.0.0' },
    devDependencies: { 'dev-tool': '1.0.0', 'peer-fw': '1.0.0' },
}

export const scopeInstalled = ['peer-fw', 'peer-only', 'prod-mid', 'prod-ui', 'semver']
export const scopeNotInstalled = ['dev-tool', 'dev-only-sub']
