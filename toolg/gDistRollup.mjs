import rollupFiles from 'w-package-tools/src/rollupFiles.mjs'
import getFiles from 'w-package-tools/src/getFiles.mjs'


let fdSrc = './src'
let fdTar = './dist'


rollupFiles({
    fns: 'WScanDep.mjs',
    fdSrc,
    fdTar,
    nameDistType: 'kebabCase',
    globals: {
        'node:path': 'path',
        'node:url': 'url',
        'node:fs/promises': 'fs/promises',
        'node:child_process': 'child_process',
        'playwright': 'playwright',
        // wsemi(fsEnsureBins)打包進來後所用之 node 內建模組;import.meta.url 於輸出被換為 pathToFileURL(__filename),亦需 url
        'url': 'url',
        'fs': 'fs',
        'path': 'path',
        'crypto': 'crypto',
        'stream': 'stream',
        'stream/promises': 'stream/promises',
        'child_process': 'child_process',
        'os': 'os',
    },
    external: [
        'node:path',
        'node:url',
        'node:fs/promises',
        'node:child_process',
        'playwright',
        'url',
        'fs',
        'path',
        'crypto',
        'stream',
        'stream/promises',
        'child_process',
        'os',
    ],
})
