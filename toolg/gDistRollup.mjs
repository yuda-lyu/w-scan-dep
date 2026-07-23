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
    },
    external: [
        'node:path',
        'node:url',
        'node:fs/promises',
        'node:child_process',
        'playwright',
    ],
})
