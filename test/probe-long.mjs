// theme=trash-guard status=oneoff date=2026-11-10
// 探针：长脚本 / 编码 / 折行 能否被启动扫描拦住（只跑判定，不执行任何删除）
import { mkdir, writeFile } from 'node:fs/promises'
import { join, resolve } from 'node:path'
import { pathToFileURL } from 'node:url'

const PLUGIN = pathToFileURL(resolve(import.meta.dirname, '..', 'index.js')).href
const ROOT = join(tmpdir(), 'dsh-trash-guard-tests', `probe-${Date.now()}`)
await mkdir(join(ROOT, 'data'), { recursive: true })

const handlers = new Map()
const plugin = await import(PLUGIN)
plugin.apply({ logger: { info() {}, warn() {} }, get: () => undefined,
  on: (e, h) => { if (!handlers.has(e)) handlers.set(e, []); handlers.get(e).push(h) },
  tools: { register: () => () => {} } }, { workspace: ROOT, trashDir: '_trash', debug: { dir: ROOT + '/_debug' } })
const guard = handlers.get('tools/pre-execute')[0]
const decide = (command) => guard({ name: 'pwsh', arguments: { command } }, async () => ({ kind: 'allow' }))

const pad = (n, line) => Array.from({ length: n }, (_, i) => line(i)).join('\r\n') + '\r\n'
const filler = (n) => pad(n, (i) => `# harmless line ${i} ${'x'.repeat(40)}`)

const cases = []
// a) 300KB 注释填充 + 末尾删除
await writeFile(join(ROOT, 'long.ps1'), filler(6000) + 'Remove-Item .\\data -Recurse -Force\r\n', 'utf8')
cases.push(['300KB 脚本，删除在最后一行', 'pwsh -File .\\long.ps1'])
// a2) 删除埋在中间
await writeFile(join(ROOT, 'middle.ps1'), filler(3000) + 'Remove-Item .\\data -Recurse -Force\r\n' + filler(3000), 'utf8')
cases.push(['300KB 脚本，删除埋在中段', 'pwsh -File .\\middle.ps1'])
// b) 600KB > 512KB 上限
await writeFile(join(ROOT, 'huge.ps1'), filler(12000) + 'Remove-Item .\\data -Recurse -Force\r\n', 'utf8')
cases.push(['600KB 脚本（超过 512KB 上限）', 'pwsh -File .\\huge.ps1'])
// c) UTF-16LE BOM
await writeFile(join(ROOT, 'utf16.ps1'), Buffer.concat([Buffer.from([0xff, 0xfe]), Buffer.from('Remove-Item .\\data -Recurse -Force\r\n', 'utf16le')]))
cases.push(['UTF-16LE + BOM 的 .ps1', 'pwsh -File .\\utf16.ps1'])
// d) UTF-8 BOM
await writeFile(join(ROOT, 'utf8bom.ps1'), Buffer.concat([Buffer.from([0xef, 0xbb, 0xbf]), Buffer.from('Remove-Item .\\data -Force\r\n', 'utf8')]))
cases.push(['UTF-8 BOM 的 .ps1', 'pwsh -File .\\utf8bom.ps1'])
// e) 反引号折行拆开动词
await writeFile(join(ROOT, 'backtick.ps1'), 'Remove-`\r\nItem .\\data -Force\r\n', 'utf8')
cases.push(['反引号折行拆开 Remove-Item', 'pwsh -File .\\backtick.ps1'])
// f) 函数定义在前、调用在后
await writeFile(join(ROOT, 'func.ps1'), 'function Cleanup { Remove-Item .\\data -Recurse -Force }\r\nCleanup\r\n', 'utf8')
cases.push(['删除写在函数里、末尾调用', 'pwsh -File .\\func.ps1'])
// g) 超长内联命令（100KB）
cases.push(['100KB 内联命令，末尾跟 Remove-Item', `Get-ChildItem . | Out-Null; ${'#' + 'y'.repeat(60)}; Remove-Item .\\data -Force`])

for (const [label, command] of cases) {
  const decision = await decide(command)
  console.log(`${decision.kind === 'deny' ? 'deny ' : 'ALLOW'}  ${label}`)
}
console.log(`\nROOT=${ROOT}`)
