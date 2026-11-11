// theme=trash-guard status=oneoff date=2026-11-10
/**
 * 极端案例套件：编码矩阵 / 折行变形 / 启动形态 / 路径对抗 / 影子层压力 / 健壮性。
 *
 * 与 e2e.mjs 的分工：e2e 是"必须永远绿"的回归门禁；本文件是"把边界打穿看哪里漏"的探针，
 * 失败项会在报告里如实列出并决定是修还是登记为边界。
 *
 * 说明（规则26）：文件里出现的删除命令只是"被检测的输入样本"或惰性夹具，**一条都不执行**；
 * 需要"删除已发生"的场景一律用 rename 模拟。
 *
 * 跑法：node test/extreme.mjs
 */
import { mkdir, readFile, rename, writeFile } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join, resolve } from 'node:path'
import { pathToFileURL } from 'node:url'

const PLUGIN = pathToFileURL(resolve(import.meta.dirname, '..', 'index.js')).href
const ROOT = join(tmpdir(), 'dsh-trash-guard-tests', `ext-${new Date().toISOString().replace(/[:.]/g, '-')}`)

const results = []
const record = (ok, section, label, detail) => {
	results.push({ ok, section })
	console.log(`${ok ? 'ok  ' : 'FAIL'} [${section}] ${label}${ok || !detail ? '' : `\n      ${detail}`}`)
}

const handlers = new Map()
const registered = []
const plugin = await import(PLUGIN)
plugin.apply({
	logger: { info() {}, warn() {} },
	get: () => undefined,
	on: (event, handler) => { if (!handlers.has(event)) handlers.set(event, []); handlers.get(event).push(handler) },
	tools: { register: (definition) => { registered.push(definition); return () => {} } },
}, { workspace: ROOT, trashDir: '_trash', debug: { dir: ROOT + '/_debug' } })
const guard = handlers.get('tools/pre-execute')[0]
const trashTool = registered.find((tool) => tool.name === 'trash')
const restoreTool = registered.find((tool) => tool.name === 'restore')
const decide = (command) => guard({ name: 'pwsh', arguments: { command } }, async () => ({ kind: 'allow' }))
const write = (rel, content) => writeFile(join(ROOT, rel), content)
const deny = async (section, label, command) => {
	const decision = await decide(command)
	record(decision.kind === 'deny', section, label, `实际 ${decision.kind}`)
}
const allow = async (section, label, command) => {
	const decision = await decide(command)
	record(decision.kind === 'allow', section, label, `实际 ${decision.kind}${decision.reason ? ` — ${decision.reason.split('\n')[0]}` : ''}`)
}

await mkdir(join(ROOT, 'data'), { recursive: true })
await mkdir(join(ROOT, 'sub'), { recursive: true })
await mkdir(join(ROOT, 'dir.ps1'), { recursive: true })
const DELETE_LINE = 'Remove-Item .\\data -Recurse -Force\r\n'

// ── X1 编码矩阵 ─────────────────────────────────────────────────────────────
const u16be = (text) => {
	const body = Buffer.from(text, 'utf16le')
	body.swap16()
	return Buffer.concat([Buffer.from([0xfe, 0xff]), body])
}
await writeFile(join(ROOT, 'enc-utf16be.ps1'), u16be(DELETE_LINE))
await writeFile(join(ROOT, 'enc-utf16le-nobom.ps1'), Buffer.from(DELETE_LINE, 'utf16le'))
await writeFile(join(ROOT, 'enc-utf8.ps1'), Buffer.from(DELETE_LINE, 'utf8'))
await writeFile(join(ROOT, 'enc-utf8bom.ps1'), Buffer.concat([Buffer.from([0xef, 0xbb, 0xbf]), Buffer.from(DELETE_LINE, 'utf8')]))
await writeFile(join(ROOT, 'enc-mixed.ps1'), Buffer.concat([Buffer.from([0xc4, 0xe3, 0xba, 0xc3, 0x0d, 0x0a]), Buffer.from(DELETE_LINE, 'ascii')]))
await writeFile(join(ROOT, 'enc-nul.ps1'), Buffer.concat([Buffer.from(DELETE_LINE, 'utf8'), Buffer.from([0x00, 0x00]), Buffer.from('Write-Output ok\r\n', 'utf8')]))
await write('enc-lf.ps1', DELETE_LINE.replace(/\r\n/g, '\n'))
await deny('X1 编码', 'UTF-16BE + BOM', 'pwsh -File .\\enc-utf16be.ps1')
await deny('X1 编码', 'UTF-16LE 无 BOM（按 NUL 占比猜）', 'pwsh -File .\\enc-utf16le-nobom.ps1')
await deny('X1 编码', 'UTF-8 无 BOM', 'pwsh -File .\\enc-utf8.ps1')
await deny('X1 编码', 'UTF-8 + BOM', 'pwsh -File .\\enc-utf8bom.ps1')
await deny('X1 编码', '非 UTF-8 高位字节 + ASCII 删除', 'pwsh -File .\\enc-mixed.ps1')
await deny('X1 编码', '正文夹 NUL 字节', 'pwsh -File .\\enc-nul.ps1')
await deny('X1 编码', '纯 LF 换行', 'pwsh -File .\\enc-lf.ps1')

// ── X2 折行与结构变形 ───────────────────────────────────────────────────────
await write('fold-backtick.ps1', 'Remove-`\r\nItem .\\data -Force\r\n')
await write('fold-backtick2.ps1', 'Remove-`\n`\nItem .\\data -Force\n')
await write('fold-bat.ps1', 'Remove-Item `\r\n  .\\data -Force\r\n')
await write('heredoc.ps1', '@"\r\nRemove-Item .\\data -Force\r\n"@ | Out-String\r\n')
await write('comment.ps1', '# Remove-Item is blocked\r\nWrite-Output ok\r\n')
await write('string.ps1', 'Write-Output "Remove-Item x"\r\n')
await write('oneline.ps1', `${'#'.padEnd(3)}${'x'.repeat(200000)}; Remove-Item .\\data -Force\r\n`)
await write('manylines.ps1', `${Array.from({ length: 50000 }, (_, i) => `# line ${i}`).join('\r\n')}\r\nRemove-Item .\\data -Force\r\n`)
await deny('X2 折行', '反引号折行（CRLF）', 'pwsh -File .\\fold-backtick.ps1')
await deny('X2 折行', '连续两个反引号折行（LF）', 'pwsh -File .\\fold-backtick2.ps1')
await deny('X2 折行', '动词与参数分散两行', 'pwsh -File .\\fold-bat.ps1')
await deny('X2 折行', 'here-string 内出现删除文字', 'pwsh -File .\\heredoc.ps1')
await allow('X2 折行', '纯注释提及（不误伤）', 'pwsh -File .\\comment.ps1')
await allow('X2 折行', '字符串字面量里提及（不误伤）', 'pwsh -File .\\string.ps1')
await deny('X2 折行', '单行 200KB 后接删除', 'pwsh -File .\\oneline.ps1')
await deny('X2 折行', '5 万行脚本末尾删除', 'pwsh -File .\\manylines.ps1')

// ── X3 启动形态 ─────────────────────────────────────────────────────────────
await write('deleter.ps1', DELETE_LINE)
await write('sub/deleter.ps1', DELETE_LINE)
await write('中文脚本.ps1', DELETE_LINE)
await write('build.bat', '@echo off\r\ndel /q *.tmp\r\n')
await write('chain1.ps1', '& .\\chain2.ps1\r\n')
await write('chain2.ps1', '& .\\chain3.ps1\r\n')
await write('chain3.ps1', '& .\\deleter.ps1\r\n')
await write('loopA.ps1', '& .\\loopB.ps1\r\n')
await write('loopB.ps1', '& .\\loopA.ps1\r\n')
await deny('X3 形态', 'powershell -command "& \'x.ps1\'"', 'powershell -command "& \'deleter.ps1\'"')
await deny('X3 形态', 'Start-Process -ArgumentList @("-File","x.ps1")', "Start-Process pwsh -ArgumentList @('-File','deleter.ps1')")
await deny('X3 形态', 'cmd /c call build.bat', 'cmd /c call build.bat')
await deny('X3 形态', 'cmd.exe /c "build.bat arg"', 'cmd.exe /c "build.bat arg1"')
await deny('X3 形态', '多条命令用分号串联', 'Write-Output a; pwsh -File .\\deleter.ps1')
await deny('X3 形态', '脚本后面带参数', 'pwsh -File .\\deleter.ps1 -Verbose')
await deny('X3 形态', '子目录里的脚本', 'pwsh -File .\\sub\\deleter.ps1')
await deny('X3 形态', '中文文件名脚本', 'pwsh -File .\\中文脚本.ps1')
allow('X3 形态', '三层链（chain1→chain2→chain3→deleter）', 'pwsh -File .\\chain1.ps1')
allow('X3 形态', '循环引用不死循环', 'pwsh -File .\\loopA.ps1')
allow('X3 形态', '目录名恰好叫 dir.ps1（不是文件）', 'pwsh -File .\\dir.ps1')

// ── X4 路径对抗 ─────────────────────────────────────────────────────────────
allow('X4 路径', '越出工作区的相对路径', 'pwsh -File ..\\deleter.ps1')
allow('X4 路径', '不存在的绝对路径', 'pwsh -File C:\\nope\\deleter.ps1')
allow('X4 路径', '没有脚本扩展名', 'pwsh -File .\\deleter')
deny('X4 路径', '带空格的绝对路径', `pwsh -File "${join(ROOT, 'deleter.ps1')}"`)

// ── X7 误伤回归：路径里出现 `rd`/`del` 段（真实环境踩到过） ───────────────────
await mkdir(join(ROOT, 'rd'), { recursive: true })
await write('rd/safe.bat', '@echo off\r\necho hello\r\n')
await write('rd/evil.bat', '@echo off\r\ndel /q *.tmp\r\n')
allow('X7 误伤', '路径含 \\rd\\ 段的无害 .bat 不该被拦', `cmd /c "${join(ROOT, 'rd', 'safe.bat')}"`)
deny('X7 误伤', '同目录下的带删除 .bat 仍靠启动扫描拦住', `cmd /c "${join(ROOT, 'rd', 'evil.bat')}"`)

// ── X5 影子层压力 ───────────────────────────────────────────────────────────
await mkdir(join(ROOT, 'bulk'), { recursive: true })
await Promise.all(Array.from({ length: 300 }, (_, i) => writeFile(join(ROOT, 'bulk', `f${i}.txt`), `payload-${i}`)))
const started = Date.now()
await decide('Get-ChildItem .\\data')
const syncMs = Date.now() - started
const started2 = Date.now()
await decide('Get-ChildItem .\\data')
const syncMs2 = Date.now() - started2
record(syncMs < 15000, 'X5 压力', `300 文件首次建影耗时 ${syncMs}ms`, '超过 15s')
record(syncMs2 < 15000, 'X5 压力', `300 文件稳态重扫耗时 ${syncMs2}ms`, '超过 15s')
for (let i = 0; i < 20; i += 1) await rename(join(ROOT, 'bulk', `f${i}.txt`), join(ROOT, `escaped-${i}.txt`))
await decide('Get-ChildItem .\\data')
const manifest = (await readFile(join(ROOT, '_trash', 'manifest.jsonl'), 'utf8')).trim().split('\n').filter(Boolean).map((line) => JSON.parse(line))
const swept = manifest.filter((entry) => entry.op === 'trash' && entry.from.includes('bulk'))
record(swept.length === 20, 'X5 压力', '20 个消失文件全部收进垃圾箱', `实际 ${swept.length}`)
const restored = await restoreTool.execute({ ids: swept.map((entry) => entry.id) }, {})
record(restored.restored.length === 20, 'X5 压力', '20 条全部可 restore', `实际 ${restored.restored.length}`)

// ── X6 健壮性 / 越界 ────────────────────────────────────────────────────────
const badPaths = await trashTool.execute({ paths: 'not-an-array' }, {}).catch((error) => ({ threw: error.message }))
record(badPaths.threw === undefined, 'X6 健壮', 'paths 传字符串不崩溃', JSON.stringify(badPaths))
const escape = await trashTool.execute({ paths: ['..\\..\\Windows\\notepad.exe'] }, {})
record(escape.failed.length === 1 && escape.moved.length === 0, 'X6 健壮', '越界路径被拒', JSON.stringify(escape))
const empty = await trashTool.execute({ paths: [] }, {})
record(empty.moved.length === 0 && empty.failed.length === 0, 'X6 健壮', '空数组安全返回', JSON.stringify(empty))
const concurrent = await Promise.all(Array.from({ length: 8 }, (_, i) => trashTool.execute({ paths: ['sub'], note: `c${i}` }, {})))
record(concurrent.every((entry) => entry.moved.length + entry.failed.length === 1), 'X6 健壮', '8 个并发 trash 不互相破坏', JSON.stringify(concurrent.map((entry) => entry.moved.length)))
const lines = (await readFile(join(ROOT, '_trash', 'manifest.jsonl'), 'utf8')).trim().split('\n').filter(Boolean)
const parseable = lines.filter((line) => { try { JSON.parse(line); return true } catch { return false } })
record(parseable.length === lines.length, 'X6 健壮', '并发追加后 manifest 每行仍可解析', `${parseable.length}/${lines.length}`)

// ── 汇总 ────────────────────────────────────────────────────────────────────
const failed = results.filter((item) => !item.ok)
const bySection = new Map()
for (const item of results) {
	const bucket = bySection.get(item.section) ?? { ok: 0, total: 0 }
	bucket.total += 1
	if (item.ok) bucket.ok += 1
	bySection.set(item.section, bucket)
}
console.log('')
for (const [section, bucket] of bySection) console.log(`${bucket.ok}/${bucket.total}  ${section}`)
console.log(`\n${results.length} 项，${failed.length} 失败${failed.length === 0 ? ' — ALL PASS' : ''}`)
if (failed.length > 0) process.exitCode = 1
