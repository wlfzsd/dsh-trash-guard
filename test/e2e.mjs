// theme=trash-guard status=active date=2026-11-10
/**
 * e2e 判定矩阵：用**真实文件**当夹具，逐条跑插件的 tools/pre-execute 钩子。
 *
 * 说明（与规则26 的关系）：本文件里出现的删除命令只作为"被检测的输入样本"，
 * 或写进 `测试临时\_sandbox\` 下的惰性夹具文件供扫描器读取 —— **一条都不会被执行**。
 * 需要验证"删除已发生"的场景，用 `rename()` 把文件移走模拟（等价效果、零删除调用）。
 *
 * 跑法：node test/e2e.mjs
 */
import { execFileSync } from 'node:child_process'
import { existsSync } from 'node:fs'
import { mkdir, readFile, rename, writeFile } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join, resolve } from 'node:path'
import { pathToFileURL } from 'node:url'

const PLUGIN = pathToFileURL(resolve(import.meta.dirname, '..', 'index.js')).href
const RUN = `e2e-${new Date().toISOString().replace(/[:.]/g, '-')}`
const ROOT = join(tmpdir(), 'dsh-trash-guard-tests', RUN)

const results = []
function record(status, section, label, detail) {
	results.push({ status, section, label, detail })
	if (status !== 'ok') console.log(`${status} ${section} :: ${label}${detail ? `\n    ${detail}` : ''}`)
}

// ── 挂载插件（mock ctx，走真实的 apply/hook 代码） ──────────────────────────
const handlers = new Map()
const registered = []
const plugin = await import(PLUGIN)
plugin.apply({
	logger: { info() {}, warn() {} },
	get: () => undefined,
	on(event, handler) {
		if (!handlers.has(event)) handlers.set(event, [])
		handlers.get(event).push(handler)
	},
	tools: { register: (definition) => { registered.push(definition); return () => {} } },
}, { workspace: ROOT, trashDir: '_trash', debug: { dir: ROOT + '/_debug' } })

const guard = handlers.get('tools/pre-execute')[0]
const trashTool = registered.find((tool) => tool.name === 'trash')
const restoreTool = registered.find((tool) => tool.name === 'restore')

/** 模拟 DSH 的一次 tool 派发：先过策略，deny 就不进正文。 */
async function dispatch(name, args) {
	const decision = await guard({ name, arguments: args }, async () => ({ kind: 'allow' }))
	return decision
}

async function expectDecision(section, label, name, args, want) {
	const decision = await dispatch(name, args)
	const got = decision.kind
	if (got === want) record('ok', section, label)
	else record('FAIL', section, label, `期望 ${want}，实际 ${got}${decision.reason ? `\n    reason: ${decision.reason.split('\n')[0]}` : ''}`)
	if (want === 'deny' && decision.kind === 'deny') {
		const good = /trash\(/.test(decision.reason) && /manifest\.jsonl/.test(decision.reason)
		record(good ? 'ok' : 'FAIL', section, `${label} — 拒绝文案给出 trash 出路`, good ? '' : decision.reason)
	}
	return decision
}

const write = (rel, content) => writeFile(join(ROOT, rel), content, 'utf8')

// ── 夹具（惰性文本，绝不执行） ─────────────────────────────────────────────
await mkdir(join(ROOT, 'data'), { recursive: true })
await mkdir(join(ROOT, 'my scripts'), { recursive: true })
await write('data/a.txt', 'alpha')
await write('data/b.txt', 'beta')
await write('sentinel.txt', 'must survive')

await write('deleter.ps1', 'Get-ChildItem .\\data -Recurse | Remove-Item -Force -Recurse\nWrite-Output done\n')
await write('dotnet.ps1', "$p = 'data/a.txt'\n[System.IO.File]::Delete($p)\n")
await write('nested.ps1', '& "$PSScriptRoot\\deleter.ps1"\n')
await write('nested-rel.ps1', '& .\\deleter.ps1\n')
await write('harmless.ps1', "Write-Output 'hello-from-script'\n")
await write('obfuscated.ps1', "& ([scriptblock]::Create('Remove-' + 'Item .\\data -Recurse -Force'))\n")
await write('my scripts/deleter.ps1', 'Remove-Item .\\x -Force\n')
await write('build.bat', '@echo off\r\ndel /q *.tmp\r\necho done\r\n')
await write('cond.bat', '@echo off\r\nif exist data\\a.txt del data\\a.txt\r\n')
await write('loop.bat', '@echo off\r\nfor /d %%i in (*) do rd /s /q "%%i"\r\n')
await write('safe.bat', '@echo off\r\necho del is not a command here\r\nrem del this too\r\nset DELME=1\r\n')
await write('maker.cmd', '@echo off\r\nrmdir /s /q build\r\n')
await write('cond2.bat', '@echo off\r\nif exist data\\a.txt (del data\\a.txt)\r\n')
await write('loop2.bat', '@echo off\r\nfor %%f in (*.log) do del "%%f"\r\n')
await write('pushd.bat', '@echo off\r\npushd .. & rd /s /q old & popd\r\n')
await write('child.bat', '@echo off\r\ndel /q stale.txt\r\n')
await write('parent.bat', '@echo off\r\ncall child.bat\r\n')
await mkdir(join(ROOT, 'scripts'), { recursive: true })
await write('scripts/build.bat', '@echo off\r\ndel /q out\\*.tmp\r\n')

// ── A. 命令层（PowerShell / cmd 直写） ──────────────────────────────────────
const COMMAND_DENY = [
	['Remove-Item .\\data\\a.txt', 'Remove-Item 基本形态'],
	['Remove-Item -Recurse -Force .\\data', 'Remove-Item 递归强删'],
	['ri .\\data\\a.txt', 'ri 别名'],
	['rm .\\data\\b.txt', 'rm 别名'],
	['del .\\data\\a.txt', 'del 别名'],
	['erase .\\data\\a.txt', 'erase 别名'],
	['rd /s /q .\\data', 'rd 目录树'],
	['rmdir /s /q .\\data', 'rmdir 目录树'],
	['Clear-Content .\\sentinel.txt', 'Clear-Content 清空'],
	['Set-Content .\\sentinel.txt -Value ""', 'Set-Content 置空'],
	['[System.IO.File]::Delete("data\\a.txt")', '.NET File.Delete'],
	['[System.IO.Directory]::Delete("data", $true)', '.NET Directory.Delete 递归'],
	['(Get-Item .\\data\\a.txt).Delete()', 'FileInfo.Delete 方法'],
	['Get-ChildItem .\\data -Recurse | Remove-Item -Force', '管道批量删'],
	['gci -Recurse | ri -Force', 'gci|ri 缩写'],
	['git clean -xdf', 'git clean'],
	['git reset --hard', 'git reset --hard'],
	['robocopy .\\empty .\\data /MIR', 'robocopy /MIR'],
	['cmd /c del data\\a.txt', 'cmd /c 包裹 del'],
	['cmd /c rd /s /q data', 'cmd /c 包裹 rd'],
	['powershell -EncodedCommand ZQBjAGgAbwA=', '-EncodedCommand 不可审计'],
	['vssadmin delete shadows /all /quiet', 'vssadmin 删卷影'],
	['Move-Item .\\data\\a.txt .\\data\\b.txt -Force', 'Move-Item -Force 覆盖'],
	['remove-item .\\data\\a.txt -Force', '大小写混写'],
	['foreach ($f in @("a","b")) { Remove-Item $f -Force }', 'foreach 块内删除'],
	['"data\\a.txt" | Remove-Item', '管道左侧传参'],
	['$files = Get-ChildItem .\\data; $files | Remove-Item -Force', '分号后管道删除'],
	['Invoke-Command -ScriptBlock { Remove-Item .\\data\\a.txt }', 'ScriptBlock 内删除'],
	['forfiles /p . /m *.tmp /c "cmd /c del @path"', 'forfiles 里套 cmd /c del'],
	['Remove-Item .\\data\\a.txt -ErrorAction SilentlyContinue', '带 ErrorAction 的删除'],
]
for (const [command, label] of COMMAND_DENY) {
	await expectDecision('A 命令层', label, 'pwsh', { command }, 'deny')
}

const COMMAND_ALLOW = [
	['Get-ChildItem .\\data', '普通列目录'],
	['Get-Content .\\data\\a.txt', '读文件'],
	['npm run build', '构建命令'],
	['Write-Output "del data\\a.txt"', '字符串里出现 del（不该误伤）'],
	["Select-String -Pattern 'Remove-Item' -Path .\\deleter.ps1", '搜索删除字样（不该误伤）'],
	['Copy-Item .\\data\\a.txt .\\data\\c.txt', '复制'],
]
for (const [command, label] of COMMAND_ALLOW) {
	await expectDecision('A 命令层', label, 'pwsh', { command }, 'allow')
}

// ── B. .ps1：写入侧 ─────────────────────────────────────────────────────────
await expectDecision('B 写入侧', 'write 出带 Remove-Item 的 .ps1', 'write', { file_path: 'x.ps1', content: 'Remove-Item .\\a -Force\n' }, 'deny')
await expectDecision('B 写入侧', 'write 出 .NET 删除的 .ps1', 'write', { file_path: 'x.ps1', content: '[IO.File]::Delete($p)\n' }, 'deny')
await expectDecision('B 写入侧', 'write 出无害 .ps1', 'write', { file_path: 'x.ps1', content: 'Write-Output 1\n' }, 'allow')
await expectDecision('B 写入侧', 'write 出 .md（不是脚本）', 'write', { file_path: 'doc.md', content: 'Remove-Item .\\a\n' }, 'allow')

// ── C. .ps1：启动侧（真实文件，正文扫描） ───────────────────────────────────
await expectDecision('C 启动侧', 'pwsh -File 指向带删除的 .ps1', 'pwsh', { command: 'pwsh -NoProfile -File .\\deleter.ps1' }, 'deny')
await expectDecision('C 启动侧', 'powershell -File 同上', 'pwsh', { command: 'powershell -ExecutionPolicy Bypass -File .\\deleter.ps1' }, 'deny')
await expectDecision('C 启动侧', '& .\\deleter.ps1 调用符', 'pwsh', { command: '& .\\deleter.ps1' }, 'deny')
await expectDecision('C 启动侧', '.NET 删除的 .ps1', 'pwsh', { command: 'pwsh -File .\\dotnet.ps1' }, 'deny')
await expectDecision('C 启动侧', '嵌套调用 $PSScriptRoot 的 .ps1', 'pwsh', { command: 'pwsh -File .\\nested.ps1' }, 'deny')
await expectDecision('C 启动侧', '嵌套调用 .\\ 相对路径的 .ps1', 'pwsh', { command: 'pwsh -File .\\nested-rel.ps1' }, 'deny')
await expectDecision('C 启动侧', '带空格的脚本路径', 'pwsh', { command: 'pwsh -File ".\\my scripts\\deleter.ps1"' }, 'deny')
await expectDecision('C 启动侧', '无害 .ps1（不误伤）', 'pwsh', { command: 'pwsh -File .\\harmless.ps1' }, 'allow')
await expectDecision('C 启动侧', '不存在的脚本（无从扫描）', 'pwsh', { command: 'pwsh -File .\\nope.ps1' }, 'allow')

// ── D. .bat / .cmd ─────────────────────────────────────────────────────────
await expectDecision('D 批处理', 'cmd /c build.bat（行首 del）', 'pwsh', { command: 'cmd /c build.bat' }, 'deny')
await expectDecision('D 批处理', 'cmd /c "cond.bat"（if exist ... del）', 'pwsh', { command: 'cmd /c "cond.bat"' }, 'deny')
await expectDecision('D 批处理', 'cmd /c loop.bat（for ... do rd）', 'pwsh', { command: 'cmd /c loop.bat' }, 'deny')
await expectDecision('D 批处理', 'cmd /c maker.cmd（rmdir）', 'pwsh', { command: 'cmd /c maker.cmd' }, 'deny')
await expectDecision('D 批处理', 'cmd /c safe.bat（只 echo/rem 提及）', 'pwsh', { command: 'cmd /c safe.bat' }, 'allow')
await expectDecision('D 批处理', 'write 出带 del 的 .bat', 'write', { file_path: 'y.bat', content: '@echo off\r\ndel *.log\r\n' }, 'deny')
await expectDecision('D 批处理', 'write 出 if exist ... del 的 .bat', 'write', { file_path: 'y.bat', content: '@echo off\r\nif exist a.txt del a.txt\r\n' }, 'deny')
await expectDecision('D 批处理', 'write 出 echo del 的 .bat（不误伤）', 'write', { file_path: 'y.bat', content: '@echo off\r\necho del a.txt\r\n' }, 'allow')
await expectDecision('D 批处理', 'cmd /c cond2.bat（if exist (...) 括号内 del）', 'pwsh', { command: 'cmd /c cond2.bat' }, 'deny')
await expectDecision('D 批处理', 'cmd /c loop2.bat（for %%f do del）', 'pwsh', { command: 'cmd /c loop2.bat' }, 'deny')
await expectDecision('D 批处理', 'cmd /c pushd.bat（& 串联 rd）', 'pwsh', { command: 'cmd /c pushd.bat' }, 'deny')
await expectDecision('D 批处理', 'cmd /c parent.bat（call 子批处理里的 del）', 'pwsh', { command: 'cmd /c parent.bat' }, 'deny')
await expectDecision('D 批处理', '子目录里的 scripts\\build.bat', 'pwsh', { command: '.\\scripts\\build.bat' }, 'deny')
await expectDecision('D 批处理', '.\\build.bat 直接当程序执行', 'pwsh', { command: '.\\build.bat' }, 'deny')
await expectDecision('D 批处理', 'start 启动 .bat', 'pwsh', { command: 'start .\\build.bat' }, 'deny')
await expectDecision('C 启动侧', 'Start-Process -ArgumentList "-File x.ps1"', 'pwsh', { command: 'Start-Process powershell -ArgumentList "-File .\\deleter.ps1"' }, 'deny')
await expectDecision('C 启动侧', '& "带引号的脚本路径"', 'pwsh', { command: '& ".\\deleter.ps1"' }, 'deny')
await expectDecision('C 启动侧', 'Get-Content 只是读脚本（不误伤）', 'pwsh', { command: 'Get-Content .\\deleter.ps1' }, 'allow')

// ── E. 已知逃逸（如实记录，靠影子层兜底） ───────────────────────────────────
await expectDecision('E 逃逸', '字符串拼接动态生成删除（文本层看不见）', 'pwsh', { command: "& ([scriptblock]::Create('Remove-' + 'Item .\\data -Recurse -Force'))" }, 'allow')
await expectDecision('E 逃逸', '运行期生成的 .ps1 被启动（正文是拼接的）', 'pwsh', { command: 'pwsh -File .\\obfuscated.ps1' }, 'allow')
await expectDecision('E 逃逸', '命令名存在变量里再调用（$cmd=...）', 'pwsh', { command: "$cmd = 'Remove-' + 'Item'; & $cmd .\\data\\a.txt" }, 'allow')

// ── H. 长脚本 / 编码 / 折行（实测暴露过的三类漏判，固化成回归） ────────────────
const filler = (lines, tag) => `${Array.from({ length: lines }, (_, i) => `# ${tag} ${i} ${'x'.repeat(40)}`).join('\r\n')}\r\n`
await write('long-tail.ps1', `${filler(6000, 'pad')}Remove-Item .\\data -Recurse -Force\r\n`)
await write('long-middle.ps1', `${filler(3000, 'pad')}Remove-Item .\\data -Recurse -Force\r\n${filler(3000, 'pad')}`)
await write('huge.ps1', `${filler(12000, 'pad')}Remove-Item .\\data -Recurse -Force\r\n`)   // ≈800KB，超过旧 512KB 上限
await writeFile(join(ROOT, 'utf16.ps1'), Buffer.concat([Buffer.from([0xff, 0xfe]), Buffer.from('Remove-Item .\\data -Force\r\n', 'utf16le')]))
await writeFile(join(ROOT, 'utf8bom.ps1'), Buffer.concat([Buffer.from([0xef, 0xbb, 0xbf]), Buffer.from('Remove-Item .\\data -Force\r\n', 'utf8')]))
await write('backtick.ps1', 'Remove-`\r\nItem .\\data -Force\r\n')
await write('infunc.ps1', 'function Cleanup { Remove-Item .\\data -Recurse -Force }\r\nCleanup\r\n')

await expectDecision('H 长脚本', '≈300KB 脚本，删除在最后一行', 'pwsh', { command: 'pwsh -File .\\long-tail.ps1' }, 'deny')
await expectDecision('H 长脚本', '≈300KB 脚本，删除埋在中段', 'pwsh', { command: 'pwsh -File .\\long-middle.ps1' }, 'deny')
await expectDecision('H 长脚本', '≈800KB 脚本（旧 512KB 上限已失效）', 'pwsh', { command: 'pwsh -File .\\huge.ps1' }, 'deny')
await expectDecision('H 长脚本', 'UTF-16LE + BOM 的 .ps1（PS 5.1 `>` 默认编码）', 'pwsh', { command: 'pwsh -File .\\utf16.ps1' }, 'deny')
await expectDecision('H 长脚本', 'UTF-8 BOM 的 .ps1', 'pwsh', { command: 'pwsh -File .\\utf8bom.ps1' }, 'deny')
await expectDecision('H 长脚本', '反引号折行把 Remove-Item 劈成两半', 'pwsh', { command: 'pwsh -File .\\backtick.ps1' }, 'deny')
await expectDecision('H 长脚本', '删除写在函数里、末尾才调用', 'pwsh', { command: 'pwsh -File .\\infunc.ps1' }, 'deny')
await expectDecision('H 长脚本', '≈60KB 内联命令里夹删除', 'pwsh', { command: `Get-ChildItem . | Out-Null; ${'y'.repeat(60000)}; Remove-Item .\\data -Force` }, 'deny')

// ── F. 影子层：逃逸之后的兜底 ───────────────────────────────────────────────
await mkdir(join(ROOT, 'shadow'), { recursive: true })
await write('shadow/victim.txt', 'bytes-to-recover')
// 任意一次改动型调用 → 建影
await dispatch('pwsh', { command: 'Get-ChildItem .\\data' })
record(existsSync(join(ROOT, '_trash', '.shadow', 'shadow', 'victim.txt')) ? 'ok' : 'FAIL', 'F 影子层', '建影成功')
// 用"移走"模拟删除（rename，等价效果、零删除调用）
await rename(join(ROOT, 'shadow', 'victim.txt'), join(ROOT, 'escaped.txt'))
await dispatch('pwsh', { command: 'Get-ChildItem .\\data' })
const manifest = (await readFile(join(ROOT, '_trash', 'manifest.jsonl'), 'utf8')).trim().split('\n').filter(Boolean).map((line) => JSON.parse(line))
const swept = manifest.find((record2) => record2.op === 'trash' && record2.from.includes('victim.txt'))
record(swept ? 'ok' : 'FAIL', 'F 影子层', '删除被回收进垃圾箱', swept ? '' : JSON.stringify(manifest))
if (swept) {
	const content = await readFile(swept.to, 'utf8')
	record(content === 'bytes-to-recover' ? 'ok' : 'FAIL', 'F 影子层', '回收内容完好', content)
	const restored = await restoreTool.execute({ ids: [swept.id] }, {})
	record(restored.restored.length === 1 ? 'ok' : 'FAIL', 'F 影子层', '可 restore 复位')
}

// ── G. 真实执行：允许的脚本能正常跑（证明不误伤、不空拦） ───────────────────
try {
	const stdout = execFileSync('powershell.exe', ['-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', join(ROOT, 'harmless.ps1')], { encoding: 'utf8' })
	record(stdout.includes('hello-from-script') ? 'ok' : 'FAIL', 'G 真实执行', '无害 .ps1 仍可正常执行', stdout.trim())
} catch (error) {
	record('FAIL', 'G 真实执行', '无害 .ps1 执行失败', error.message)
}

// ── 汇总 ────────────────────────────────────────────────────────────────────
const bySection = new Map()
for (const item of results) {
	const bucket = bySection.get(item.section) ?? { ok: 0, total: 0 }
	bucket.total += 1
	if (item.status === 'ok') bucket.ok += 1
	bySection.set(item.section, bucket)
}
console.log('')
for (const [section, bucket] of bySection) console.log(`${bucket.ok}/${bucket.total}  ${section}`)
const failed = results.filter((item) => item.status !== 'ok').length
console.log(`\n${results.length} 项断言，${failed} 失败 ${failed === 0 ? '— ALL PASS' : ''}`)
if (failed > 0) process.exitCode = 1
