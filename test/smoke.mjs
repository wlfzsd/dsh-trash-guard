// theme=trash-guard status=active date=2026-11-10
/**
 * 冒烟验证（不加载进 dsh、不碰用户 profile）：
 *  1. 插件能被 import + apply(mockCtx) 正常挂载；
 *  2. 注册的两个工具定义能通过 dsh-tools 的真实 schema 校验；
 *  3. tools/pre-execute 判定表：命中/未命中样本逐条对拍；
 *  4. trash/restore 真实往返（rename，不删除）；
 *  5. 影子层：硬链接建影 → 文件被移走(=删除) → 下一轮 sweep 自动收进垃圾箱 → 可 restore。
 *
 * 跑法：node test/smoke.mjs
 * 每次跑用一个新目录 .tmp-smoke/run-<时间戳>，旧目录留在原地不清理（本机零删除约定）。
 */
import { mkdir, readFile, rename, stat, writeFile } from 'node:fs/promises'
import { existsSync } from 'node:fs'
import { homedir, tmpdir } from 'node:os'
import { join, resolve } from 'node:path'
import { pathToFileURL } from 'node:url'

const DSH_TOOLS = pathToFileURL(
	join(process.env.APPDATA ?? join(homedir(), 'AppData', 'Roaming'), 'npm', 'node_modules', '@deepseek-ai', 'dsh', 'node_modules', '@deepseek-ai', 'dsh-tools', 'lib', 'index.js'),
).href
const PLUGIN = pathToFileURL(resolve(import.meta.dirname, '..', 'index.js')).href
const RUN = `run-${new Date().toISOString().replace(/[:.]/g, '-')}`
const ROOT = join(tmpdir(), 'dsh-trash-guard-tests', RUN)

const failures = []
function check(label, actual, expected) {
	const pass = JSON.stringify(actual) === JSON.stringify(expected)
	if (!pass) failures.push(`${label}\n    期望: ${JSON.stringify(expected)}\n    实际: ${JSON.stringify(actual)}`)
	console.log(`${pass ? 'ok  ' : 'FAIL'} ${label}`)
}

const plugin = await import(PLUGIN)
check('导出 apply/inject/name', [typeof plugin.apply, plugin.inject, plugin.name], ['function', ['tools'], 'dsh-trash-guard'])

// ── mock ctx ────────────────────────────────────────────────────────────────
const handlers = new Map()
const registered = []
const ctx = {
	logger: { info() {}, warn() {} },
	get: () => undefined,
	on(event, handler) {
		if (!handlers.has(event)) handlers.set(event, [])
		handlers.get(event).push(handler)
	},
	tools: { register(definition) { registered.push(definition); return () => {} } },
}
await mkdir(ROOT, { recursive: true })
plugin.apply(ctx, { workspace: ROOT, trashDir: '_trash', debug: { dir: ROOT + '/_debug' } })

check('注册 2 个工具', registered.map((tool) => tool.name), ['trash', 'restore'])
check('挂载 tools/pre-execute', handlers.has('tools/pre-execute'), true)

// ── 用真实的 dsh-tools 校验工具定义 ─────────────────────────────────────────
const dshTools = await import(DSH_TOOLS)
for (const tool of registered) {
	try {
		dshTools.assertSupportedJsonSchema(tool.parameters)
		dshTools.assertSupportedJsonSchema(tool.output.schema)
		dshTools.projectToolSchema(tool, true)
		check(`schema 合法: ${tool.name}`, true, true)
	} catch (error) {
		check(`schema 合法: ${tool.name}`, `抛错: ${error.message}`, true)
	}
	const rendered = tool.output.render({ paths: ['x'] }, tool.name === 'trash'
		? { stamp: 's', trashDir: 't', moved: [{ id: 'i', from: 'a', to: 'b', kind: 'file' }], failed: [] }
		: { restored: [], failed: [], available: [] })
	check(`${tool.name} render 返回文本块`, rendered[0]?.type === 'text' && rendered[0].text.length > 0, true)
}

// ── 判定表对拍 ──────────────────────────────────────────────────────────────
const guard = handlers.get('tools/pre-execute')[0]
const allow = async () => ({ kind: 'allow' })
async function verdict(name, args) {
	const result = await guard({ name, arguments: args }, allow)
	return result.kind
}

const COMMAND_CASES = [
	['Remove-Item .\\a.txt', 'deny'],
	['Remove-Item -Recurse -Force .\\build', 'deny'],
	['Get-ChildItem . | Remove-Item -Force', 'deny'],
	['rm -rf build', 'deny'],
	['del a.txt', 'deny'],
	['Clear-Content notes.txt', 'deny'],
	['Set-Content x.txt -Value ""', 'deny'],
	["[System.IO.File]::Delete('C:\\x')", 'deny'],
	['git clean -fdx', 'deny'],
	['pwsh -EncodedCommand ZQBjAGgAbwA=', 'deny'],
	['robocopy a b /MIR', 'deny'],
	['Move-Item a.txt b.txt -Force', 'deny'],
	['cmd /c del a.txt', 'deny'],
	['nvim a.txt', 'allow'],
	['Get-ChildItem -Recurse', 'allow'],
	['npm run build', 'allow'],
	['Write-Output "del a.txt"', 'allow'],
	['Select-String -Pattern "Remove-Item" .\\a.ps1', 'allow'],
	['Get-Content model.txt', 'allow'],
]
for (const [command, expected] of COMMAND_CASES) {
	check(`command: ${command}`, await verdict('pwsh', { command }), expected)
}

// 脚本正文（write 工具）判定
const PS_WITH_DELETE = 'Get-ChildItem .\\out -Recurse | Remove-Item -Force\nWrite-Output done\n'
const PS_COMMENT_ONLY = '# Remove-Item is blocked here; use the trash tool\nWrite-Output ok\n'
const PS_DOTNET = '[System.IO.File]::Delete($path)\n'
const MD_NOT_SCRIPT = 'Remove-Item -Recurse -Force .\\x\n'
check('write .ps1 含删除', await verdict('write', { file_path: 'x.ps1', content: PS_WITH_DELETE }), 'deny')
check('write .ps1 仅注释提及', await verdict('write', { file_path: 'x.ps1', content: PS_COMMENT_ONLY }), 'allow')
check('write .ps1 .NET 直调', await verdict('write', { file_path: 'x.ps1', content: PS_DOTNET }), 'deny')
check('write .md 不扫描', await verdict('write', { file_path: 'notes.md', content: MD_NOT_SCRIPT }), 'allow')
check('write .txt 不扫描', await verdict('write', { file_path: 'notes.txt', content: MD_NOT_SCRIPT }), 'allow')
check('trash 工具自身放行', await verdict('trash', { paths: ['x'] }), 'allow')
check('无关工具放行', await verdict('read', { file_path: 'x.txt' }), 'allow')

// 拒绝文案要给出唯一正确下一步
const denial = await guard({ name: 'pwsh', arguments: { command: 'Remove-Item .\\a.txt' } }, allow)
check('拒绝文案提到 trash 工具', denial.kind === 'deny' && denial.reason.includes('trash(') && denial.reason.includes('manifest.jsonl'), true)

// ── trash / restore 往返 ────────────────────────────────────────────────────
const trashTool = registered.find((tool) => tool.name === 'trash')
const restoreTool = registered.find((tool) => tool.name === 'restore')
const manifestPath = join(ROOT, '_trash', 'manifest.jsonl')
const readManifestLines = async () => (await readFile(manifestPath, 'utf8')).trim().split('\n').filter(Boolean).map((line) => JSON.parse(line))

await mkdir(join(ROOT, 'src', 'deep'), { recursive: true })
await writeFile(join(ROOT, 'src', 'deep', 'keep.txt'), 'payload-1', 'utf8')
await writeFile(join(ROOT, 'src', 'old.log'), 'payload-2', 'utf8')

const trashed = await trashTool.execute({ paths: ['src/deep/keep.txt', 'src\\old.log'], note: 'smoke' }, {})
check('trash 移动 2 项', [trashed.moved.length, trashed.failed.length], [2, 0])
check('源文件已不在原处', [existsSync(join(ROOT, 'src', 'deep', 'keep.txt')), existsSync(join(ROOT, 'src', 'old.log'))], [false, false])
check('垃圾箱里存在且内容一致', await readFile(trashed.moved[0].to, 'utf8'), 'payload-1')
check('命名带序号保留原名', trashed.moved[0].to.endsWith('1-keep.txt'), true)

const restored = await restoreTool.execute({ ids: trashed.moved.map((item) => item.id) }, {})
check('restore 恢复 2 项', [restored.restored.length, restored.failed.length], [2, 0])
check('文件回到原位且内容一致', await readFile(join(ROOT, 'src', 'deep', 'keep.txt'), 'utf8'), 'payload-1')
check('再次 restore 同 id 失败（防重复）', (await restoreTool.execute({ ids: [trashed.moved[0].id] }, {})).failed.length, 1)

// 越界保护
const outside = await trashTool.execute({ paths: ['C:\\Windows\\notepad.exe'] }, {})
check('工作区外路径被拒绝', [outside.moved.length, outside.failed.length], [0, 1])

// 不存在路径 → 失败但不抛
const missing = await trashTool.execute({ paths: ['src/nope.txt'] }, {})
check('不存在的路径进 failed', missing.failed.length, 1)

// 目录整体移动
await mkdir(join(ROOT, 'dist', 'nested'), { recursive: true })
await writeFile(join(ROOT, 'dist', 'nested', 'a.js'), 'x', 'utf8')
const dirMove = await trashTool.execute({ paths: ['dist'] }, {})
check('目录整树移动', [dirMove.moved.length, dirMove.moved[0]?.kind], [1, 'dir'])
check('目录内文件随行', await stat(join(dirMove.moved[0].to, 'nested', 'a.js')).then(() => true), true)

// ── 影子层：文本层看不见的删除也能收进垃圾箱 ────────────────────────────────
await mkdir(join(ROOT, 'shadow'), { recursive: true })
await writeFile(join(ROOT, 'shadow', 'killed-by-ps1.txt'), 'bytes-from-shadow', 'utf8')

// 任意一次开跑前调用（这里用无害的 Get-ChildItem）会建影
check('影子层调用放行', await verdict('pwsh', { command: 'Get-ChildItem' }), 'allow')
const mirror = join(ROOT, '_trash', '.shadow', 'shadow', 'killed-by-ps1.txt')
check('影子已建立', existsSync(mirror), true)
check('影子与原文件同 inode（硬链接，不复制字节）', (await stat(mirror, { bigint: true })).ino === (await stat(join(ROOT, 'shadow', 'killed-by-ps1.txt'), { bigint: true })).ino, true)

// 用"移走"模拟一次删除：.ps1 / 原生程序 / .NET 删掉的效果等价
await rename(join(ROOT, 'shadow', 'killed-by-ps1.txt'), join(ROOT, 'escaped.txt'))
await verdict('pwsh', { command: 'Get-ChildItem' })
const shadowEntries = (await readManifestLines()).filter((record) => record.note?.includes('影子层'))
check('sweep 记了 1 条影子回收', shadowEntries.length, 1)
check('影子回收的内容完好', await readFile(shadowEntries[0].to, 'utf8'), 'bytes-from-shadow')
check('影子回收可 restore', (await restoreTool.execute({ ids: [shadowEntries[0].id] }, {})).restored.length, 1)
check('restore 后回原位', await readFile(join(ROOT, 'shadow', 'killed-by-ps1.txt'), 'utf8'), 'bytes-from-shadow')

// trash 工具自己移走的文件，不能被影子层再记一遍
await writeFile(join(ROOT, 'shadow', 'retire.txt'), 'once', 'utf8')
await verdict('pwsh', { command: 'Get-ChildItem' })          // 建影
const retired = await trashTool.execute({ paths: ['shadow/retire.txt'] }, {})  // 正式进垃圾箱
await verdict('pwsh', { command: 'Get-ChildItem' })          // 下一轮 sweep 不应重复记账
const retireRecords = (await readManifestLines()).filter((record) => record.op === 'trash' && record.from?.includes('retire.txt'))
check('一次删除只记一条（不重复）', retireRecords.length, 1)
check('retire 的 id 来自 trash 工具', retireRecords[0].id, retired.moved[0].id)

// ── isSkipped：任意层级的 skipDirs 都要跳过（2026-11-12 回归） ────────────────
// 事故：`插件发布\x\.git\refs\...` 只在路径**首段**比对 skipDirs，嵌套 .git 仍被建影，
// 每次 git 提交都在 _trash 里留噪声。这里把"任意层级"固化成门禁。
const { isSkipped } = plugin.__internals
const SKIP = ['.git', 'node_modules', '__pycache__', '.venv']
const SKIP_CASES = [
	['插件发布/x/.git/refs/heads/main', true, '嵌套 .git（正斜杠）'],
	['插件发布\\x\\.git\\config', true, '嵌套 .git（反斜杠）'],
	['a/b/node_modules/pkg/index.js', true, '嵌套 node_modules'],
	['deep/.venv/lib/x.py', true, '嵌套 .venv'],
	['_trash/2026-11-12/1-a.txt', true, '垃圾箱自身（任意层级）'],
	['src/app.js', false, '普通文件不跳'],
	['git-notes/x.txt', false, '名字含 git 但不是 .git 段'],
]
for (const [rel, expected, label] of SKIP_CASES) check(`isSkipped: ${label}`, isSkipped(rel, '_trash', SKIP), expected)

// ── 误伤回归（2026-11-12）：只在文本里"提到"，不算删除 ─────────────────────
const { classifyText, docPayloadOnly, normalizeTemplate } = plugin.__internals
const MV = 'Move-Item'
const FC = '-Force'
const KL = 'Remove-Item'

// ① overwrite-move 加了语句起始锚点：搜索/输出里提到不再命中，真执行仍命中
check('误伤: 搜索文本里的 move 字样', classifyText(`Select-String -Pattern "${MV} ${FC}" .\\a.md`)?.id, undefined)
check('误伤: 输出文本里的 move 字样', classifyText(`Write-Output "${MV} a b ${FC}"`)?.id, undefined)
check('正例: 真执行 move -Force 仍拦', classifyText(`${MV} .\\a.txt .\\b.txt ${FC}`)?.id, 'overwrite-move')

// ② 模板占位符 ${...} / {{...}} 在脚本正文里不算代码
check('误伤: 脚本里的模板占位', classifyText(normalizeTemplate('const t = `${REMOVE}` x'))?.id, undefined)
check('正例: 脚本里真删除仍拦', classifyText(`${KL} .\\a.txt`)?.id, 'remove-item')

// ③ 往非可执行文档写正文（here-string / 引号）豁免；真清空、写脚本、含执行器都不豁免
const docHere = `Add-Content -LiteralPath .\\notes.md -Value @'\n${KL} .\\a.txt\n'@`
check('误伤: 写 .md 的 here-string 正文', docPayloadOnly(docHere), true)
check('误伤: 写 .json 的引号正文', docPayloadOnly(`Set-Content .\\a.json -Value '${KL} x'`), true)
check('正例: 文档正文里夹真删除必须拦', docPayloadOnly(`${docHere}; ${KL} .\\b.txt`), false)
check('正例: 写脚本 must 拦', docPayloadOnly(`Add-Content -LiteralPath .\\run.ps1 -Value @'\n${KL} .\\a.txt\n'@`), false)
check('正例: 含执行器必须拦', docPayloadOnly(`Add-Content .\\notes.md -Value @'\nInvoke-Expression x\n'@`), false)
check('正例: 真清空仍拦', docPayloadOnly(`Set-Content .\\a.md -Value ''`), false)

console.log(`\n${failures.length === 0 ? 'ALL PASS' : `${failures.length} FAILED`}`)
if (failures.length > 0) {
	console.log(failures.join('\n'))
	process.exitCode = 1
}
