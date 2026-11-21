// theme=trash-guard status=active date=2026-11-12
/**
 * AUTO-FIX GATE（自动改规则的安全闸门）。
 *
 * 用户 2026-11-12 的验收要求原话：**"只要能解决错误拦截的同时，不放开正确拦截"**。
 * 这条闸门就是那句话的可执行形态——任何规则改动，必须在同一份语料上同时满足：
 *   ① MUST_DENY 全都被拒（不放走真删除）
 *   ② MUST_ALLOW 全都被放（不新增误伤）
 * 任一条不满足 → 退出码 1，改动不得进入正式。
 *
 * 语料分三组：
 *   MUST_DENY_TEXT    命令字符串里必须命中
 *   MUST_DENY_SCRIPT  脚本正文（write 侧）必须命中
 *   MUST_ALLOW_TEXT   命令字符串里必须放行（误伤回收）
 *   MUST_ALLOW_DOC    写非可执行文档的正文必须放行（docPayloadOnly）
 *
 * 跑法：node test/guard.mjs [--selftest]
 *   --selftest：故意把一条期望反转，确认闸门会 FAIL（防"永远 PASS 的假门禁"）。
 */
import { mkdtempSync, readFileSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'

const PLUGIN = new URL('../index.js', import.meta.url).href
const plugin = await import(PLUGIN)
const { classifyText, classifyScript, docPayloadOnly, normalizeTemplate, launchedScriptRefs, setRulesFile, DEFAULT_RULES_PATH, applyAllow, activeRules, classifyCommandDeep, scanLaunchedScripts } = plugin.__internals

// 2026-11-14：闸门此前没调 apply()，rulesFile 为空 → 测的是**内置兜底**，改 rules.json 测不到。
// 夜间流程改的是外置规则，闸门必须先指向它，否则“ALL PASS”是假的。
setRulesFile(DEFAULT_RULES_PATH)

// ── ① 必须拒绝：命令字符串 ────────────────────────────────────────────────
const MUST_DENY_TEXT = [
	['Remove-Item .\\a.txt', 'remove-item'],
	['rm -rf build', 'remove-item'],
	['del a.txt', 'remove-item'],
	['rd /s /q out', 'remove-item'],
	['Clear-Content notes.txt', 'clear-content'],
	["Set-Content x.txt -Value ''", 'truncate'],
	["[System.IO.File]::Delete('C:\\x')", 'dotnet-delete'],
	['git clean -fdx', 'git-destructive'],
	['robocopy a b /MIR', 'robocopy-purge'],
	['pwsh -EncodedCommand ZQBjAGgAbwA=', 'encoded-command'],
	['cmd /c del a.txt', 'cmd-wrapper'],
	['Move-Item a.txt b.txt -Force', 'overwrite-move'],
	['Get-ChildItem . | ForEach-Object { Move-Item $_.FullName .\\dst -Force }', 'overwrite-move'],
	['diskpart', 'disk-destructive'],
	['shutil.rmtree(out)', 'runtime-api-delete'],
	// 2026-11-13：短别名后直接跟 `/` 开关（cmd 合法写法）仍要拦——收紧别名后仍须覆盖
	['del/q a.txt', 'remove-item'],
	['rd/s /q out', 'remove-item'],
	// 2026-11-15：白名单只掩 Env:，同行的真文件删除仍要拦
	['Remove-Item Env:\\X; Remove-Item .\\a.txt', 'remove-item'],
	// 2026-11-18：引号参数是数据，但同行真删除仍要拦；锁清理白名单只认字面量
	['Select-String -Pattern "x"; Remove-Item .\\a.txt', 'remove-item'],
	['os.remove(OTHER_LOCK)', 'runtime-api-delete'],
	// 2026-11-19：白名单只掩数据段，命令里其余位置的真删除仍要拦
	['git commit -m "x"; Remove-Item .\\a.txt', 'remove-item'],
	['python -c "import os; os.remove(\'x\')"', 'runtime-api-delete'],
	["python x.py --json '{}' ; Remove-Item .\\a.txt", 'remove-item'],
	// 2026-11-19 加固：双引号里的 $(...) 会执行——白名单不得掩掉含 $/反引号的双引号段
	['git commit -m "$(Remove-Item .\\a.txt)"', 'remove-item'],
	['Select-String -Pattern "$(Remove-Item .\\a.txt)" .', 'remove-item'],
	['$x = "$(Remove-Item .\\a.txt)" -match \'a\'', 'remove-item'],
	['python x.py --json "$(Remove-Item .\\a.txt)"', 'remove-item'],
	// 2026-11-21：Go 正则片段里的接收者名是数据，但真命令 $(rm \*) 仍须拦
	['$(rm \\*)', 'remove-item'],
	// 2026-11-21 S4：裸 CR（0x0D）也是语句分隔符——前缀类补 \r 后仍须拦
	['x\rrm .\\a.txt', 'remove-item'],
	['x\rClear-Content .\\a.txt', 'clear-content'],
]

// ── ②a 必须拒绝：执行器参数里的删除（2026-11-21 补执行器盲区） ─────────────
// 命令本身没有语句前缀，删除藏在 -Command/iex/变量里——只看外层会放行（exec-args 缺口）。
// 样本用拼接构造，避免本文件被插件自身的写侧扫描拦下。
const DEL = 'Remove' + '-Item .\\a.txt'
const CLR = 'Clear' + '-Content .\\a.txt'
const MUST_DENY_DEEP = [
	[`pwsh -Command "${DEL}"`, 'remove-item'],
	[`powershell -NoProfile -c "${CLR}"`, 'clear-content'],
	[`Invoke-Expression '${DEL}'`, 'remove-item'],
	[`$c = '${DEL}'; & $c`, 'remove-item'],
	[`cmd /c "${DEL}"`, 'remove-item'],
	[`python -c "import os; os.remove('x')"`, 'runtime-api-delete'],
	// 2026-11-21 S4 后：变量引用在 -Command/iex 后、括号包裹载荷、node --eval 三类补覆盖
	[`$v = '${DEL}'; pwsh -Command $v`, 'remove-item'],
	[`$v = '${DEL}'; iex $v`, 'remove-item'],
	[`pwsh -Command ("${DEL}")`, 'remove-item'],
	[`node --eval "const fs=require('fs');fs.rmSync('x')"`, 'runtime-api-delete'],
	[`pwsh -Command (((("Remove-Item .\\a.txt"))))`, 'remove-item'],
	[`pwsh -Command ${'('.repeat(17)}"Remove-Item .\\a.txt"${')'.repeat(17)}`, 'remove-item'],
	[`pwsh -Command ${'('.repeat(64)}"Remove-Item .\\a.txt"${')'.repeat(64)}`, 'remove-item'],
	[`iex ${'('.repeat(513)}"Remove-Item .\\a.txt"${')'.repeat(513)}`, 'remove-item'],
	[`iex ${'('.repeat(1024)}"Remove-Item .\\a.txt"${')'.repeat(1024)}`, 'remove-item'],
]

// ── ② 必须拒绝：脚本正文（write 侧） ──────────────────────────────────────
const MUST_DENY_SCRIPT = [
	['Remove-Item .\\data -Recurse -Force\r\n', 'x.ps1', 'remove-item'],
	['if exist data\\a.txt del data\\a.txt\r\n', 'run.bat', 'bat-delete'],
	['for /d %%i in (*) do rd /s /q "%%i"\r\n', 'loop.bat', 'bat-delete'],
	['Remove-`\r\nItem .\\data -Force\r\n', 'fold.ps1', 'remove-item'],
	['shutil.rmtree("/tmp/x")\n', 'clean.py', 'runtime-api-delete'],
	['del .\\a.txt\r\n', 'x.ps1', 'remove-item'],
	// 2026-11-21 S4：脚本正文用裸 CR 分隔语句，第二行删除仍须拦
	['Write-Output A\rClear-Content .\\a.txt\r\n', 'cr.ps1', 'clear-content'],
]

// ── ②b 必须放行：脚本正文（2026-11-13 实测误伤） ──────────────────────────
const MUST_ALLOW_SCRIPT = [
	['del self._hb_lines[:-40]\n', 'app.py', 'Python del 删的是名字/切片，不是文件'],
	['// 注释里的 {rm}/{del} 不该命中\n', 'probe.mjs', '注释里的花括号短词'],
	['"""说明：app.py 里的 os.remove(SINGLE_LOCK) 是锁清理。"""\n', 'probe.py', 'docstring 提到锁清理（白名单 single-lock-cleanup）'],
]

// ── ②c 启动识别（2026-11-13 补：解释器直启 / cmd 套解释器 / Start-Process） ──
const MUST_LAUNCH = [
	['python "x.py"', 'python 直启'],
	['py -3 x.py', 'py 启动器'],
	['python -u -X utf8 x.py', 'python 多开关'],
	['pwsh x.ps1', 'pwsh 位置参数'],
	['Start-Process "x.ps1"', 'Start-Process'],
	['cmd /c python x.py', 'cmd /c 套解释器'],
]

// ── ②d 不得误认启动（只认语句起点，不认参数/内联代码） ────────────────────
const MUST_NOT_LAUNCH = [
	['echo python x.py', '非语句起点'],
	['python -c "print(1)"', '内联代码'],
]

// ── ③ 必须放行：命令字符串（这三类都是真实误伤过的） ──────────────────────
const MUST_ALLOW_TEXT = [
	['Select-String -Pattern "Move-Item -Force" .\\a.md', '搜索 move 字样（旧版误伤）'],
	["Select-String -Path x -Pattern 'Remove-Item' .\\a.ps1", '搜索删除字样'],
	['Write-Output "Remove-Item a.txt"', '纯输出文本'],
	['Get-ChildItem -Recurse', '纯遍历'],
	['npm run build', '普通构建'],
	// 2026-11-13：`(RD.PSK_HEX)` / `(RD, ...)` 里的 RD 是标识符，不是 rd 命令
	['$d = bytes.fromhex(RD.PSK_HEX)', '属性名 RD. 不是 rd 命令'],
	['$x = getattr(RD, "PSK_HEX")', '参数里的 RD, 不是 rd 命令'],
	// 2026-11-14：`rd = csv.reader(...)` 这类变量赋值不是 rmdir 命令
	['rd = csv.reader(fh)', 'rd 变量赋值'],
	['RD = _imp("x")', 'RD 变量赋值（大写）'],
	['rm = 1', 'rm 变量赋值'],
	// 2026-11-15：清理进程环境变量不是删文件（白名单条目 env-var-cleanup）
	['Remove-Item Env:SM_ACCT', '清理进程环境变量'],
	// 2026-11-18：扫描/匹配开关的引号参数（含 | 交替）不再误伤（白名单 scan-arg-quoted）
	["Select-String -LiteralPath .\\a.py -Pattern 'os\\.remove|del '", '扫描删除字样（引号内 | 交替）'],
	['$hit -match "del |rmdir"', '表达式里 match 删除字样'],
	// 2026-11-19：三类"引号内是数据"的误伤（git 提交说明 / --json 证据 / 比较运算符左侧字面量）
	['git commit -m "feat: 修引号内 |del 误伤"', 'git 提交说明（allow git-commit-message）'],
	[`python stage_gate.py --json '{"problem":"引号内 |del 扫描"}'`, '--json 证据数据（allow json-flag-arg）'],
	[`"OS_REMOVE => " + ('os.remove("x")' -match $kw)`, '比较运算符左侧字面量（allow regex-test-literal）'],
	// 2026-11-19：同一形态带右侧引号操作数（-match 'x'）时，allow 顺序仍须先掩左侧字面量
	[`$r = ('os.remove("x")' -match 'os\\.remove')`, '比较左侧字面量 + 右侧引号操作数'],
	// 2026-11-21：Go 源码正则片段 `func \(rm \*Rule\)` 不是删除命令（allow go-regex-receiver）
	[`L 'c004443' 'internal/networkrules/rule/rule.go' 'func \\(rm \\*Rule\\) andModifiers|func \\(rm \\*Rule\\) orModifiers'`, 'Go 正则接收者片段（allow go-regex-receiver）'],
]

// ── ③a 必须放行：执行器参数里只有数据/只读命令（2026-11-21） ────────────────
const SEL = "Select-String -LiteralPath .\\a.py -Pattern 'Remove" + "-Item'"
const Q = String.fromCharCode(39)
const IEX_DATA = 'Write-Output "iex ' + Q + 'Remove' + '-Item x' + Q + '"'
const CMD_DATA = 'Write-Output "pwsh -Command ' + Q + 'Remove' + '-Item x' + Q + '"'
const MUST_ALLOW_DEEP = [
	[`pwsh -Command "Get-ChildItem ."`, '执行器里只读命令'],
	[`powershell -NoProfile -Command "${SEL}"`, '执行器里搜索字样（引号内数据）'],
	[`iex "Get-Date"`, 'iex 只读'],
	[`$c = 'Get-Date'; & $c`, '变量里只读命令'],
	[IEX_DATA, '纯输出文本里提到 iex（不是执行）'],
	[CMD_DATA, '纯输出文本里提到 pwsh -Command（不是执行）'],
	// 2026-11-21 S4 后：先 `& $c` 再赋值的写法运行时变量为空，不该判删
	[`& $c; $c = '${DEL}'`, '引用在赋值之前（运行时为空）'],
]

// ── ④ 必须放行：写文档的正文 ──────────────────────────────────────────────
const MUST_ALLOW_DOC = [
	[`Add-Content -LiteralPath .\\notes.md -Value @'\nRemove-Item .\\a.txt\n'@`, '写 .md 的 here-string'],
	[`Set-Content .\\a.json -Value 'Remove-Item x'`, '写 .json 的引号正文'],
]

// ── ⑤ 反向样本：文档里夹真删除 / 写脚本 / 含执行器 / 真清空，都必须继续拒绝 ──
const MUST_NOT_EXEMPT = [
	[`Add-Content .\\notes.md -Value @'\nRemove-Item .\\a.txt\n'@; Remove-Item .\\b.txt`, '文档正文 + 真删除'],
	[`Add-Content -LiteralPath .\\run.ps1 -Value @'\nRemove-Item .\\a.txt\n'@`, '写脚本'],
	[`Add-Content .\\notes.md -Value @'\nInvoke-Expression x\n'@`, '含执行器'],
	["Set-Content .\\a.md -Value ''", '真清空'],
]

const selftest = process.argv.includes('--selftest')
const failures = []
// 2026-11-21：条数改用计数器——往语料里加样本时不必再手改公式（旧公式漏算过 3 条）。
let checks = 0
const record = (ok, label, detail) => {
	checks += 1
	if (!ok) failures.push(`${label} :: ${detail}`)
	console.log(`${ok ? 'ok  ' : 'FAIL'} ${label}`)
}

for (const [cmd, want] of MUST_DENY_TEXT) {
	const got = classifyText(cmd)?.id
	const ok = selftest && cmd === MUST_DENY_TEXT[0][0] ? false : got === want
	record(ok, `deny: ${cmd.slice(0, 42)}`, `got=${got ?? 'allow'} want=${want}`)
}
for (const [src, file, want] of MUST_DENY_SCRIPT) {
	const got = classifyScript(src, file)?.id
	record(got === want, `deny-script: ${file}`, `got=${got ?? 'allow'} want=${want}`)
}
for (const [cmd, label] of MUST_ALLOW_TEXT) {
	const got = classifyText(cmd)?.id
	record(got === undefined, `allow: ${label}`, `got=${got ?? 'allow'}`)
}
for (const [cmd, want] of MUST_DENY_DEEP) {
	const got = classifyCommandDeep(cmd, { allow: [] })?.id
	record(got === want, `deny-deep: ${cmd.slice(0, 42)}`, `got=${got ?? 'allow'} want=${want}`)
}
for (const [cmd, label] of MUST_ALLOW_DEEP) {
	const got = classifyCommandDeep(cmd, { allow: [] })?.id
	record(got === undefined, `allow-deep: ${label}`, `got=${got ?? 'allow'}`)
}
// 启动侧多根解析：workdir 里的脚本要能读到；不在候选根里的不猜。
const rootA = mkdtempSync(join(tmpdir(), 'tg-root-a-'))
const workA = mkdtempSync(join(tmpdir(), 'tg-root-b-'))
writeFileSync(join(workA, 'scan.ps1'), 'Remove' + '-Item .\\x\r\n')
const hitRoot = await scanLaunchedScripts('pwsh -File .\\scan.ps1', [workA, rootA], {})
record(hitRoot !== undefined && hitRoot.where === 'launched', 'launch-root: workdir 命中', JSON.stringify(hitRoot))
const missRoot = await scanLaunchedScripts('pwsh -File .\\scan.ps1', [rootA], {})
record(missRoot === undefined, 'launch-root: 非候选根不命中', JSON.stringify(missRoot))
for (const [src, file, label] of MUST_ALLOW_SCRIPT) {
	const got = classifyScript(src, file)?.id
	record(got === undefined, `allow-script: ${label}`, `got=${got ?? 'allow'}`)
}
for (const [cmd, label] of MUST_LAUNCH) {
	const refs = launchedScriptRefs(cmd)
	record(refs.some((r) => /\.(?:py|ps1)$/i.test(r)), `launch: ${label}`, `refs=${JSON.stringify(refs)}`)
}
for (const [cmd, label] of MUST_NOT_LAUNCH) {
	const refs = launchedScriptRefs(cmd)
	record(refs.length === 0, `no-launch: ${label}`, `refs=${JSON.stringify(refs)}`)
}
for (const [cmd, label] of MUST_ALLOW_DOC) {
	record(docPayloadOnly(cmd) === true, `allow-doc: ${label}`, `docPayloadOnly=${docPayloadOnly(cmd)}`)
}
for (const [cmd, label] of MUST_NOT_EXEMPT) {
	record(docPayloadOnly(cmd) === false, `not-exempt: ${label}`, `docPayloadOnly=${docPayloadOnly(cmd)}`)
}
// 模板占位归一化本身
record(classifyText(normalizeTemplate('const t = `${REMOVE}` x')) === undefined, 'allow: 模板占位', 'normalizeTemplate 后仍命中')

// ── ⑦ 白名单机制（2026-11-14）：只掩匹配段，不丢整行 ────────────────────
const demoAllow = [{ id: 'demo', re: /rd\s*=\s*/gi }]
record(applyAllow('rd = csv.reader(fh)', demoAllow) === 'Xcsv.reader(fh)', 'allow-mask: 片段掩码', applyAllow('rd = csv.reader(fh)', demoAllow))
const mixed = applyAllow('rd = 1; Remove-Item x', demoAllow)
record(classifyText(mixed)?.id === 'remove-item', 'allow-mask: 同行真删除仍拦', `masked=${JSON.stringify(mixed)} got=${classifyText(mixed)?.id ?? 'ALLOW'}`)

// ── ⑧ 真实白名单条目：不得吞掉任何 MUST_DENY 样本（空 allow 时 0 条） ─────
const realAllow = activeRules().allow
let allowChecks = 0
for (const rule of realAllow) {
	for (const [cmd] of MUST_DENY_TEXT) {
		allowChecks += 1
		const masked = applyAllow(cmd, [rule])
		const still = classifyText(masked)?.id
		record(still !== undefined, `allow-safe: ${rule.id} × ${cmd.slice(0, 30)}`, `masked=${JSON.stringify(masked)} got=${still ?? 'ALLOW'}`)
	}
	for (const [src, file] of MUST_DENY_SCRIPT) {
		allowChecks += 1
		const masked = applyAllow(src, [rule])
		const still = classifyScript(masked, file)?.id
		record(still !== undefined, `allow-safe-script: ${rule.id} × ${file}`, `masked=${JSON.stringify(masked)} got=${still ?? 'ALLOW'}`)
	}
	for (const [cmd] of MUST_DENY_DEEP) {
		allowChecks += 1
		const masked = applyAllow(cmd, [rule])
		const still = classifyCommandDeep(masked, { allow: [] })?.id
		record(still !== undefined, `allow-safe-deep: ${rule.id} × ${cmd.slice(0, 30)}`, `masked=${JSON.stringify(masked)} got=${still ?? 'ALLOW'}`)
	}
}

// ── ⑧b 内置兜底与外置规则的边界修复同步（2026-11-14） ─────────────────────
setRulesFile('')
record(classifyText('rd = csv.reader(fh)') === undefined, 'builtin: rd 变量赋值', `got=${classifyText('rd = csv.reader(fh)')?.id ?? 'allow'}`)
record(classifyText('rd /s /q out')?.id === 'remove-item', 'builtin: rd /s 仍拦', `got=${classifyText('rd /s /q out')?.id ?? 'allow'}`)
setRulesFile(DEFAULT_RULES_PATH)

// ── ⑨ 外置 allow 载入端到端（临时规则文件，跑完切回真实规则） ──────────────
const demoDir = mkdtempSync(join(tmpdir(), 'trash-guard-allow-'))
const demoRules = JSON.parse(readFileSync(DEFAULT_RULES_PATH, 'utf8'))
demoRules.allow = [
	{
		id: 'demo-selectstring',
		label: 'demo',
		pattern: "(?:select-string|sls)[^;\\n]*?-pattern\\s*:?\\s*'[^'\\n]*'",
		flags: 'gi',
	},
]
writeFileSync(join(demoDir, 'rules.json'), JSON.stringify(demoRules))
setRulesFile(join(demoDir, 'rules.json'))
record(activeRules().allow.length === 1, 'allow-load: 外置条目载入', `n=${activeRules().allow.length}`)
record(classifyText("Select-String -Path x -Pattern 'Remove-Item'") === undefined, 'allow-load: 掩码后放行', 'still deny')
record(classifyText("Select-String -Path x -Pattern 'Remove-Item'; Remove-Item y")?.id === 'remove-item', 'allow-load: 同行真删除仍拦', 'got allow')
const demoRd = [{ id: 'demo-rd', re: /rd\s*=\s*/gi }]
record(classifyScript(applyAllow('rd = 1\r\nshutil.rmtree("/tmp/x")\r\n', demoRd), 'x.py')?.id === 'runtime-api-delete', 'allow-load: 脚本里真删除仍拦', 'got allow')
record(classifyScript(applyAllow('rd = 1\r\nif exist x del x\r\n', demoRd), 'x.bat')?.id === 'bat-delete', 'allow-load: 批处理真删除仍拦', 'got allow')
setRulesFile(DEFAULT_RULES_PATH)

console.log(`\n闸门：${checks} 条语料，${failures.length === 0 ? 'ALL PASS' : `${failures.length} FAILED`}`)
if (failures.length > 0) {
	console.log(failures.join('\n'))
	process.exitCode = 1
}

