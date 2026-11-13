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
const PLUGIN = new URL('../index.js', import.meta.url).href
const plugin = await import(PLUGIN)
const { classifyText, classifyScript, docPayloadOnly, normalizeTemplate, launchedScriptRefs } = plugin.__internals

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
]

// ── ② 必须拒绝：脚本正文（write 侧） ──────────────────────────────────────
const MUST_DENY_SCRIPT = [
	['Remove-Item .\\data -Recurse -Force\r\n', 'x.ps1', 'remove-item'],
	['if exist data\\a.txt del data\\a.txt\r\n', 'run.bat', 'bat-delete'],
	['for /d %%i in (*) do rd /s /q "%%i"\r\n', 'loop.bat', 'bat-delete'],
	['Remove-`\r\nItem .\\data -Force\r\n', 'fold.ps1', 'remove-item'],
	['shutil.rmtree("/tmp/x")\n', 'clean.py', 'runtime-api-delete'],
	['del .\\a.txt\r\n', 'x.ps1', 'remove-item'],
]

// ── ②b 必须放行：脚本正文（2026-11-13 实测误伤） ──────────────────────────
const MUST_ALLOW_SCRIPT = [
	['del self._hb_lines[:-40]\n', 'app.py', 'Python del 删的是名字/切片，不是文件'],
	['// 注释里的 {rm}/{del} 不该命中\n', 'probe.mjs', '注释里的花括号短词'],
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
const record = (ok, label, detail) => {
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

const total = MUST_DENY_TEXT.length + MUST_DENY_SCRIPT.length + MUST_ALLOW_TEXT.length + MUST_ALLOW_SCRIPT.length + MUST_LAUNCH.length + MUST_NOT_LAUNCH.length + MUST_ALLOW_DOC.length + MUST_NOT_EXEMPT.length + 1
console.log(`\n闸门：${total} 条语料，${failures.length === 0 ? 'ALL PASS' : `${failures.length} FAILED`}`)
if (failures.length > 0) {
	console.log(failures.join('\n'))
	process.exitCode = 1
}

