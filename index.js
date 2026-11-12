// theme=trash-guard status=active date=2026-11-10
/**
 * dsh-trash-guard — 让 DSH 的每一次"删除意图"落进工作区垃圾箱。
 *
 * 两条互补的通道：
 *  1) `tools/pre-execute` 策略：模型发出的 shell 命令文本、以及它写入的脚本正文
 *     （.ps1/.bat/.sh/.py/...）里出现删除动作时，直接 deny，并把它引导到 `trash` 工具。
 *     这是在"删除发生之前"拦，代价是只看得见文本。
 *  2) `trash` / `restore` 两个工具：把文件或目录 **移动** 到 `_trash/<时间戳>/`，
 *     同时把 来源→去向 写进 `_trash/manifest.jsonl`。全程只用 rename（同卷原子移动），
 *     不调用任何删除 API —— 所以即使本插件出 bug，最坏结果也只是东西没动，而不是丢。
 *
 * 明确不覆盖（见 README「覆盖矩阵」）：
 *  - 由**别的程序在运行时生成**的脚本（文本层看不见正文）；
 *  - 被删内容的字节级"快照"（本插件不做 shadow store，阶段二）；
 *  - 不经过 `pwsh`/`bash`/`write`/`apply_patch` 这几个工具的删除（例如某个已注册的第三方工具自己删文件）。
 *
 * 依赖：零。只用 node: 内置模块，插件定义用普通对象（不 import defineTool），
 * 因为 profile 目录里没有 node_modules，任何裸包导入都会解析失败。
 */

import { existsSync, mkdirSync, statSync, writeFileSync } from 'node:fs'
import { appendFile, link, mkdir, open, readdir, readFile, rename, stat } from 'node:fs/promises'
import { basename, dirname, isAbsolute, join, relative, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'

export const name = 'dsh-trash-guard'
/** 只需要工具注册表；fs 服务可有可无（有就用来解析进程可见路径）。 */
export const inject = ['tools']

const TRASH_TOOL = 'trash'
const RESTORE_TOOL = 'restore'
const DEFAULT_CONFIG = {
	/** 垃圾箱目录：相对工作区，或绝对路径。必须在同一卷上才能 rename。 */
	trashDir: '_trash',
	/** 工作区根；不给就用宿主进程的 cwd（dsh 的 workspaceRoot 默认就是它）。 */
	workspace: '',
	/** 扫描 `write` 写出的脚本正文。 */
	scanScriptWrites: true,
	/** 启动命令里引用的脚本文件，启动前读正文扫描。 */
	scanLaunchedScripts: true,
	/** 单个脚本最多读多少字节来扫（按字节读后再按 BOM 解码）。 */
	maxScriptBytes: 8 * 1024 * 1024,
	/** 拒绝把工作区之外的路径移进垃圾箱（防止 agent 把 C:\\Windows 搬进回收区）。 */
	denyOutsideWorkspace: true,
	/** 例外白名单：命令字符串命中任一条正则就放行（给自己留的逃生门）。 */
	allow: [],
	/**
	 * 影子层：在每次改动型工具调用前后维护一份"硬链接镜像"，用来兜住
	 * 文本层看不见的删除（运行期生成的 .ps1、原生程序、.NET 直调）。
	 * 硬链接不复制字节，只加一个目录项，所以成本是 O(文件数) 的元数据操作。
	 */
	shadow: {
		enabled: true,
		/**
		 * 单次扫描上限；超过就本轮放弃影子（并告警），避免大仓库把每次调用拖成秒级。
		 * 本机实测：300 文件首次建影 ≈1.2s、稳态重扫 ≈0.5s（≈1.6ms/文件，含 Defender 扫描），
		 * 5000 文件最坏约 8s —— 再大就调小这个值改用文本层 + 启动扫描层。
		 */
		maxFiles: 5000,
		/** 这些顶层目录不建影子。 */
		skipDirs: ['.git', 'node_modules', '__pycache__', '.venv'],
	},
	/**
	 * 2026-11-11 调试模式（**默认开启**）：每次拦截都把现场写成一行 JSONL 到 debug.dir，
	 * 供夜间分析误判与规则优化。写盘失败只告警，绝不影响拦截本身。
	 */
	debug: {
		enabled: true,
		dir: 'E:\\dsh-trash-guard-logs',
		maxTextBytes: 16 * 1024,
		redact: true,
	},
}

/** 调试日志默认目录（E 盘；目录不存在时首次写日志自动创建）。 */
const DEFAULT_DEBUG_DIR = 'E:\\dsh-trash-guard-logs'

/** 语句起始锚点：行首、或 `; | & ( {` 之后，避免把字符串/参数里的 del、rm 当成命令。 */
const STATEMENT = String.raw`(?:^|[\n;|&({])\s*`

/**
 * 删除动作识别表。只认「语句起始」形态与明确的 API 调用形态，
 * 宁可漏判也不误伤普通文本（误伤会让 agent 整个工作流卡死）。
 * 每条：id（报错里显示）、label（人话）、re（正则）。
 */
const RULES = [
	{
		id: 'remove-item',
		label: 'Remove-Item / rm / del / rd / rmdir / unlink',
		re: new RegExp(STATEMENT + String.raw`(?:remove-item|clear-item|ri|rm|del|erase|rd|rmdir|unlink)\b`, 'i'),
	},
	{
		id: 'clear-content',
		label: 'Clear-Content',
		re: new RegExp(STATEMENT + String.raw`clear-content\b`, 'i'),
	},
	{
		id: 'truncate',
		label: "Set-Content -Value '' / $null（清空文件内容）",
		re: /\bset-content\b[^\n;|]*?\s-value\s+(?:''|""|\$null)(?=\s|$)/i,
	},
	{
		id: 'dotnet-delete',
		label: '[System.IO.File]::Delete / [IO.File]::Delete 一类 .NET 直调',
		re: /\[\s*(?:[A-Za-z0-9_.]*\.)?(?:file|directory|fileinfo|directoryinfo)\s*\]\s*::\s*delete/i,
	},
	{
		id: 'method-delete',
		label: '对象上的 .Delete() / .Delete($true) 方法',
		re: /\.\s*delete\s*\(\s*(?:\$?(?:true|false)\s*)?\)/i,
	},
	{
		id: 'git-destructive',
		label: 'git clean / git reset --hard / git checkout -- .',
		re: /\bgit\s+(?:clean\b|reset\s+--hard\b|checkout\s+--\s+\.)/i,
	},
	{
		id: 'encoded-command',
		label: '-EncodedCommand（内容不可见，无法审计）',
		re: /-encodedcommand\b/i,
	},
	{
		id: 'robocopy-purge',
		label: 'robocopy /MIR|/PURGE（镜像即删除多余项）',
		re: /\brobocopy\b[^\n]*\s\/(?:mir|purge)\b/i,
	},
	{
		id: 'runtime-api-delete',
		label: 'shutil.rmtree / os.remove / fs.rm / fs.unlink 等脚本 API',
		re: /\b(?:shutil\.rmtree|os\.remove|os\.unlink|os\.rmdir|fs\.rm\(|fs\.rmSync|fs\.unlink|fs\.unlinkSync|fs\.rmdir)\b/i,
	},
	{
		id: 'disk-destructive',
		label: 'diskpart / Clear-Disk / Format-Volume / vssadmin delete',
		re: /\b(?:diskpart|clear-disk|format-volume|initialize-disk|vssadmin\s+delete)\b/i,
	},
	{
		id: 'overwrite-move',
		label: 'Move-Item -Force（覆盖目标 = 目标消失）',
		// 2026-11-12 误伤修复：原来没有语句起始锚点，`Select-String -Pattern "Move-Item -Force"` 这种
		// **只是搜索文本**的调用也会被判成删除。加 STATEMENT 锚点后，只有真正在语句起始处执行的
		// move 才算；引号/参数里提到这串字不再命中。
		re: new RegExp(STATEMENT + String.raw`(?:move-item|mv|move)\b[^\n]*?\s-force\b`, 'i'),
	},
	{
		id: 'cmd-wrapper',
		label: 'cmd /c del|erase|rd|rmdir',
		// 末尾用 lookahead 而不是 \b：路径里出现 `\rd\` 这种目录名时不该被当成删除动词（真实测试踩到过）
		re: /\bcmd(?:\.exe)?\s+[^\n]*?\/(?:c|k)\s+[^\n]*?\b(?:del|erase|rd|rmdir|deltree)(?=[\s"']|$)/i,
	},
]

const SCRIPT_EXT = new Set([
	'.ps1', '.psm1', '.psd1', '.bat', '.cmd', '.sh', '.bash', '.zsh',
	'.py', '.js', '.mjs', '.cjs', '.ts', '.vbs', '.reg',
])

/** 这些工具可能在磁盘上造成增删，影子层只围着它们转。 */
const MUTATING_TOOLS = new Set(['pwsh', 'bash', 'write', 'edit', 'apply_patch', TRASH_TOOL, RESTORE_TOOL])

/** 压缩成一行、截断，用于把命中的原文回给模型（不刷屏）。 */
function clip(text, max = 160) {
	const one = String(text).replace(/\s+/g, ' ').trim()
	return one.length > max ? `${one.slice(0, max)}…` : one
}

/**
 * 拆掉续行符再判定：PowerShell 的 `` ` `` 折行、批处理的 `^` 折行、shell 的 `\` 折行。
 * 不拆的话 `Remove-` + 换行 + `Item` 这种写法会把动词劈成两半，规则就看不见了。
 */
function normalizeContinuations(text) {
	return String(text).replace(/`\r?\n/g, '').replace(/\^\r?\n/g, '').replace(/\\\r?\n/g, '')
}

/**
 * 按 BOM / 内容特征解码脚本字节。
 * PowerShell 5.1 的 `>` 与 `Out-File` 默认写 UTF-16LE，按 UTF-8 硬读会得到夹 NUL 的乱码，
 * 正则全部失效 —— 这是"脚本明明有删除却扫不到"的主要成因。
 */
function decodeScriptBuffer(buffer) {
	if (buffer.length >= 2 && buffer[0] === 0xff && buffer[1] === 0xfe) return buffer.subarray(2).toString('utf16le')
	if (buffer.length >= 2 && buffer[0] === 0xfe && buffer[1] === 0xff) return Buffer.from(buffer.subarray(2)).swap16().toString('utf16le')
	if (buffer.length >= 3 && buffer[0] === 0xef && buffer[1] === 0xbb && buffer[2] === 0xbf) return buffer.subarray(3).toString('utf8')
	const window = buffer.subarray(0, Math.min(512, buffer.length))
	let nuls = 0
	for (const byte of window) if (byte === 0) nuls += 1
	if (window.length >= 4 && nuls / window.length > 0.3) return buffer.toString('utf16le') // 无 BOM 的 UTF-16
	return buffer.toString('utf8')
}

/** 读脚本正文：按字节读 + 解码；超过上限只读前 maxBytes，避免把大文件整个吞进内存。 */
async function readScriptText(target, maxBytes) {
	const info = await stat(target)
	if (!info.isFile()) return undefined
	const size = Number(info.size)
	const length = Math.min(size, maxBytes)
	if (length === 0) return ''
	const handle = await open(target, 'r')
	try {
		const buffer = Buffer.alloc(length)
		await handle.read(buffer, 0, length, 0)
		return decodeScriptBuffer(buffer)
	} finally {
		await handle.close()
	}
}

/** 命中规则的那一行原文（脚本正文场景比整篇更有用）。 */
function matchedLine(text, re) {
	const line = String(text).split(/\r?\n/).find((candidate) => re.test(candidate))
	return line ?? clip(text)
}

/** 文本里是否有删除动作；返回规则对象或 undefined。 */
function classifyText(text, allow = []) {
	const body = normalizeContinuations(text)
	for (const pattern of allow) {
		try {
			if (new RegExp(pattern, 'i').test(body)) return undefined
		} catch {
			/* 配置里的坏正则不影响主判定 */
		}
	}
	for (const rule of RULES) if (rule.re.test(body)) return rule
	return undefined
}

/**
 * 批处理专用的宽松规则：.bat/.cmd 里删除动词可以出现在行中间
 * （`if exist x del x`、`for /d %%i in (*) do rd /s /q "%%i"`），
 * 语句起始锚点会漏判，所以对批处理正文单独放宽；`rem`/`::`/`echo`/`set` 行不参与。
 */
const BAT_RULE = {
	id: 'bat-delete',
	label: '批处理里的 del/erase/rd/rmdir（行中任意位置）',
	re: /(?:^|[\s&|(])(?:del|erase|rd|rmdir)(?=[\s/"']|$)/i,
}

/** 逐行找批处理删除动词；返回命中行对应的规则或 undefined。 */
function classifyBatch(content) {
	for (const rawLine of normalizeContinuations(String(content)).split(/\r?\n/)) {
		const line = rawLine.trim()
		if (line.length === 0) continue
		if (/^(?:rem\b|::|@?echo\b|title\b|set\b)/i.test(line)) continue
		if (BAT_RULE.re.test(line)) return BAT_RULE
	}
	return undefined
}

/**
 * 2026-11-12 误伤修复：脚本正文里的模板占位符（`${DEL}`、`{{ cmd }}`）不是代码。
 * 它们会把 `{` 变成语句起始锚点，让 `del`/`rm` 这类短词在占位符名里被误命中
 * （实测：写测试脚本时 `${DEL}` 被判成删除）。只在**写入侧/脚本正文**归一化，
 * 命令侧不动——命令里的 `${...}` 是真实变量展开，仍需 fail-closed。
 */
function normalizeTemplate(text) {
	return String(text)
		.replace(/\$\{[^}\n]{1,60}\}/g, 'X')
		.replace(/\{\{[^}\n]{1,60}\}\}/g, 'X')
}

/** 往"非可执行文档"里写正文的 cmdlet（内容不会被当代码跑）。 */
const DOC_WRITE_TARGET = /(?:add-content|set-content|out-file)\b[^\n;|]*?\s(?:-literalpath|-filepath|-path)?\s*['"]?([^\s'";|]+\.(?:md|markdown|txt|json|jsonl|log|csv|ya?ml))['"]?/i
/** 命令里若出现这些"把文本当代码执行"的入口，就不适用文档豁免。 */
const TEXT_EXECUTOR = /\b(?:invoke-expression|iex|start-process|cmd(?:\.exe)?\s+\/[ck]|bash\s+-c|sh\s+-c|python[0-9.]*\s+-[ce]|node\s+-e)\b/i

/**
 * 2026-11-12 误伤修复：把"只是写进 .md/.txt/.json 的正文"从删除判定里豁免。
 * 实测误伤：`Add-Content notes.md -Value @'…Move-Item -Force…'@` 把文档写作当成删除。
 * 三条闸门同时成立才豁免：①目标是非可执行文档后缀 ②命令不含文本执行器 ③去掉 here-string
 * 与引号内容后已无任何命中。任何一条不成立 → 维持拦截（fail-closed）。
 */
function docPayloadOnly(command) {
	const text = String(command)
	if (!DOC_WRITE_TARGET.test(text)) return false
	if (TEXT_EXECUTOR.test(text)) return false
	const stripped = text
		.replace(/@(['"])\r?\n[\s\S]*?\r?\n\1@/g, 'X')
		// 只折叠**非空**引号内容：`-Value ''` 这种真·清空必须保持原样，否则会被自己豁免掉。
		.replace(/"[^"\n]+"/g, 'X')
		.replace(/'[^'\n]+'/g, 'X')
	return classifyText(stripped) === undefined
}

/** 脚本正文判定：通用规则 + 批处理宽松规则。 */
function classifyScript(content, scriptPath) {
	const body = normalizeTemplate(content)
	const rule = classifyText(body)
	if (rule !== undefined) return rule
	if (/\.(?:bat|cmd)$/i.test(String(scriptPath ?? ''))) return classifyBatch(body)
	return undefined
}

/** child 是否严格等于 parent 或位于其内部。 */
function isInside(parent, child) {
	const rel = relative(parent, child)
	return rel === '' || (!rel.startsWith('..') && !isAbsolute(rel))
}

/** 2026-11-10T10-44-02-123Z，用作垃圾箱子目录名与 id 前缀。 */
function stampOf(date = new Date()) {
	return date.toISOString().replace(/[:.]/g, '-')
}

/** 归一化调试配置：默认开启；路径/上限/脱敏都有安全回退。 */
function debugSettings(config) {
	const debug = config?.debug ?? {}
	const enabled = debug.enabled !== false
	const rawDir = typeof debug.dir === 'string' && debug.dir.trim() !== '' ? debug.dir.trim() : DEFAULT_DEBUG_DIR
	const maxTextBytes = Number.isFinite(debug.maxTextBytes) && debug.maxTextBytes > 0 ? Math.trunc(debug.maxTextBytes) : 16 * 1024
	return { enabled, dir: resolve(rawDir), maxTextBytes, redact: debug.redact !== false }
}

/** 本地日期 YYYY-MM-DD（日志按人看的本地时区切分，不用 UTC）。 */
function localDateStamp(date = new Date()) {
	const pad = (value) => String(value).padStart(2, '0')
	return `${date.getFullYear()}-${pad(date.getMonth() + 1)}-${pad(date.getDate())}`
}

/**
 * 2026-11-11：启动心跳。记录**真正被加载的那个模块文件**的 mtime，供夜间分析判断
 * "运行态是不是最新版"——不改代码、不重启就永远无法从外部确认这件事，所以让插件自己说。
 * 写失败只告警，不影响挂载。
 */
function writeHeartbeat(config, warn) {
	const debug = debugSettings(config)
	if (!debug.enabled) return
	try {
		const modulePath = fileURLToPath(import.meta.url)
		const info = statSync(modulePath)
		mkdirSync(debug.dir, { recursive: true })
		writeFileSync(
			join(debug.dir, '_heartbeat.json'),
			`${JSON.stringify({
				at: new Date().toISOString(),
				pid: process.pid,
				node: process.version,
				modulePath,
				moduleMtimeMs: info.mtimeMs,
				moduleBytes: info.size,
				trashDir: config.trashDir,
				debugDir: debug.dir,
				shadow: config.shadow?.enabled === true,
			}, null, 2)}\n`,
			'utf8',
		)
	} catch (error) {
		warn?.(`dsh-trash-guard: 心跳写入失败（不影响拦截）：${error instanceof Error ? error.message : String(error)}`)
	}
}

/** 轻量脱敏：只挡最常见的"键=值"与 Bearer 凭据形态，不改变命令结构，便于复盘时仍能读懂。 */
function redactSecrets(text) {
	return String(text)
		.replace(/\b(authorization)\s*[:=]\s*(bearer\s+)?[^\s"']+/gi, (whole, key, bearer) => `${key}: ${bearer ? 'Bearer ' : ''}***`)
		.replace(/\b(Bearer)\s+[A-Za-z0-9\-_.=]+/gi, '$1 ***')
		.replace(/\b(passw(?:or)?d|pwd|token|secret|api[_-]?key|apikey)(\s*[:=]\s*)([^\s"']+)/gi, (whole, key, sep) => `${key}${sep}***`)
}

/** 会话标识：只取确实存在的 id，取不到就留空（不猜）。 */
function sessionKeyOf(exec) {
	const session = exec?.agent?.session
	if (typeof session === 'string') return session
	if (session !== undefined && session !== null) {
		const id = session.id ?? session.sessionId
		if (typeof id === 'string' && id !== '') return id
	}
	return ''
}

/** 把一次拦截写成一行 JSONL；任何失败只告警，绝不影响拦截返回值。 */
async function writeBlockRecord(config, exec, hit, root, warn) {
	const debug = debugSettings(config)
	if (!debug.enabled) return
	try {
		const args = exec?.arguments ?? {}
		// 2026-11-11：launched（启动前读到的脚本）优先留正文，留不到才退回命中片段——
		// 只存 clip 过的片段会让复盘侧无法复核（折行/反引号被压平后就"看起来不命中"了）。
		let raw
		if (hit.where === 'command') raw = String(args.command ?? '')
		else if (hit.where === 'script') raw = String(args.content ?? '')
		else if (hit.where === 'patch') raw = String(args.input ?? args.patch ?? '')
		else raw = ''
		if (hit.where === 'launched' && hit.path) {
			try {
				// 用与扫描同一套 BOM/UTF-16 解码，避免把 UTF-16LE 脚本记成乱码（复核时会"看起来不命中"）
				const body = await readScriptText(hit.path, config.maxScriptBytes ?? DEFAULT_CONFIG.maxScriptBytes)
				raw = body === undefined ? '' : body
			} catch {
				raw = ''
			}
			if (raw === '') raw = String(hit.snippet ?? '')
		}
		if (raw === '') raw = String(hit.snippet ?? '')
		const capped = raw.length > debug.maxTextBytes ? raw.slice(0, debug.maxTextBytes) : raw
		const record = {
			at: new Date().toISOString(),
			session: sessionKeyOf(exec),
			tool: String(exec?.name ?? ''),
			where: hit.where,
			path: hit.path ?? null,
			rule: { id: hit.rule?.id ?? '', label: hit.rule?.label ?? '' },
			risks: Array.isArray(hit.risks) ? hit.risks : [],
			workspace: root,
			snippet: hit.snippet ?? '',
			text: debug.redact ? redactSecrets(capped) : capped,
			textBytes: raw.length,
			truncated: raw.length > capped.length,
		}
		await mkdir(debug.dir, { recursive: true })
		await appendFile(join(debug.dir, `blocks-${localDateStamp()}.jsonl`), `${JSON.stringify(record)}\n`, 'utf8')
	} catch (error) {
		warn?.(`dsh-trash-guard: 调试日志写入失败（不影响拦截）：${error instanceof Error ? error.message : String(error)}`)
	}
}

function isScriptPath(path) {
	const lower = String(path).toLowerCase()
	const dot = lower.lastIndexOf('.')
	return dot >= 0 && SCRIPT_EXT.has(lower.slice(dot))
}

/** 从一条命令里抠出被**启动**的脚本文件（只认调用位，不认"被读取的路径"）。 */
function launchedScriptRefs(command) {
	const refs = new Set()
	const text = String(command)
	const push = (token) => {
		if (token === undefined) return
		const trimmed = token.trim()
		// 引号里可能是一整条子命令（cmd 语义："build.bat arg1"），首词才是程序
		for (const part of [trimmed, trimmed.split(/\s+/)[0]]) {
			if (part.length > 0 && isScriptPath(part)) refs.add(part)
		}
	}
	const TOKEN = String.raw`(?:"([^"\n]+)"|'([^'\n]+)'|([^\s"'|;&()<>,]+))`
	// 1) 语句起始就是脚本本身：`.\x.ps1`、`& .\x.ps1`、`x.bat`
	for (const match of text.matchAll(new RegExp(String.raw`(?:^|[\n;|&(])\s*&?\s*${TOKEN}`, 'g'))) push(match[1] ?? match[2] ?? match[3])
	// 2) `-File` / `-f`：允许 `-File x.ps1`、`-File 'x.ps1'`、`@('-File','x.ps1')` 三种写法
	for (const match of text.matchAll(new RegExp(String.raw`-f(?:ile)?["']?\s*[,;]?\s*${TOKEN}`, 'gi'))) push(match[1] ?? match[2] ?? match[3])
	// 3) `cmd /c` / `cmd /k` 之后的 token
	for (const match of text.matchAll(new RegExp(String.raw`cmd(?:\.exe)?\s+[^\n]*?\/(?:c|k)\s+${TOKEN}`, 'gi'))) push(match[1] ?? match[2] ?? match[3])
	// 4) `call` / `start` 之后的 token
	for (const match of text.matchAll(new RegExp(String.raw`\b(?:call|start)\s+${TOKEN}`, 'gi'))) push(match[1] ?? match[2] ?? match[3])
	return [...refs]
}

/**
 * 归一化脚本文本里的路径写法：`$PSScriptRoot\x.ps1`、`%~dp0x.bat`、`.\x.ps1`
 * 都还原成相对当前脚本目录的普通相对路径（不做变量展开，只剥已知前缀）。
 */
function normalizeScriptRef(ref) {
	return String(ref)
		.replace(/^["']|["']$/g, '')
		.replace(/^(?:\$PSScriptRoot|\$\{PSScriptRoot\}|\$here|%~dp0)[\\/]/i, '')
		.replace(/^\.[\\/]/, '')
}

/**
 * 启动前扫描被引用的脚本正文（`pwsh -File x.ps1`、`cmd /c build.bat`、`& .\x.ps1`）。
 * 这是"模型直接跑一个现成脚本"的唯一可见点——命令文本里只有文件名，正文在启动前读出来看。
 * 递归跟随脚本之间的调用（深度 ≤2、最多 24 个文件），跟随路径相对脚本所在目录解析。
 * @returns {{where:'launched', path:string, rule:object, snippet:string} | undefined}
 */
async function scanLaunchedScripts(command, baseDir, config, seen = new Set(), depth = 0) {
	if (depth > 2 || seen.size > 24) return undefined
	for (const ref of launchedScriptRefs(command)) {
		const cleaned = normalizeScriptRef(ref)
		const target = isAbsolute(cleaned) ? resolve(cleaned) : resolve(baseDir, cleaned)
		if (seen.has(target)) continue
		seen.add(target)
		if (!existsSync(target)) continue
		let body
		try {
			body = await readScriptText(target, config?.maxScriptBytes ?? DEFAULT_CONFIG.maxScriptBytes)
		} catch {
			continue
		}
		if (body === undefined) continue
		const rule = classifyScript(body, target)
		if (rule !== undefined) return { where: 'launched', path: target, rule, snippet: clip(matchedLine(body, rule.re)) }
		const nested = await scanLaunchedScripts(body, dirname(target), config, seen, depth + 1)
		if (nested !== undefined) return nested
	}
	return undefined
}

/**
 * 工作区根解析顺序：
 *  1. 显式配置 `workspace`；
 *  2. 会话当前工作目录（`workingDirectory` 服务，插件在多会话/换目录时靠它对齐）；
 *  3. `fs` 服务能给出进程路径就用；
 *  4. 最后退回宿主 cwd。
 */
function workspaceOf(ctx, config, exec) {
	if (typeof config.workspace === 'string' && config.workspace.length > 0) return resolve(config.workspace)
	const session = exec?.agent?.session
	if (session !== undefined) {
		try {
			const cwd = ctx.get?.('workingDirectory')?.get?.(session)
			if (typeof cwd === 'string' && cwd.length > 0) return resolve(cwd)
		} catch {
			/* 没有 workingDirectory 服务就往下走 */
		}
	}
	try {
		const fs = ctx.get?.('fs')
		if (fs !== undefined && typeof fs.processPath === 'function') return resolve(fs.processPath('.'))
	} catch {
		/* 没有 fs 服务就用 cwd */
	}
	return resolve(process.cwd())
}

/**
 * 判定一次工具调用的删除意图。
 * @returns {Promise<{where: string, rule: object, snippet: string, path?: string} | undefined>}
 */
async function inspect(tool, args, config, root) {
	const payload = args ?? {}
	if (tool === 'pwsh' || tool === 'bash') {
		const command = payload.command
		if (typeof command !== 'string' || command.length === 0) return undefined
		const rule = classifyText(command, config.allow)
		if (rule !== undefined) {
			// 2026-11-12：只写进文档的正文不算删除（详见 docPayloadOnly）。
			if (!docPayloadOnly(command)) return { where: 'command', rule, snippet: clip(command), risks: riskFactors(command) }
		}
		// 命令文本本身干净，但它启动的脚本可能不干净：启动前读正文。
		const launched = config.scanLaunchedScripts ? await scanLaunchedScripts(command, root ?? process.cwd(), config) : undefined
		return launched === undefined ? undefined : { ...launched, risks: riskFactors(launched.snippet) }
	}
	if (tool === 'write' && config.scanScriptWrites) {
		const path = payload.file_path ?? payload.path
		const content = payload.content
		if (typeof path === 'string' && typeof content === 'string' && isScriptPath(path)) {
			const rule = classifyScript(content, path)
			if (rule !== undefined) return { where: 'script', rule, path, snippet: clip(matchedLine(content, rule.re)), risks: riskFactors(content) }
		}
		return undefined
	}
	if (tool === 'apply_patch') {
		const body = String(payload.input ?? payload.patch ?? '')
		if (/^\*\*\*\s+Delete File:/im.test(body)) {
			return { where: 'patch', rule: { id: 'patch-delete', label: '*** Delete File:' }, snippet: clip(matchedLine(body, /^\*\*\*\s+Delete File:/im)), risks: riskFactors(body) }
		}
	}
	return undefined
}

/**
 * 2026-11-10：高危因子识别。**只用于把"这条指令危险在哪"写进拒绝文案，不参与 allow/deny 判定**，
 * 所以宁可少报也不误判——它不会改变任何放行结果。
 */
function riskFactors(text) {
	const t = String(text ?? '')
	const hits = []
	const push = (label) => {
		if (!hits.includes(label)) hits.push(label)
	}
	if (/(?:^|[\s"'=(,])(?:-recurse\b|-r\b|\/s\b|\/r\b|--recursive\b)/i.test(t)) push('递归遍历（-Recurse / /s / -r）')
	if (/(?:^|[\s"'=(,])\*|[*?][\\/"'\s]|\\\*/i.test(t)) push('通配符（* / ?）——一次可能命中整棵目录树')
	if (/(?:^|[^A-Za-z0-9_])[A-Za-z]:[\\/](?=$|[\s"'`,;|)&])/.test(t)) push('盘符根路径（如 C:\\ / E:\\，会波及整个盘）')
	else if (/(?:^|[^A-Za-z0-9_])[A-Za-z]:[\\/]/.test(t)) push('盘符绝对路径（目标已指向具体位置，确认是否走出当前目录）')
	if (/%systemdrive%|%homedrive%|%userprofile%|\$env:systemdrive|\$env:userprofile/i.test(t)) push('环境变量根（可能展开成整个盘或家目录）')
	if (/(?:\bfor\b|\bforeach\b|ForEach-Object|\bwhile\b|\bdo\s*\{|%\w+\s+in\s+\()/i.test(t)) push('循环构造（for / foreach / while / 管道内循环）')
	if (/(?<!\|)\|(?!\|)/.test(t)) push('管道串联（一条命令串多个动作，实际范围难读）')
	if (/(?:^|[\s"',])(?:-force\b|\/f\b|\/q\b|--force\b|-rf\b|-fr\b)/i.test(t)) push('强制开关（-Force / /f / /q / -rf）——跳过确认直接执行')
	if (/-encodedcommand\b/i.test(t)) push('编码载荷（-EncodedCommand，正文不可审计）')
	if (/\.\.(?:[\\/]|$)/.test(t)) push('上溯路径（..）——可能跳出当前目录')
	return hits
}

/** 给模型的拒绝文案：三段式——①为什么被拦 ②换成什么 ③提交前必须自查什么。 */
function denialText(hit, trashDir) {
	const target = hit.where === 'command'
		? '命令'
		: hit.where === 'launched'
			? `要启动的脚本 ${hit.path}（启动前已读正文）`
			: `脚本 ${hit.path} 的正文`
	// 2026-11-10：三段式拒绝文案（①为什么被拦 ②换成什么 ③提交前必须自查什么），并按用户要求把
	// "递归/通配/根路径/循环"这类会无界放大的因子点名写出来；同时保留「唯一落点 + 唯一降级」结构。
	const risks = Array.isArray(hit.risks) ? hit.risks : []
	const riskLine = risks.length > 0
		? `【风险】本条指令被识别出的放大因子：${risks.join('；')}。这些因子会让"删一个"变成"删一片"，务必在替换指令里全部消掉。`
		: '【风险】本条指令未识别出递归/通配类放大因子，但它仍是删除类动作，同样不放行。'
	return [
		`【1｜你被拦截了】权限拒绝（DENY / code=DELETE_BLOCKED），本次调用没有执行：${target}里出现删除类高危动作（${hit.rule.id} / ${hit.rule.label}）。命中片段：${hit.snippet}`,
		riskLine,
		`【2｜换成这个】唯一合法做法（不要自选别的方案、不要跳步）：把"删"改成"移进垃圾箱" —— ${TRASH_TOOL}({ paths: ["<路径>", ...], note: "<为什么要移除>" })。落点固定 ${trashDir}/<时间戳>/，同时追加 ${trashDir}/manifest.jsonl，这是本工作区唯一的删除实现。需要"清空/覆盖某文件"也只能先 ${TRASH_TOOL} 原件、再写新文件，禁止就地覆盖。`,
		`【3｜提交前必须自查（逐条写下结论再动手）】a) 范围有界吗：路径是否只指向本次真要动的目标？有没有盘符根、..、\`*\`/\`?\` 通配、\`-Recurse\`/\`/s\` 这类会扩散到整棵树的东西？b) 有循环吗：\`for\`/\`foreach\`/\`while\`/管道串联会不会对"遍历出来的每一项"重复执行、越滚越大？c) 转义会让范围变形吗：引号、\`$()\`、反引号折行、变量展开会不会把字面路径变成通配或另一条路径（PowerShell 转义是最常见的事故源）？d) 会碰到恢复源吗：目标里有没有 ${trashDir}？垃圾箱是恢复源，绝不能被当作移动/清空对象。e) 可回滚吗：${trashDir} 里有副本、manifest 里有记录，才算可回滚。`,
		`【纪律】原样重试或换写法绕过都会得到同样拒绝，不要连试；只有 ${TRASH_TOOL} 返回 failed 时才停止并上报（把失败清单：路径＋原始错误，原样交给用户），不要改名加 .bak、不要换别的删除写法。`,
		`【批量还原】恢复一律以 ${trashDir}/manifest.jsonl 为唯一台账：\`${RESTORE_TOOL}\`({ ids: [...] }) 传多个 id，或 \`${RESTORE_TOOL}\`({ paths: [...] }) 按原始路径批量还原（原位置被占用会记 failed，不会覆盖）。`,
	].join('\n')
}

/** 追加一行 JSON 到 manifest（append-only，restore 也只追加）。 */
async function appendManifest(manifestPath, records) {
	await mkdir(dirname(manifestPath), { recursive: true })
	await appendFile(manifestPath, records.map((record) => `${JSON.stringify(record)}\n`).join(''), 'utf8')
}

/** 读回 manifest：返回 not-yet-restored 的 trash 记录。 */
async function readManifest(manifestPath) {
	if (!existsSync(manifestPath)) return []
	const text = await readFile(manifestPath, 'utf8')
	const entries = []
	const restored = new Set()
	for (const line of text.split(/\r?\n/)) {
		if (line.trim().length === 0) continue
		let record
		try {
			record = JSON.parse(line)
		} catch {
			continue
		}
		if (record.op === 'restore' && typeof record.id === 'string') restored.add(record.id)
		// 2026-11-12：只把 op='trash'（真正的移入）当作可恢复条目；
		// op='version' 是编辑产生的旧版本快照，不参与 restore，也不该占「可恢复」列表。
		else if (record.op === 'trash' && typeof record.id === 'string') entries.push(record)
	}
	return entries.filter((entry) => !restored.has(entry.id))
}

const text = (value) => [{ type: 'text', text: value }]

/**
 * 结案一个影子：trash 工具已经把原文件移走，若还留着影子，下一轮 sweep 会
 * 把同一次删除再记一遍。这里把影子挪进 `_trash/.retired/`（同一 inode，不费字节），
 * 让 sweep 只扫 `.shadow/`，从而"一次删除一条记录"。
 */
async function retireShadow(root, trashRoot, target) {
	const rel = relative(root, target)
	if (rel.length === 0 || rel.startsWith('..') || isAbsolute(rel)) return
	const mirror = join(trashRoot, '.shadow', rel)
	if (!existsSync(mirror)) return
	const dest = join(trashRoot, '.retired', stampOf(), `${Date.now()}-${basename(target)}`)
	try {
		await mkdir(dirname(dest), { recursive: true })
		await rename(mirror, dest)
	} catch {
		/* 结案失败不影响主流程（最坏是下一轮多一条同内容记录） */
	}
}

/** 路径里是否有任何一段等于垃圾箱目录名，或首段在跳过名单里。 */
function isSkipped(rel, trashDir, skipDirs) {
	const segments = rel.split(/[\\/]/)
	if (segments.includes(trashDir)) return true
	// 2026-11-12：以前只比对首段，导致 `插件发布\x\.git\refs\...` 这类嵌套目录仍被建影、
	// 每次 git 提交都在 _trash 里留噪声。改为任意层级命中即跳过。
	return segments.some((segment) => skipDirs.includes(segment))
}

/** 广度不限、深度优先地收集文件相对路径（只收普通文件，上限 maxFiles）。 */
async function walkFiles(root, shouldSkip, maxFiles) {
	const found = []
	const stack = ['']
	while (stack.length > 0 && found.length < maxFiles) {
		const current = stack.pop()
		let entries
		try {
			entries = await readdir(current.length === 0 ? root : join(root, current), { withFileTypes: true })
		} catch {
			continue
		}
		for (const entry of entries) {
			const rel = current.length === 0 ? entry.name : join(current, entry.name)
			if (shouldSkip(rel)) continue
			if (entry.isDirectory()) stack.push(rel)
			else if (entry.isFile()) found.push(rel)
		}
	}
	return found
}

/**
 * 影子同步：把工作区每个文件做成 `_trash/.shadow/` 下的硬链接。
 * 硬链接与原文件同一 inode —— 原文件被删后链接仍然持有内容，
 * 而且从此以后对原文件的**就地改写**会同步反映到影子上，所以影子里的内容
 * 永远是"最后一次落盘时的样子"，正是删除瞬间要留住的那份字节。
 * 不复制、不删除：只 link() 与 rename()。
 * @returns {{linked: number, refreshed: number, kept: number, truncated: boolean}}
 */
async function shadowSync(root, trashRoot, config, log, cache = new Map()) {
	const store = join(trashRoot, '.shadow')
	// 影子库被清掉过（或首次运行）→ 清空 mtime 缓存，强制重建一遍
	if (!existsSync(store)) cache.clear()
	const shadow = config.shadow
	const stats = { linked: 0, refreshed: 0, kept: 0, truncated: false, walkedDirs: 0, skippedDirs: 0 }
	const files = []
	// 目录 mtime 门槛：一个文件被增/删/改名都会抬升它**父目录**的 mtime，
	// 所以"父目录 mtime 没变"就等于"这个目录下的文件集合没变"，不必逐个 stat 子项。
	// 仍然要 readdir 才下得去（子目录 mtime 只反映它自己那一层）。
	const stack = ['']
	while (stack.length > 0 && files.length < shadow.maxFiles) {
		const relDir = stack.pop()
		const absDir = relDir.length === 0 ? root : join(root, relDir)
		let info
		try {
			info = await stat(absDir)
		} catch {
			continue
		}
		const stamp = String(info.mtimeMs)
		const changed = cache.get(absDir) !== stamp
		if (changed) cache.set(absDir, stamp)
		stats.walkedDirs += 1
		if (!changed) stats.skippedDirs += 1
		let entries
		try {
			entries = await readdir(absDir, { withFileTypes: true })
		} catch {
			continue
		}
		for (const entry of entries) {
			const rel = relDir.length === 0 ? entry.name : join(relDir, entry.name)
			if (isSkipped(rel, config.trashDir, shadow.skipDirs)) continue
			if (entry.isDirectory()) stack.push(rel)
			else if (entry.isFile() && changed) files.push(rel)
		}
	}
	if (files.length >= shadow.maxFiles) stats.truncated = true
	const stamp = stampOf()
	const superseded = []
	let skippedLogs = 0
	for (const rel of files) {
		const live = join(root, rel)
		const mirror = join(store, rel)
		try {
			const liveStat = await stat(live, { bigint: true })
			if (existsSync(mirror)) {
				const mirrorStat = await stat(mirror, { bigint: true })
				if (mirrorStat.ino === liveStat.ino) {
					stats.kept += 1
					continue
				}
				// 影子的 inode 已经不是当前文件：旧版本按"被替换"收进垃圾箱，而不是丢弃。
				const dest = join(trashRoot, stamp, `s${stats.refreshed + 1}-${basename(rel)}`)
				await mkdir(dirname(dest), { recursive: true })
				await rename(mirror, dest)
				superseded.push({
					// 2026-11-12：`op: 'version'` 而不是 'trash'——这是"编辑产生的旧版本快照"，
					// 不是删除。混在 trash 流里会让删除台账被噪声淹没（本机实测 140 条里 123 条是它）。
					op: 'version',
					id: `${stamp}-r${stats.refreshed + 1}`,
					at: new Date().toISOString(),
					from: live,
					to: dest,
					kind: 'file',
					note: '影子层：该路径已被替换，旧版本收进垃圾箱（版本快照，不是删除）',
				})
				stats.refreshed += 1
			}
			await mkdir(dirname(mirror), { recursive: true })
			await link(live, mirror)
			stats.linked += 1
		} catch (error) {
			if (skippedLogs < 3) {
				skippedLogs += 1
				log?.(`shadow sync skipped ${rel}: ${error instanceof Error ? error.message : String(error)}`)
			}
		}
	}
	if (superseded.length > 0) await appendManifest(join(trashRoot, 'manifest.jsonl'), superseded)
	return stats
}

/**
 * 影子清扫：影子里有、工作区里已经没有的文件 = 一次删除。
 * 把影子（仍握着原 inode 的内容）移进 `_trash/<时间戳>/` 并登记 manifest。
 * 这一步与"谁删的、用什么语言删的"完全无关 —— 所以 .ps1、原生程序、.NET 直调都在网内。
 * @returns {{swept: number, truncated: boolean}}
 */
async function shadowSweep(root, trashRoot, config, cache = new Map()) {
	const store = join(trashRoot, '.shadow')
	if (!existsSync(store)) return { swept: 0, truncated: false }
	const shadow = config.shadow
	const stamp = stampOf()
	const records = []
	let swept = 0
	let mirrors = 0
	// 同样的目录 mtime 门槛：原目录 mtime 没变 → 该目录下不可能有文件消失，整目录跳过子项。
	const stack = ['']
	while (stack.length > 0 && mirrors < shadow.maxFiles) {
		const relDir = stack.pop()
		const storeDir = relDir.length === 0 ? store : join(store, relDir)
		const liveDir = relDir.length === 0 ? root : join(root, relDir)
		let entries
		try {
			entries = await readdir(storeDir, { withFileTypes: true })
		} catch {
			continue
		}
		let liveStamp = 'gone'
		try {
			liveStamp = String((await stat(liveDir)).mtimeMs)
		} catch {
			liveStamp = 'gone'
		}
		const changed = cache.get(liveDir) !== liveStamp
		if (changed) cache.set(liveDir, liveStamp)
		for (const entry of entries) {
			const rel = relDir.length === 0 ? entry.name : join(relDir, entry.name)
			if (entry.isDirectory()) {
				stack.push(rel)
				continue
			}
			if (!entry.isFile()) continue
			mirrors += 1
			if (!changed) continue
			if (existsSync(join(root, rel))) continue
			const mirror = join(storeDir, entry.name)
			const dest = join(trashRoot, stamp, `${swept + 1}-${basename(rel)}`)
			try {
				await mkdir(dirname(dest), { recursive: true })
				await rename(mirror, dest)
				swept += 1
				records.push({
					op: 'trash',
					id: `${stamp}-s${swept}`,
					at: new Date().toISOString(),
					from: join(root, rel),
					to: dest,
					kind: 'file',
					note: '影子层：检测到原文件已消失，内容已收进垃圾箱',
				})
			} catch {
				/* 单个影子移不动不影响其它条目 */
			}
		}
	}
	if (records.length > 0) await appendManifest(join(trashRoot, 'manifest.jsonl'), records)
	return { swept, truncated: mirrors >= shadow.maxFiles }
}


/** `trash` 工具定义（普通对象，registry 只校验 output{ schema, render } 与参数 JSON Schema）。 */
function trashTool(ctx, getConfig) {
	return {
		name: TRASH_TOOL,
		description:
			'Move files or directories into the workspace trash instead of deleting them. Every removal in this harness must go through here so it stays recoverable: items land in <workspace>/_trash/<UTC stamp>/ and are recorded in _trash/manifest.jsonl. Use restore with the returned ids to put them back. 中文（删除/删除文件/误删/清理/清空一切走这里，可恢复；不要用命令行删）。',
		parameters: {
			type: 'object',
			properties: {
				paths: {
					type: 'array',
					items: { type: 'string' },
					description: 'Absolute or workspace-relative paths to move into the trash.',
				},
				note: { type: 'string', description: 'Why these items are being removed; recorded in the manifest.' },
			},
			required: ['paths'],
		},
		output: {
			schema: {
				type: 'object',
				additionalProperties: false,
				properties: {
					stamp: { type: 'string' },
					trashDir: { type: 'string' },
					moved: {
						type: 'array',
						items: {
							type: 'object',
							additionalProperties: false,
							properties: {
								id: { type: 'string' },
								from: { type: 'string' },
								to: { type: 'string' },
								kind: { type: 'string' },
							},
						},
					},
					failed: {
						type: 'array',
						items: {
							type: 'object',
							additionalProperties: false,
							properties: {
								path: { type: 'string' },
								error: { type: 'string' },
							},
						},
					},
				},
			},
			render: (_args, value) => {
				const lines = value.moved.map((item) => `moved ${item.kind}: ${item.from} -> ${item.to} (id ${item.id})`)
				for (const item of value.failed) lines.push(`FAILED ${item.path}: ${item.error}`)
				lines.push(`${value.moved.length} moved, ${value.failed.length} failed; trash dir: ${value.trashDir}`)
				// 2026-11-10：失败只准「上报」，不准换第二套文件操作（改名/换写法），保证状态唯一、可批量恢复。
				if (value.failed.length > 0) {
					lines.push('失败不再升级为别的文件操作：不要改名散落文件、不要换别的删除写法重试；把上面的路径与原始错误原样交给用户。')
				}
				return text(lines.join('\n'))
			},
		},
		async execute(args, exec) {
			const config = getConfig()
			const root = workspaceOf(ctx, config, exec)
			const trashRoot = isAbsolute(config.trashDir) ? resolve(config.trashDir) : join(root, config.trashDir)
			const manifestPath = join(trashRoot, 'manifest.jsonl')
			const stamp = stampOf()
			const note = typeof args.note === 'string' ? args.note : ''
			const moved = []
			const failed = []
			const records = []
			for (const raw of args.paths) {
				const target = isAbsolute(raw) ? resolve(raw) : resolve(root, raw)
				let index = moved.length + failed.length + 1
				try {
					const info = await stat(target)
					if (isInside(trashRoot, target)) throw new Error('目标已经在垃圾箱里，不需要再移一次')
					// 2026-11-10：垃圾箱是恢复源，禁止把"包含 _trash 的目录"整体移走（否则恢复源一起消失）。
					if (isInside(target, trashRoot)) throw new Error(`目标包含垃圾箱目录 ${trashRoot}，拒绝对其整体移动`)
					if (config.denyOutsideWorkspace && !isInside(root, target)) throw new Error(`不在工作区 ${root} 内，拒绝移动`)
					const id = `${stamp}-${index}`
					const dest = join(trashRoot, stamp, `${index}-${basename(target)}`)
					await mkdir(dirname(dest), { recursive: true })
					// 同卷原子移动：这是"删除"的唯一实现方式，全程不调用删除 API。
					await rename(target, dest)
					await retireShadow(root, trashRoot, target)
					const kind = info.isDirectory() ? 'dir' : 'file'
					moved.push({ id, from: target, to: dest, kind })
					records.push({ op: 'trash', id, at: new Date().toISOString(), from: target, to: dest, kind, note })
				} catch (error) {
					failed.push({ path: raw, error: error instanceof Error ? error.message : String(error) })
				}
			}
			if (records.length > 0) await appendManifest(manifestPath, records)
			return { stamp, trashDir: trashRoot, moved, failed }
		},
	}
}

/** `restore` 工具定义：按 id 把垃圾箱里的条目原样移回。 */
function restoreTool(ctx, getConfig) {
	return {
		name: RESTORE_TOOL,
		description:
			'Move items from the workspace trash back to where they came from. Accepts the ids returned by the trash tool (latest ids are listed by reading _trash/manifest.jsonl when you pass ids: ["?"]). 中文（恢复/撤销删除/找回误删的文件；ids=["?"] 只列出最近可恢复条目）。',
		parameters: {
			type: 'object',
			properties: {
				ids: {
					type: 'array',
					items: { type: 'string' },
					description: 'Trash ids to restore. Pass ["?"] to list restorable ids instead of moving anything.',
				},
				paths: {
					type: 'array',
					items: { type: 'string' },
					description: '按原始路径批量还原（绝对或工作区相对，对应 manifest 里的 from 字段）；可与 ids 并用。',
				},
			},
			required: [],
		},
		output: {
			schema: {
				type: 'object',
				additionalProperties: false,
				properties: {
					restored: {
						type: 'array',
						items: {
							type: 'object',
							additionalProperties: false,
							properties: {
								id: { type: 'string' },
								from: { type: 'string' },
								to: { type: 'string' },
							},
						},
					},
					failed: {
						type: 'array',
						items: {
							type: 'object',
							additionalProperties: false,
							properties: { id: { type: 'string' }, error: { type: 'string' } },
						},
					},
					available: {
						type: 'array',
						items: {
							type: 'object',
							additionalProperties: false,
							properties: { id: { type: 'string' }, path: { type: 'string' } },
						},
					},
				},
			},
			render: (_args, value) => {
				const lines = value.restored.map((item) => `restored ${item.id}: ${item.from}`)
				for (const item of value.failed) lines.push(`FAILED ${item.id}: ${item.error}`)
				if (value.available.length > 0) lines.push(`restorable ids: ${value.available.map((entry) => `${entry.id} (${entry.path})`).join(', ')}`)
				return text(lines.join('\n') || '(nothing restored)')
			},
		},
		async execute(args, exec) {
			const config = getConfig()
			const root = workspaceOf(ctx, config, exec)
			const trashRoot = isAbsolute(config.trashDir) ? resolve(config.trashDir) : join(root, config.trashDir)
			const manifestPath = join(trashRoot, 'manifest.jsonl')
			const entries = await readManifest(manifestPath)
			const available = entries.slice(-20).map((entry) => ({ id: entry.id, path: entry.from }))
			const restored = []
			const failed = []
			// 2026-11-10：支持按原始路径批量还原（paths），与 ids 并用；两者都空时报错而不是静默成功。
			const ids = Array.isArray(args.ids) ? args.ids : []
			const wantedPaths = Array.isArray(args.paths) ? args.paths : []
			const targets = []
			for (const id of ids) {
				if (id === '?') continue
				if (!targets.includes(id)) targets.push(id)
			}
			for (const raw of wantedPaths) {
				const wanted = isAbsolute(raw) ? resolve(raw) : resolve(root, raw)
				const found = entries.find((candidate) => resolve(candidate.from) === wanted)
				if (found === undefined) failed.push({ id: raw, error: `没有与该路径匹配的可恢复记录：${wanted}` })
				else if (!targets.includes(found.id)) targets.push(found.id)
			}
			if (targets.length === 0 && failed.length === 0) failed.push({ id: '<none>', error: '需要 ids 或 paths 至少一项' })
			for (const id of targets) {
				const entry = entries.find((candidate) => candidate.id === id)
				if (entry === undefined) {
					failed.push({ id, error: '没有这个 id（可能已经恢复过）' })
					continue
				}
				try {
					if (!existsSync(entry.to)) throw new Error(`垃圾箱里已经没有 ${entry.to}`)
					if (existsSync(entry.from)) throw new Error(`原位置已被占用：${entry.from}`)
					await mkdir(dirname(entry.from), { recursive: true })
					await rename(entry.to, entry.from)
					restored.push({ id, from: entry.from, to: entry.to })
				} catch (error) {
					failed.push({ id, error: error instanceof Error ? error.message : String(error) })
				}
			}
			if (restored.length > 0) {
				await appendManifest(manifestPath, restored.map((item) => ({ op: 'restore', id: item.id, at: new Date().toISOString() })))
			}
			return { restored, failed, available }
		},
	}
}

/**
 * 挂载插件。
 * @param ctx - cordis 上下文，注入 `tools`。
 * @param userConfig - 见 DEFAULT_CONFIG。
 */
export function apply(ctx, userConfig) {
	const config = { ...DEFAULT_CONFIG, ...(userConfig ?? {}) }
	config.allow = Array.isArray(config.allow) ? config.allow : []
	config.shadow = { ...DEFAULT_CONFIG.shadow, ...(userConfig?.shadow ?? {}) }
	const current = () => config

	const warn = (message) => ctx.logger?.warn?.(message)
	const trashRootOf = (exec) =>
		isAbsolute(config.trashDir) ? resolve(config.trashDir) : join(workspaceOf(ctx, config, exec), config.trashDir)

	// 影子层串行执行：并行工具调用不能同时扫/同建同一批链接。
	let shadowChain = Promise.resolve()
	// 目录 mtime 缓存：分 sync / sweep 两份，互不污染（sweep 先跑，不能把"已看过"喂给 sync）
	const syncCache = new Map()
	const sweepCache = new Map()
	const runShadow = (exec) => {
		shadowChain = shadowChain.then(async () => {
			const root = workspaceOf(ctx, config, exec)
			const trashRoot = trashRootOf(exec)
			try {
				const sweep = await shadowSweep(root, trashRoot, config, sweepCache)
				if (sweep.swept > 0) ctx.logger?.info?.(`dsh-trash-guard: 影子层收进 ${sweep.swept} 个被删条目 -> ${trashRoot}`)
				const sync = await shadowSync(root, trashRoot, config, warn, syncCache)
				if (sync.truncated) warn(`dsh-trash-guard: 影子扫描达到 maxFiles 上限（${config.shadow.maxFiles}），本轮未全量建影；调大 shadow.maxFiles 或缩小工作区`)
			} catch (error) {
				warn(`dsh-trash-guard: 影子层跳过本轮（${error instanceof Error ? error.message : String(error)}）`)
			}
		})
		return shadowChain
	}

	// 1) 删除意图 → deny（不执行，让模型改道 trash）；顺带维护影子层。
	ctx.on(
		'tools/pre-execute',
		async (exec, next) => {
			const toolName = exec?.name
			if (toolName !== TRASH_TOOL && toolName !== RESTORE_TOOL) {
				const hit = await inspect(toolName, exec?.arguments, config, workspaceOf(ctx, config, exec))
				if (hit !== undefined) {
					// 2026-11-11：先落调试日志（默认开），再返回 deny；写日志失败不影响拒绝。
					await writeBlockRecord(config, exec, hit, workspaceOf(ctx, config, exec), warn)
					return {
						kind: 'deny',
						reason: denialText(hit, trashRootOf(exec)),
						info: { name: 'TRASH_GUARD', code: 'DELETE_BLOCKED' },
					}
				}
			}
			if (config.shadow.enabled && MUTATING_TOOLS.has(toolName)) await runShadow(exec)
			return next()
		},
		{ prepend: true },
	)

	// 2) 唯一的"删除"实现：移动进垃圾箱。
	ctx.tools.register(trashTool(ctx, current))
	ctx.tools.register(restoreTool(ctx, current))
	// 2026-11-11：启动即心跳，让夜间分析能判断"运行态是否最新版"（否则只能靠重启才验证得到）。
	writeHeartbeat(config, warn)
	ctx.logger?.info?.('dsh-trash-guard: delete intents rerouted to workspace trash')
}

/** 仅供单元测试使用：导出纯函数，不影响加载。 */
export const __internals = {
	classifyText, classifyScript, classifyBatch, launchedScriptRefs, scanLaunchedScripts, normalizeScriptRef,
	inspect, isInside, isScriptPath, clip, matchedLine, RULES, BAT_RULE,
	riskFactors, denialText, normalizeTemplate, docPayloadOnly,
	debugSettings, redactSecrets, localDateStamp, sessionKeyOf, writeBlockRecord, writeHeartbeat, DEFAULT_DEBUG_DIR,
	shadowSync, shadowSweep, isSkipped, walkFiles, DEFAULT_CONFIG,
}
