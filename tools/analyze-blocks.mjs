// theme=trash-guard status=active date=2026-11-11
// 夜间分析：读调试日志（默认 E:\dsh-trash-guard-logs），统计拦截分布并挑出疑似误判样本。
// 用法：
//   node tools/analyze-blocks.mjs                 # 增量：只分析上次分析之后的新记录
//   node tools/analyze-blocks.mjs --all           # 全量重算（不移动 lastAnalyzedAt 之外的语义）
//   node tools/analyze-blocks.mjs --since 2026-11-01T00:00:00Z
//   node tools/analyze-blocks.mjs --dir E:\dsh-trash-guard-logs --out <报告路径>
// 退出码：0 正常（含"没有新记录"）；2 目录不存在且没有任何日志；1 参数/读取错误。
import { existsSync, readdirSync, readFileSync, mkdirSync, statSync, writeFileSync } from 'node:fs'
import { dirname, join, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'

const HERE = dirname(fileURLToPath(import.meta.url))
const PLUGIN = resolve(HERE, '..')
const mod = await import(new URL('../index.js', import.meta.url).href)
const { classifyText, classifyScript, classifyBatch, DEFAULT_DEBUG_DIR } = mod.__internals

function parseArgs(argv) {
	const out = { dir: DEFAULT_DEBUG_DIR, since: undefined, all: false, nightly: false, out: undefined, json: false, trash: undefined }
	for (let i = 0; i < argv.length; i += 1) {
		const a = argv[i]
		if (a === '--dir') out.dir = argv[++i]
		else if (a === '--since') out.since = argv[++i]
		else if (a === '--out') out.out = argv[++i]
		else if (a === '--trash') out.trash = argv[++i]
		else if (a === '--all') out.all = true
		else if (a === '--nightly') out.nightly = true
		else if (a === '--json') out.json = true
		else if (a === '--help' || a === '-h') {
			console.log('node tools/analyze-blocks.mjs [--dir <dir>] [--since <ISO>|--nightly|--all] [--trash <workspace/_trash/manifest.jsonl>] [--out <path>] [--json]')
			process.exit(0)
		}
	}
	out.dir = resolve(out.dir)
	if (out.trash !== undefined) out.trash = resolve(out.trash)
	return out
}

const args = parseArgs(process.argv.slice(2))
const statePath = join(args.dir, '_state.json')
const reportsDir = join(args.dir, 'reports')

if (!existsSync(args.dir)) {
	console.error(`目录不存在：${args.dir}（本插件还没拦过任何东西，或 debug.dir 配错）`)
	process.exit(2)
}

const state = existsSync(statePath) ? JSON.parse(readFileSync(statePath, 'utf8')) : {}
const since = args.all ? new Date(0) : (args.since ? new Date(args.since) : (state.lastAnalyzedAt ? new Date(state.lastAnalyzedAt) : new Date(Date.now() - 7 * 86400000)))
// 2026-11-12：夜间复盘要"整夜"而不是"距上次运行几分钟"。--nightly 按本地日 0 点起算，
// 避免增量游标把窗口切成 5 分钟、让「漏报候选 0」被误读成整夜 0 条。
const effectiveSince = args.nightly
	? new Date(new Date().setHours(0, 0, 0, 0))
	: since

const files = readdirSync(args.dir).filter((f) => /^blocks-\d{4}-\d{2}-\d{2}\.jsonl$/.test(f)).sort()
const records = []
const parseErrors = []
for (const file of files) {
	const lines = readFileSync(join(args.dir, file), 'utf8').split(/\r?\n/)
	lines.forEach((line, index) => {
		if (line.trim() === '') return
		try {
			const rec = JSON.parse(line)
			rec.__file = file
			rec.__line = index + 1
			records.push(rec)
		} catch (error) {
			parseErrors.push({ file, line: index + 1, error: String(error && error.message ? error.message : error) })
		}
	})
}

const fresh = records.filter((r) => new Date(r.at) > effectiveSince)

/**
 * 2026-11-11：漏报候选。
 * 拦截日志只记"被拦住"的调用，**漏掉的根本不会产生 blocks 记录**；唯一可自动采集的漏报信号在
 * `_trash/manifest.jsonl`：`note` 含"原文件已消失"的条目 = 文件不是走 trash 工具消失的
 * （可能是①规则没覆盖的新写法 ②AI 换写法绕过成功 ③正常的移动/重命名 ④git 等工具改写内部文件）。
 * `note` 含"已被替换"的是编辑产生的旧版本快照，不算漏报，单独计数。
 */
/**
 * 2026-11-11：运行态自检。
 * 插件改完代码不重启，磁盘是新的、进程里还是旧的，日志可能一行都不写——此时"0 条"绝不能读成
 * "零拦截"（规则27：本轮 0 条要附真实原因）。判据只有心跳能提供：
 * 心跳里记的是**被加载的那个模块文件**的 mtime，与磁盘当前 mtime 比对即可判定新旧。
 */
const pluginPath = fileURLToPath(new URL('../index.js', import.meta.url))
const heartbeatPath = join(args.dir, '_heartbeat.json')
let diskMtimeMs
try {
	diskMtimeMs = statSync(pluginPath).mtimeMs
} catch {
	diskMtimeMs = undefined
}
let heartbeat
if (existsSync(heartbeatPath)) {
	try {
		heartbeat = JSON.parse(readFileSync(heartbeatPath, 'utf8'))
	} catch {
		heartbeat = undefined
	}
}
let runtimeStatus
let runtimeReason
if (heartbeat === undefined) {
	runtimeStatus = 'unknown'
	runtimeReason = '没有心跳文件：当前进程里的插件可能是旧版本（未含心跳）、或从未成功挂载。此状态下"0 条日志"不能当作"零拦截"。'
} else if (diskMtimeMs !== undefined && Math.abs(Number(heartbeat.moduleMtimeMs) - diskMtimeMs) > 1) {
	runtimeStatus = 'stale'
	runtimeReason = `运行中的插件不是磁盘上的最新版（心跳记录模块 mtime=${heartbeat.moduleMtimeMs}，磁盘=${diskMtimeMs}）。改动要重启 dsh 才生效；此状态下"0 条日志"不能当作"零拦截"。`
} else {
	runtimeStatus = 'fresh'
	runtimeReason = '运行中的插件与磁盘上的 index.js 一致（心跳 moduleMtimeMs 与磁盘 mtime 相符）。'
}

/** 0 条到底意味着什么：只有运行态确认一致，"0 条"才是可信的"本轮无拦截"。 */
const zeroMeaning = fresh.length === 0
	? (runtimeStatus === 'fresh'
		? '本轮无新增拦截（运行态已确认最新，结论可信）'
		: `本轮 0 条日志，但运行态未确认（${runtimeStatus}）——**不能判定为零拦截**，属"日志未生效/未确认"，不是"没发生"`)
	: undefined

const misses = []
const versionSnapshots = []
if (args.trash !== undefined) {
	if (existsSync(args.trash)) {
		for (const line of readFileSync(args.trash, 'utf8').split(/\r?\n/)) {
			if (line.trim() === '') continue
			let rec
			try {
				rec = JSON.parse(line)
			} catch {
				continue
			}
			// 2026-11-12：新版把"编辑产生的旧版本"记成 op='version'；旧版记成 op='trash' + note 含"已被替换"。
			// 两种都要认，否则升级当晚会把版本快照误计成删除。
			if (rec.op === 'version') {
				versionSnapshots.push(rec)
				continue
			}
			if (rec.op !== 'trash') continue
			const note = String(rec.note ?? '')
			if (note.includes('原文件已消失')) misses.push(rec)
			else if (note.includes('已被替换')) versionSnapshots.push(rec)
		}
	} else {
		console.error(`提醒：--trash 指定的台账不存在：${args.trash}`)
	}
}
const freshMisses = misses.filter((m) => new Date(m.at) > effectiveSince)
const bump = (map, key) => map.set(key, (map.get(key) ?? 0) + 1)
const byRule = new Map()
const byWhere = new Map()
const byTool = new Map()
const byDay = new Map()
const bySession = new Map()
const byWorkspace = new Map()
for (const r of fresh) {
	bump(byRule, r.rule?.id ?? '(unknown)')
	bump(byWhere, r.where ?? '(unknown)')
	bump(byTool, r.tool ?? '(unknown)')
	bump(byDay, String(r.at).slice(0, 10))
	bump(bySession, r.session || '(no-session)')
	bump(byWorkspace, r.workspace || '(unknown)')
}

/**
 * 按记录来源挑插件当时用的分类器：`.bat/.cmd` 用批处理规则、其它脚本用脚本规则、命令用命令规则。
 * （2026-11-11 修：首版一律用 classifyText，把 `if exist x del x`、`for /d %%i ... rd /s`、
 *  `Remove-`` 反引号续行这类**真危险**的批处理/折行写法全判成了"误判"。）
 */
function classifierFor(record) {
	const path = String(record.path ?? '')
	if (/\.(bat|cmd)$/i.test(path)) return (text) => classifyBatch(text)
	if (record.where === 'script' || record.where === 'launched') return (text) => classifyScript(text, path || 'x.ps1')
	return (text) => classifyText(text, [])
}

/** 去掉引号与 # 注释后的文本（用于判断"是否只是提到删除词"）。 */
function stripMentions(text) {
	return String(text ?? '')
		.replace(/`[^`\n]*`/g, '``')
		.replace(/"[^"\n]*"/g, '""')
		.replace(/'[^'\n]*'/g, "''")
		.replace(/#.*$/gm, '')
		.replace(/<#[^#]*#>/g, '')
}

/** 引号里的内容可能正是实际执行体（cmd /c、bash -c、解释器 -c），这类不能判成误判。 */
const INLINE_EXEC = /\b(?:cmd(?:\.exe)?\s*\/[ck]\b|(?:bash|sh|zsh)\s+-c\b|pwsh(?:\.exe)?\b|powershell(?:\.exe)?\b|python[0-9.]*\s+-[ce]\b|node\s+-e\b|perl\s+-e\b|ruby\s+-e\b)/i

const candidates = []
const needsHuman = []
const repeatMap = new Map()
for (const r of fresh) {
	const full = String(r.text ?? '')
	const snippet = String(r.snippet ?? '')
	// 复核正文：默认用记录里的 text；只有"旧格式只剩片段"或"正文被截断"时才退回 snippet，
	// 并把这些情况记为**模糊点**（需要人工），不要把它们算成"误判"。
	let text = full
	const info = []
	const ambiguous = []
	if (r.where === 'launched' && (full === '' || full === snippet)) {
		text = snippet
		ambiguous.push('日志里只有命中片段（旧格式），无法复核全文')
	}
	if (r.truncated && snippet !== '') {
		text = snippet
		ambiguous.push('日志正文按 maxTextBytes 截断，复核改用 snippet')
	}
	const norm = full.replace(/\s+/g, ' ').trim()
	bump(repeatMap, `${r.rule?.id}\u0000${r.session || '(no-session)'}\u0000${norm.slice(0, 300)}`)
	const classify = classifierFor(r)
	const reasons = []
	const partialEvidence = ambiguous.length > 0
	if (classify(stripMentions(text)) === undefined) {
		if (INLINE_EXEC.test(text)) ambiguous.push('去掉引号后不命中，但含 cmd /c、-c、pwsh 等"引号内即执行体"形态 → 不能判误判')
		else if (partialEvidence) ambiguous.push('证据不完整（只有片段或被截断），无法判断"是否只是提到删除词"')
		else reasons.push('去掉引号/注释后不再命中任何规则（疑似"仅在字符串或注释里提到删除词"）')
	}
	if (/\B--help\b|\s-h\b|--dry-?run\b|-WhatIf\b|--version\b/i.test(text)) reasons.push('命令带 --help/--dry-run/-WhatIf/--version 一类只读开关')
	if (r.where === 'launched' && r.path && !existsSync(r.path)) ambiguous.push('被拦脚本现在已不存在（不影响当时判定，仅供参考）')
	if (r.where === 'script' && r.path && !/\.(ps1|psm1|psd1|bat|cmd|sh|bash|zsh|py|js|mjs|cjs|ts|vbs|reg)$/i.test(r.path)) reasons.push('被拦的写入路径不是脚本后缀（写入侧误判）')
	if (reasons.length > 0) candidates.push({ r, reasons, notes: [...info, ...ambiguous] })
	else if (ambiguous.length > 0) needsHuman.push({ r, notes: [...info, ...ambiguous] })
}

const repeats = [...repeatMap.entries()].filter(([, n]) => n >= 3).sort((a, b) => b[1] - a[1])

const fmtTable = (map, header) => {
	const rows = [...map.entries()].sort((a, b) => b[1] - a[1])
	if (rows.length === 0) return `_（无）_\n`
	return `| ${header} | 次数 |\n|---|---|\n` + rows.map(([k, v]) => `| \`${String(k).replace(/\|/g, '\\|')}\` | ${v} |`).join('\n') + '\n'
}

const now = new Date()
const stamp = `${now.getFullYear()}${String(now.getMonth() + 1).padStart(2, '0')}${String(now.getDate()).padStart(2, '0')}-${String(now.getHours()).padStart(2, '0')}${String(now.getMinutes()).padStart(2, '0')}`
const reportPath = args.out ? resolve(args.out) : join(reportsDir, `analyze-${stamp}.md`)

const lines = []
lines.push(`# 拦截复盘报告 ${now.toISOString()}`)
lines.push('')
lines.push(`- 日志目录：\`${args.dir}\``)
lines.push(`- 分析窗口：\`${effectiveSince.toISOString()}\` 之后（${args.all ? '全量' : args.nightly ? '本日 0 点起（--nightly）' : '增量'}）`)
lines.push(`- 日志文件 ${files.length} 个；记录 ${records.length} 条；本次新记录 **${fresh.length}** 条；解析失败 ${parseErrors.length} 条`)
if (zeroMeaning !== undefined) lines.push(`- **本次 0 条的含义**：${zeroMeaning}`)
lines.push('')
lines.push('## 运行态自检（判断"0 条"可信不可信）')
lines.push(`- 结论：**${runtimeStatus}**`)
lines.push(`- 说明：${runtimeReason}`)
lines.push(`- 磁盘 index.js mtime：\`${diskMtimeMs ?? '读取失败'}\``)
if (heartbeat === undefined) lines.push('- 心跳：**缺失**（`_heartbeat.json` 不存在）')
else {
	lines.push(`- 心跳时间：\`${heartbeat.at}\`（pid ${heartbeat.pid}，node ${heartbeat.node}）`)
	lines.push(`- 心跳记录的被加载模块：\`${heartbeat.modulePath}\`（mtime \`${heartbeat.moduleMtimeMs}\`，${heartbeat.moduleBytes} B）`)
}
lines.push('')
lines.push('## 新拦截按规则')
lines.push(fmtTable(byRule, '规则 id'))
lines.push('## 新拦截按入口')
lines.push(fmtTable(byWhere, 'where'))
lines.push('## 新拦截按工具')
lines.push(fmtTable(byTool, 'tool'))
lines.push('## 新拦截按日期')
lines.push(fmtTable(byDay, '日期'))
lines.push('## 新拦截按会话')
lines.push(fmtTable(bySession, 'session'))
lines.push('')
lines.push('## 疑似误判候选')
if (candidates.length === 0) {
	lines.push('_本次没有命中启发式误判信号。_')
} else {
	lines.push(`共 ${candidates.length} 条，逐条给出理由（原文按 4000 字符窗口展示，长文本标注截断）：`)
	lines.push('')
	candidates.slice(0, 40).forEach(({ r, reasons }, i) => {
		const text = String(r.text ?? '')
		const shown = text.length > 4000 ? `${text.slice(0, 4000)}\n…（已截断至 4000 字符，全文见 ${r.__file}:${r.__line}，原长 ${text.length}）` : text
		lines.push(`### ${i + 1}. \`${r.rule?.id}\` @ ${r.at} ｜${r.where}｜${r.path ?? '-'}`)
		lines.push(`- 理由：${reasons.join('；')}`)
		lines.push('- 原文：')
		lines.push('```text')
		lines.push(shown)
		lines.push('```')
		lines.push('')
	})
	if (candidates.length > 40) lines.push(`> 另有 ${candidates.length - 40} 条未展开（见 jsonl 原文）。`)
}
lines.push('## 需人工确认（启发式拿不准，不能当误判也不能当无事）')
if (needsHuman.length === 0) {
	lines.push('_无。_')
} else {
	lines.push(`共 ${needsHuman.length} 条。按原因聚合（每组最多展开 2 条样本，其余见 jsonl 原文）：`)
	lines.push('')
	const byNote = new Map()
	for (const item of needsHuman) {
		const key = item.notes.join('；') || '(未标注)'
		if (!byNote.has(key)) byNote.set(key, [])
		byNote.get(key).push(item)
	}
	for (const [reason, group] of [...byNote.entries()].sort((a, b) => b[1].length - a[1].length)) {
		lines.push(`### ${group.length} 条｜${reason}`)
		group.slice(0, 2).forEach(({ r }) => {
			const text = String(r.text ?? '')
			const shown = text.length > 1200 ? `${text.slice(0, 1200)}\n…（已截断至 1200 字符，全文见 ${r.__file}:${r.__line}，原长 ${text.length}）` : text
			lines.push(`- \`${r.rule?.id}\` @ ${r.at} ｜${r.where}｜${r.path ?? '-'}`)
			lines.push('```text')
			lines.push(shown)
			lines.push('```')
		})
		lines.push('')
	}
}
lines.push('## 重复尝试（同规则 + 同正文 + 同会话 ≥3 次；跨会话合并会掩盖真正的重试）')
if (repeats.length === 0) lines.push('_无。_')
else lines.push(repeats.slice(0, 20).map(([key, n]) => {
	const [ruleId, session, text] = key.split('\u0000')
	return `- ${n} 次：\`${ruleId}\` ／会话 \`${session}\` ／\`${String(text).slice(0, 160)}\``
}).join('\n'))
lines.push('')
lines.push('## 漏报候选（影子层收尸：不是走 trash 消失的文件）')
if (args.trash === undefined) {
	lines.push('_未提供 `--trash` 台账，跳过漏报检测（建议加 `--trash <workspace>\\_trash\\manifest.jsonl`）。_')
} else if (freshMisses.length === 0) {
	lines.push(`_窗口内 0 条（台账全量 ${misses.length} 条；版本快照 ${versionSnapshots.length} 条已排除）。_`)
} else {
	lines.push(`窗口内 **${freshMisses.length}** 条（台账全量 ${misses.length} 条；版本快照 ${versionSnapshots.length} 条不计）。`)
	lines.push('')
	lines.push('> 这些文件不是经 `trash` 工具消失的：可能是 ①规则没覆盖的新写法（真漏）②AI 换写法绕过成功 ③正常的移动/重命名 ④git 等工具改写的内部文件。逐条判，别一律当漏报。')
	lines.push('')
	lines.push('| 时间 | 原路径 | id |')
	lines.push('|---|---|---|')
	for (const m of freshMisses.slice(0, 50)) lines.push(`| ${m.at} | \`${m.from}\` | ${m.id} |`)
	if (freshMisses.length > 50) lines.push(`| … | 另有 ${freshMisses.length - 50} 条见台账 | |`)
}
lines.push('')
lines.push('## 解析失败的日志行')
if (parseErrors.length === 0) lines.push('_无。_')
else lines.push(parseErrors.map((e) => `- ${e.file}:${e.line} — ${e.error}`).join('\n'))

mkdirSync(dirname(reportPath), { recursive: true })
writeFileSync(reportPath, `${lines.join('\n')}\n`, 'utf8')
writeFileSync(statePath, `${JSON.stringify({ lastAnalyzedAt: now.toISOString(), lastReport: reportPath, lastCounts: { fresh: fresh.length, total: records.length, candidates: candidates.length, needsHuman: needsHuman.length, repeats: repeats.length } }, null, 2)}\n`, 'utf8')

const summary = {
	dir: args.dir,
	since: effectiveSince.toISOString(),
	newRecords: fresh.length,
	totalRecords: records.length,
	runtime: { status: runtimeStatus, moduleMtimeMs: heartbeat?.moduleMtimeMs, diskMtimeMs, heartbeatAt: heartbeat?.at },
	zeroMeaning,
	candidates: candidates.length,
	needsHuman: needsHuman.length,
	repeats: repeats.length,
	misses: freshMisses.length,
	report: reportPath,
}
if (args.json) console.log(JSON.stringify(summary, null, 2))
else {
	console.log(`运行态：${runtimeStatus}${runtimeStatus === 'fresh' ? '' : '（0 条日志不能当作零拦截）'}`)
	if (zeroMeaning !== undefined) console.log(`本次 0 条的含义：${zeroMeaning}`)
	console.log(`分析完成：新增 ${fresh.length} 条（总 ${records.length}），疑似误判 ${candidates.length} 条，待人工 ${needsHuman.length} 条，漏报候选 ${freshMisses.length} 条，重复尝试组 ${repeats.length}`)
	console.log(`报告：${reportPath}`)
}
