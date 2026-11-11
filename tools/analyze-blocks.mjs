// theme=trash-guard status=active date=2026-11-11
// 夜间分析：读调试日志（默认 E:\dsh-trash-guard-logs），统计拦截分布并挑出疑似误判样本。
// 用法：
//   node tools/analyze-blocks.mjs                 # 增量：只分析上次分析之后的新记录
//   node tools/analyze-blocks.mjs --all           # 全量重算（不移动 lastAnalyzedAt 之外的语义）
//   node tools/analyze-blocks.mjs --since 2026-11-01T00:00:00Z
//   node tools/analyze-blocks.mjs --dir E:\dsh-trash-guard-logs --out <报告路径>
// 退出码：0 正常（含"没有新记录"）；2 目录不存在且没有任何日志；1 参数/读取错误。
import { existsSync, readdirSync, readFileSync, mkdirSync, writeFileSync } from 'node:fs'
import { dirname, join, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'

const HERE = dirname(fileURLToPath(import.meta.url))
const PLUGIN = resolve(HERE, '..')
const mod = await import(new URL('../index.js', import.meta.url).href)
const { RULES, classifyText, DEFAULT_DEBUG_DIR } = mod.__internals

function parseArgs(argv) {
	const out = { dir: DEFAULT_DEBUG_DIR, since: undefined, all: false, out: undefined, json: false }
	for (let i = 0; i < argv.length; i += 1) {
		const a = argv[i]
		if (a === '--dir') out.dir = argv[++i]
		else if (a === '--since') out.since = argv[++i]
		else if (a === '--out') out.out = argv[++i]
		else if (a === '--all') out.all = true
		else if (a === '--json') out.json = true
		else if (a === '--help' || a === '-h') {
			console.log('node tools/analyze-blocks.mjs [--dir <dir>] [--since <ISO>] [--all] [--out <path>] [--json]')
			process.exit(0)
		}
	}
	out.dir = resolve(out.dir)
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

const fresh = records.filter((r) => new Date(r.at) > since)
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

/** 去掉引号字符串与 # 注释后重新分类：还命中就不是"只在字符串/注释里提到"。 */
function mentionOnly(text) {
	const stripped = String(text ?? '')
		.replace(/`[^`]*`/g, '``')
		.replace(/"[^"\n]*"/g, '""')
		.replace(/'[^'\n]*'/g, "''")
		.replace(/#.*$/gm, '')
		.replace(/<#[^#]*#>/g, '')
	return classifyText(stripped, []) === undefined
}

const candidates = []
const repeatMap = new Map()
for (const r of fresh) {
	const text = String(r.text ?? '')
	const norm = text.replace(/\s+/g, ' ').trim()
	bump(repeatMap, `${r.rule?.id}\u0000${norm.slice(0, 300)}`)
	const reasons = []
	if (mentionOnly(text)) reasons.push('去掉引号/注释后不再命中任何规则（疑似"仅在字符串或注释里提到删除词"）')
	if (/\B--help\b|\s-h\b|--dry-?run\b|-WhatIf\b|--version\b/i.test(text)) reasons.push('命令带 --help/--dry-run/-WhatIf/--version 一类只读开关')
	if (r.where === 'launched' && r.path && !existsSync(r.path)) reasons.push('被拦的启动脚本路径已不存在（可能早已改名/移动）')
	if (r.where === 'script' && r.path && !/\.(ps1|psm1|psd1|bat|cmd|sh|bash|zsh|py|js|mjs|cjs|ts|vbs|reg)$/i.test(r.path)) reasons.push('被拦的写入路径不是脚本后缀（写入侧误判）')
	if (reasons.length > 0) candidates.push({ r, reasons })
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
lines.push(`- 分析窗口：\`${since.toISOString()}\` 之后（${args.all ? '全量' : '增量'}）`)
lines.push(`- 日志文件 ${files.length} 个；记录 ${records.length} 条；本次新记录 **${fresh.length}** 条；解析失败 ${parseErrors.length} 条`)
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
lines.push('## 重复尝试（同规则 + 同正文 ≥3 次，提示模型可能陷入重试）')
if (repeats.length === 0) lines.push('_无。_')
else lines.push(repeats.slice(0, 20).map(([key, n]) => `- ${n} 次：\`${key.split('\u0000')[0]}\` / \`${key.split('\u0000')[1].slice(0, 160)}\``).join('\n'))
lines.push('')
lines.push('## 解析失败的日志行')
if (parseErrors.length === 0) lines.push('_无。_')
else lines.push(parseErrors.map((e) => `- ${e.file}:${e.line} — ${e.error}`).join('\n'))

mkdirSync(dirname(reportPath), { recursive: true })
writeFileSync(reportPath, `${lines.join('\n')}\n`, 'utf8')
writeFileSync(statePath, `${JSON.stringify({ lastAnalyzedAt: now.toISOString(), lastReport: reportPath, lastCounts: { fresh: fresh.length, total: records.length, candidates: candidates.length, repeats: repeats.length } }, null, 2)}\n`, 'utf8')

const summary = {
	dir: args.dir,
	since: since.toISOString(),
	newRecords: fresh.length,
	totalRecords: records.length,
	candidates: candidates.length,
	repeats: repeats.length,
	report: reportPath,
}
if (args.json) console.log(JSON.stringify(summary, null, 2))
else {
	console.log(`分析完成：新增 ${fresh.length} 条（总 ${records.length}），疑似误判 ${candidates.length} 条，重复尝试组 ${repeats.length}`)
	console.log(`报告：${reportPath}`)
}
