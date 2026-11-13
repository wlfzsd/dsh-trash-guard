// theme=trash-guard status=active date=2026-11-12
// 双轨之"会话轨"：增量扫描 DSH 会话日志，抽出**本插件拒绝**的事件与"拒绝之后 AI 怎么反应"。
//
// 为什么要有它：blocks 日志只记 deny，且插件没重启就一条都没有；会话日志是客户端持久化的，
// 里面既有历史拒绝、也有 AI 的下一条动作，能回答"拒绝文案到底管不管用"。
//
// 用法：
//   node tools/analyze-sessions.mjs                     # 增量：从上次扫描结束时间起，到此刻
//   node tools/analyze-sessions.mjs --since 2026-11-12T00:00:00+08:00 --until 2026-11-12T12:00:00+08:00
//   node tools/analyze-sessions.mjs --all               # 忽略窗口，全量（只在基线复现时用）
//   node tools/analyze-sessions.mjs --json
// 退出码：0 正常；2 会话目录不存在；1 参数/解码错误。
//
// 铁律（用户 2026-11-12 明确要求）：
//   ① 只分析**定位到的时间段内**的记录，不放大范围；
//   ② 每次结束写回 lastScanEnd，下次从它开始，不重复分析；
//   ③ 命中数为 0 但时间窗很长时，必须报警"疑似格式变化"，不准静默当作"无拦截"。
import { existsSync, mkdirSync, readdirSync, readFileSync, statSync, writeFileSync } from 'node:fs'
import { homedir } from 'node:os'
import { dirname, join, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'
import zlib from 'node:zlib'

const HERE = dirname(fileURLToPath(import.meta.url))
const DEFAULT_SESSIONS = join(process.env.DSH_HOME ?? join(homedir(), '.dsh'), 'sessions')
const DEFAULT_STATE = 'E:\\dsh-trash-guard-logs\\_session-scan.json'
const DEFAULT_OUT_DIR = 'E:\\dsh-trash-guard-logs\\sessions'
/** 一级锚：拒绝决策里的稳定错误码（实测 228 次命中，新旧文案都有）。 */
const ANCHOR = 'DELETE_BLOCKED'
/** 二级锚：用于区分文案版本。 */
const SECONDARY = ['【1｜你被拦截了】', 'TRASH_GUARD', '被拦截了']
/** 反应链：拒绝之后 N 条记录内找这些，判断 AI 换没换路。 */
const REACT_TRASH = 'trash({'
const REACT_RETRY_WINDOW = 12

function parseArgs(argv) {
	const out = { since: undefined, until: undefined, all: false, json: false, sessions: DEFAULT_SESSIONS, state: DEFAULT_STATE, outDir: DEFAULT_OUT_DIR }
	for (let i = 0; i < argv.length; i += 1) {
		const a = argv[i]
		if (a === '--since') out.since = argv[++i]
		else if (a === '--until') out.until = argv[++i]
		else if (a === '--sessions-dir') out.sessions = argv[++i]
		else if (a === '--state') out.state = argv[++i]
		else if (a === '--out-dir') out.outDir = argv[++i]
		else if (a === '--all') out.all = true
		else if (a === '--json') out.json = true
		else if (a === '--help' || a === '-h') {
			console.log('node tools/analyze-sessions.mjs [--since <ISO>] [--until <ISO>] [--all] [--sessions-dir <dir>] [--state <file>] [--out-dir <dir>] [--json]')
			process.exit(0)
		}
	}
	out.sessions = resolve(out.sessions)
	out.state = resolve(out.state)
	out.outDir = resolve(out.outDir)
	return out
}

const args = parseArgs(process.argv.slice(2))
if (!existsSync(args.sessions)) {
	console.error(`会话目录不存在：${args.sessions}`)
	process.exit(2)
}

const state = existsSync(args.state) ? JSON.parse(readFileSync(args.state, 'utf8')) : {}
const now = new Date()
const since = args.all
	? new Date(0)
	: (args.since ? new Date(args.since) : (state.lastScanEnd ? new Date(state.lastScanEnd) : new Date(now.getFullYear(), now.getMonth(), now.getDate())))
const until = args.until ? new Date(args.until) : now
if (Number.isNaN(since.getTime()) || Number.isNaN(until.getTime())) {
	console.error('--since / --until 不是合法时间')
	process.exit(1)
}
if (until <= since) {
	console.error(`时间窗无效：since=${since.toISOString()} until=${until.toISOString()}`)
	process.exit(1)
}

/** 收集会话文件（<sessions>/<escaped-cwd>/session-<id>/session.v4.jsonl.zstd）。 */
function collectSessionFiles(root, limit) {
	const found = []
	const walk = (dir, depth) => {
		if (depth > 4) return
		let entries
		try {
			entries = readdirSync(dir, { withFileTypes: true })
		} catch {
			return
		}
		for (const entry of entries) {
			const full = join(dir, entry.name)
			if (entry.isDirectory()) walk(full, depth + 1)
			else if (entry.name === 'session.v4.jsonl.zstd') found.push(full)
		}
	}
	walk(root, 0)
	// 只看窗口内改动过的文件：mtime 早于 since 的不可能产生新事件。
	return found.filter((file) => {
		try {
			return statSync(file).mtime > new Date(since.getTime() - 1000)
		} catch {
			return false
		}
	})
}

function eventTime(record) {
	const candidates = [record.at, record.time, record.ts, record.data?.time]
	for (const value of candidates) {
		if (typeof value === 'string' || typeof value === 'number') {
			const d = new Date(value)
			if (!Number.isNaN(d.getTime())) return d
		}
	}
	return undefined
}

const files = collectSessionFiles(args.sessions, 2000)
const events = []
const decodeErrors = []
let scannedBytes = 0

for (const file of files) {
	let text
	try {
		const raw = readFileSync(file)
		scannedBytes += raw.length
		text = zlib.zstdDecompressSync(raw).toString('utf8')
	} catch (error) {
		decodeErrors.push({ file, error: String(error?.message ?? error) })
		continue
	}
	if (!text.includes(ANCHOR)) continue
	const lines = text.split(/\r?\n/)
	const sessionId = file.split(/[\\/]/).slice(-2, -1)[0] ?? ''
	for (let i = 0; i < lines.length; i += 1) {
		const line = lines[i]
		if (line.length === 0 || !line.includes(ANCHOR)) continue
		let record
		try {
			record = JSON.parse(line)
		} catch {
			continue
		}
		const when = eventTime(record)
		// 铁律①：只收窗口内的记录；边界用**严格大于** since，避免上一轮末尾的事件被重复计数。
		if (when === undefined || when <= since || when > until) continue
		const flat = line
		const rule = /（([a-z0-9-]+) \/ ([^）]+)）/.exec(flat)
		const where = /(命令|脚本[^的]*的正文|要启动的脚本[^（]*（启动前已读正文）)/.exec(flat)?.[1] ?? ''
		const secondary = SECONDARY.filter((k) => flat.includes(k))
		// 反应链：往后看 REACT_RETRY_WINDOW 条，找 AI 下一步做了什么。
		let reaction = 'unknown'
		for (let j = i + 1; j < Math.min(lines.length, i + 1 + REACT_RETRY_WINDOW); j += 1) {
			const nxt = lines[j]
			if (nxt.includes(REACT_TRASH)) {
				reaction = 'used-trash'
				break
			}
		}
		events.push({
			at: when.toISOString(),
			sessionId,
			file: file.split(/[\\/]/).slice(-3).join('/'),
			ruleId: rule?.[1] ?? '',
			ruleLabel: rule?.[2] ?? '',
			where,
			secondary,
			reaction,
		})
	}
}

// 铁律③：0 命中但窗口很长 → 疑似格式变化或插件未生效，必须说出来。
const windowMinutes = Math.round((until - since) / 60000)
const warnings = []
if (events.length === 0 && windowMinutes >= 60) {
	warnings.push(`窗口 ${windowMinutes} 分钟、扫描 ${files.length} 个会话文件，命中 ${ANCHOR} 为 0 —— 可能是真的没有拦截，也可能是会话日志格式变化或插件未进运行态；不要直接当"无拦截"。`)
}
if (decodeErrors.length > 0) warnings.push(`${decodeErrors.length} 个会话文件解压失败（见 jsonl 明细）`)

const byRule = new Map()
const byReaction = new Map()
const bySession = new Map()
const bump = (map, key) => map.set(key, (map.get(key) ?? 0) + 1)
for (const e of events) {
	bump(byRule, e.ruleId || '(unknown)')
	bump(byReaction, e.reaction)
	bump(bySession, e.sessionId)
}

const stamp = `${now.getFullYear()}${String(now.getMonth() + 1).padStart(2, '0')}${String(now.getDate()).padStart(2, '0')}-${String(now.getHours()).padStart(2, '0')}${String(now.getMinutes()).padStart(2, '0')}`
mkdirSync(args.outDir, { recursive: true })
const detailPath = join(args.outDir, `session-denies-${stamp}.jsonl`)
writeFileSync(detailPath, events.map((e) => JSON.stringify(e)).join('\n') + (events.length ? '\n' : ''), 'utf8')

const table = (map, header) => {
	const rows = [...map.entries()].sort((a, b) => b[1] - a[1])
	if (rows.length === 0) return '_（无）_'
	return `| ${header} | 次数 |\n|---|---|\n` + rows.map(([k, v]) => `| ${k} | ${v} |`).join('\n')
}
const reportPath = join(args.outDir, `session-report-${stamp}.md`)
const md = [
	'# 会话轨扫描（插件拒绝事件 + 反应链）',
	'',
	`- 窗口：${since.toISOString()} → ${until.toISOString()}（${windowMinutes} 分钟）`,
	`- 扫描会话文件 ${files.length} 个，读取压缩字节 ${scannedBytes}，解压失败 ${decodeErrors.length}`,
	`- 命中拒绝事件 **${events.length}** 条，分布 ${bySession.size} 个会话`,
	'',
	'## 按规则',
	table(byRule, 'ruleId'),
	'',
	'## AI 的反应（拒绝后 12 条内是否改用 trash 工具）',
	table(byReaction, 'reaction'),
	'',
	'## 按会话',
	table(bySession, 'sessionId'),
	'',
	'## 告警',
	warnings.length === 0 ? '_无。_' : warnings.map((w) => `- ${w}`).join('\n'),
	'',
	'## 明细',
	`- ${detailPath}`,
].join('\n')
writeFileSync(reportPath, `${md}\n`, 'utf8')

writeFileSync(args.state, `${JSON.stringify({ lastScanEnd: until.toISOString(), lastReport: reportPath, lastDetail: detailPath, lastCounts: { events: events.length, sessions: bySession.size } }, null, 2)}\n`, 'utf8')

const summary = {
	since: since.toISOString(),
	until: until.toISOString(),
	sessionFiles: files.length,
	events: events.length,
	sessions: bySession.size,
	byReaction: Object.fromEntries(byReaction),
	byRule: Object.fromEntries(byRule),
	warnings,
	report: reportPath,
	detail: detailPath,
	state: args.state,
}
if (args.json) console.log(JSON.stringify(summary, null, 2))
else {
	console.log(`会话轨：窗口 ${windowMinutes} 分钟，扫描 ${files.length} 个文件，拒绝事件 ${events.length} 条（${bySession.size} 个会话）`)
	console.log(`反应分布：${[...byReaction.entries()].map(([k, v]) => `${k}=${v}`).join(' ') || '(无)'}`)
	for (const w of warnings) console.log(`⚠ ${w}`)
	console.log(`报告：${reportPath}`)
}
