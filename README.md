# dsh-trash-guard

> theme=trash-guard status=active date=2026-11-10

让 DeepSeek Harness 里"删除"这件事，落到工作区的垃圾箱（`_trash/`）而不是真的销毁字节。

**中文关键词（按中文搜本插件用这一行）**：删除 · 删除文件 · 误删 · 误删恢复 · 撤销删除 · 恢复 · 垃圾箱 · 回收站 · 清理 · 清空 · 拦截删除 · 删除拦截 · 不要真删 · 工具名 `trash`（移入垃圾箱）/ `restore`（移回原位） · 配置项 `trashDir` · 目录 `_trash/` · 装机标识 `trash-guard`。命令里出现删除动作会在执行前被拒（写入 .ps1/.bat/.sh/.py 的正文同样被扫）。

单文件插件，零依赖，只用 `node:` 内置模块；不 import `@deepseek-ai/dsh-tools`（profile 目录里没有 node_modules，任何裸包导入都会解析失败）。

---

## 1. 先说结论：什么是可行的，什么不是

**"把 DeleteFile 透明地重定向到 Windows 回收站" —— 在插件层做不到，也不是本插件做的事。** 三条硬证据：

| # | 事实 | 出处 |
|---|------|------|
| 1 | 工具参数在进入策略前就被深冻结，策略只能 `allow/deny/cancel/ask`，**契约里明写"排除输入改写，因为参数已经记入日志并呈现给用户"** | `dsh-tools/lib/types/contracts.d.ts:318-319`；`dsh-tools/lib/pipeline.js:331`（`arguments: deepFreeze(...)`）、`:386`（`waterfall("tools/pre-execute")`） |
| 2 | 每次 pwsh 调用都是**新进程**且带 `-NoLogo -NoProfile -NonInteractive -Command`，profile 注入代理函数这条路直接堵死 | `dsh-pwsh-local/lib/index.js:200-203` |
| 3 | Windows 沙箱是 ACL **拒绝**型：授权根目录内仍然保留 DELETE 权限，只有根外被拒；它不是"重定向"层 | `dsh-sandbox-windows-acl/README.zh.md`（"能力 ACE 的 DELETE 位是授权根目录内唯一的删除授权来源"） |

要把任意进程的 `DeleteFile` 路由到回收站，只有内核 minifilter 驱动一条路 —— 那是驱动，不是插件。

**"所有删除都进垃圾箱" —— 可行。** 但正确的做法不是拦截命令字符串，而是：

1. **文本层**：命令/脚本正文里出现删除动作 → 直接 `deny`，把模型引导到 `trash` 工具（防患于未然）；
2. **工具层**：`trash` 工具用 `rename()` 把目标移进 `_trash/<时间戳>/` 并写 manifest（这是唯一的"删除"实现，全程不调用任何删除 API）；
3. **状态层（影子）**：每次改动型工具调用前，给工作区每个文件建一个 `_trash/.shadow/` 下的**硬链接**；调用前先扫一遍"影子还在、原文件没了"的条目 —— 那就是一次删除，把影子（仍握着原 inode 的内容）移进垃圾箱。

第 3 层与"谁删的、用什么语言删的"完全无关，**所以 `.ps1` 里的 `Remove-Item`、原生 `del`、`[IO.File]::Delete()` 一样进箱**。

## 2. "如果它调用的是 ps1 就不行了吧？"

分三层看，答案不一样：

| 层 | 能不能挡住 .ps1 里的删除 | 原因 |
|----|------------------------|------|
| 命令字符串改写 | ✗ | 命令里只有文件名，正文不可见 |
| PowerShell 会话内代理函数 | ✗（在 DSH 里） | 每次调用都 `-NoProfile` + 新进程，代理函数进不去 |
| **启动前读正文（本插件第 2 层）** | **✓ 能解析出脚本路径时** | `pwsh -File x.ps1`、`cmd /c x.bat`、`.\x.bat`、`& x.ps1`、`Start-Process ... -File x.ps1`、`call x.bat` 都会在**启动前**把正文读出来扫一遍，还跟着脚本之间的调用递归（深度 ≤2、≤24 个文件） |
| 影子层（本插件第 3 层） | ✓（事后兜底） | 不关心谁删的，只关心"文件没了"；硬链接本身握着内容 |
| ACL 硬拒绝（没做） | ✓ | 内核权限检查，但那是"删除失败"，不是"进垃圾箱" |

**所以对你"大部分操作在 ps1 / bat 里"这个场景：确实是靠"启动前读正文"这一层挡的**——它读的是磁盘上的真实文件，不是模型说的话，所以模型自己写的、你早就放着的、AI 上一次写的脚本，一视同仁。

仍然挡不住的三类（如实列，靠影子层收尸）：正文是**运行期拼接/远程下载**的、路径是**变量算出来的**（`& $cmd`、`& "$dir\x.ps1"`）、单文件 **>512KB** 或递归**超过 24 个文件**的。

**注意本插件对 .ps1 的另一半防护**：模型通过 `write` 工具创建的 `.ps1/.bat/.cmd/.sh/.py/...`，正文会被扫描；里面有删除动作就拒绝写入。也就是说——
- 模型**写出来的**删除脚本：写入时就被拒（或改写）；
- 模型**运行时才产生**的删除脚本（下载的、别的程序生成的、heredoc 拼的）：写入层看不见，但影子层兜住。

## 3. 覆盖矩阵

| 删除方式 | 拦不拦得住 | 靠哪层 |
|---------|-----------|--------|
| `Remove-Item` / `rm` / `del` / `Clear-Content` / `Set-Content -Value ''` 直接在命令里 | ✓ 执行前拒绝 | 文本层 |
| `Get-ChildItem \| Remove-Item -Recurse -Force`、`cmd /c del`、`robocopy /MIR`、`git clean`、`forfiles ... cmd /c del` | ✓ 执行前拒绝 | 文本层 |
| `[System.IO.File]::Delete()`、`.Delete()` 方法调用、`-EncodedCommand` | ✓ 执行前拒绝 | 文本层 |
| **已存在的 `.ps1` 被 `pwsh -File` / `& x.ps1` / `Start-Process -File` 启动** | ✓ 启动前读正文拒绝 | **启动扫描层** |
| **已存在的 `.bat/.cmd` 被 `cmd /c` / `start` / 双击式直接执行 / 被别的 bat `call`** | ✓ 启动前读正文拒绝 | **启动扫描层**（批处理放宽到行中 `if exist x del x`、`for ... do rd`） |
| 模型 `write` 出来的 `.ps1/.bat/.sh/.py` 里的删除 | ✓ 写入前拒绝 | 文本层（写入侧） |
| 运行期拼接的脚本 / 原生 exe / .NET 直调 / 第三方工具 | ✓ 事后收进垃圾箱 | **影子层** |
| 路径由变量算出（`& $cmd`、`& "$dir\x.ps1"`） | ✗ 启动扫描解不出路径 | 只剩影子层 |
| 工作区**外**的删除 | ✗（也不该管） | 沙箱本来就不允许 |
| 回收站级的"自动清空/跨卷/系统 UI" | ✗ 不做 | 只做工作区私有垃圾箱 |

## 3.1 唯一落点与降级阶梯（2026-11-10 定）
被拒时 AI 只收到**一条路径**，不是三选一——避免"每次随机挑一套方案，把文件改得乱七八糟、日后没法批量恢复"。

1. **第一步（唯一动作，不要跳步）**：`trash({ paths, note })`。落点固定 `_trash/<时间戳>/`，同时追加 `_trash/manifest.jsonl`。需要"清空/覆盖某个文件"也走同一条：先 `trash` 把原件移进垃圾箱，再写新文件。**不要就地覆盖原文件**——那会让原内容脱离 manifest，事后无法按台账恢复。
2. **第二步（只在第一步失败时才走，且是终点）**：`trash` 返回 `failed`（跨卷、路径不在工作区、目标不存在、原位置被占用等）时立即停止：不改名加 `.bak` 散落文件、不换别的删除写法重试，把 `路径＋原始错误` 原样交给用户。第二步不会再发散出第三套文件操作，所以不存在"越试越乱"的分叉。

**批量恢复口径**（日后照这个来，不用记个案）：

```powershell
# 1) 看台账：每行一条 JSON；op=trash 是移入（可 restore），op=restore 是已复位，op=version 是编辑产生的旧版本快照（不参与 restore、不计漏报）
Get-Content <workspace>\_trash\manifest.jsonl
```

```text
restore({ ids: ["<id1>", "<id2>", ...] })     # 按 id 批量复位（一次传多个）
restore({ paths: ["<原路径1>", "<原路径2>"] }) # 按原始路径批量复位（对 manifest 的 from 字段）
restore({ ids: ["?"] })                       # 只列出最近 20 条可恢复 id，不动文件
```

`restore` 逐个复原：原位置被占用会记 `failed` 而不是覆盖；垃圾箱里文件已不存在也会记 `failed`。台账是唯一真源，`_trash/<时间戳>/` 下的文件名前缀序号只是给人看的。

## 3.2 拒绝时对 AI 说什么（三段式，2026-11-10 定）

被拒后 AI 收到的不是"权限不足"四个字，而是按顺序必须先回答的三段：

1. **你被拦截了**：拒绝码 `DELETE_BLOCKED`、命中的规则 id/label、命中片段，以及**本条指令被识别出的放大因子**（递归 `-Recurse`/`/s`、通配 `*`/`?`、盘符/家目录根、循环 `for`/`foreach`/`while`、管道串联、`-Force`/`/f`/`/q`、`-EncodedCommand`、`..` 上溯）。放大因子只用于提示，**不改变 allow/deny 判定**。
2. **换成什么**：唯一动作 `trash({ paths, note })`；要"清空/覆盖某文件"只能先 trash 原件、再写新文件。
3. **提交前必须自查（逐条写结论再动手）**：a) 范围有界？b) 有循环？c) **PowerShell 转义**（引号、`$()`、反引号折行、变量展开）会不会把字面路径变成通配或另一条路径——这是论坛里最常见的事故源？d) 会不会碰到 `_trash` 恢复源？e) 可回滚（`_trash` 里有副本、manifest 里有记录）？

附纪律：原样重试、换写法绕过都会被同样拒绝，不要连试；只有 `trash` 返回 `failed` 才停止并上报。附还原口径：`restore({ ids })` 或 `restore({ paths })`。

## 3.3 恢复源自保护（`_trash` 不会被自己吃掉）

| 攻击面 | 保护 | 实测 |
|---|---|---|
| `trash` 目标是"包含 `_trash` 的目录"（如工作区根） | 拒绝整体移动 | `failed`：`目标包含垃圾箱目录 …，拒绝对其整体移动` |
| `trash` 目标已经在垃圾箱里 | 拒绝重复移入 | `failed`：`目标已经在垃圾箱里，不需要再移一次` |
| 影子层把 `_trash` 自己也建影 | `isSkipped()` 按路径段名剔除 `_trash` | 影子层从不索引 `_trash` |
| 删除命令指向 `_trash` | 文本层同样 deny（只看动作、不看目标） | 与其他删除命令一致 |

**仍然要承认的边界**：`_trash` 必须与工作区**同卷**才能 `rename`，所以它只能待在工区目录内。若某个**绕过文本层**的程序（未审计的原生 exe、编译产物）在工作区里做递归删除，`_trash` 会与工作区一起被波及——这一类只能靠沙箱 ACL（工作区外）与"别在工作区里跑未审计二进制"来防，不是本插件能封的。

## 3.4 调试模式与夜间分析（2026-11-11 加，默认开启）

**日志目录**：`E:\dsh-trash-guard-logs`（目录不存在时，第一次拦截自动创建）。

| 文件 | 内容 |
|---|---|
| `blocks-<YYYY-MM-DD>.jsonl` | 每行一条拦截记录（本地日期切分，append-only） |
| `_state.json` | 分析器状态：`lastAnalyzedAt` / `lastReport` / `lastCounts` |
| `reports/analyze-<时间戳>.md` | 分析报告（运行态自检 + 疑似误判候选 + 待人工 + 漏报候选 + 重复尝试） |
| `reports/优化建议-<日期>.md` | 夜间例行分析写入的裁决与建议 |
| `_heartbeat.json` | 挂载心跳：记录**被加载的那个模块文件**的 mtime，用来判断运行态是不是最新版 |

单条记录字段：`at`（UTC 时间）、`session`、`tool`、`where`（command/script/launched/patch）、`path`、`rule{id,label}`、`risks[]`、`workspace`、`snippet`、`text`（命令/脚本原文）、`textBytes`、`truncated`。

**为什么需要心跳**：插件改完代码不重启 dsh，磁盘是新的、进程里还是旧的，日志一行都不会写。此时"0 条日志"绝不能被读成"零拦截"（前者是没在记，后者是没发生）。心跳里的 `moduleMtimeMs` 取自实际被加载的模块文件，与磁盘 mtime 一比即可判定：

| 分析器输出 | 含义 | 0 条日志怎么读 |
|---|---|---|
| `fresh` | 运行态与磁盘一致 | 可信：本轮确实无拦截 |
| `stale` | 运行中是旧版（改过代码没重启） | **不可信**：日志没生效，不是没发生 |
| `unknown` | 没有心跳（旧版本插件或从未挂载） | **不可信**：同上 |

配置（默认值即下面这些，写进 patch 只是显式化）：

```yaml
        debug:
          enabled: true                      # 总开关，默认开
          dir: 'E:\dsh-trash-guard-logs'
          maxTextBytes: 16384                # 超长正文按此截断，并置 truncated=true
          redact: true                       # 脱敏 password/token/secret/api_key/authorization 的键值
```

**分析器**（零依赖，可手动跑）：

```powershell
node D:\Users\Administrator\.dsh\plugins\dsh-trash-guard\tools\analyze-blocks.mjs
# 选项：--dir <目录> --since <ISO> --nightly --all --trash <workspace>\_trash\manifest.jsonl --out <报告路径> --json
#   --nightly = 窗口取本地日 0 点起（夜间复盘用；否则增量游标会把窗口切成几分钟）
# 退出码：0 正常（含"无新记录"）；2 目录不存在；1 参数/读取错误
```

它会做四件事：①**运行态自检**（读 `_heartbeat.json` 比对磁盘 mtime，给出 `fresh/stale/unknown`，并把"0 条"翻译成"没在记"或"确实没发生"）；②按规则/入口/工具/日期/会话统计新增拦截；③用启发式挑**疑似误判**（**先按来源选分类器**——`.bat/.cmd` 用批处理规则、其它脚本用脚本规则、命令用命令规则——仍不命中才算；命令带 `--help/--dry-run/-WhatIf`；写入路径不是脚本后缀）；④找"同规则 + 同正文 + **同会话** ≥3 次"的重复尝试（跨会话合并会掩盖真重试）。证据不全（正文被截断/只剩片段）一律进「需人工确认」按原因聚合，不写成"疑似误判"。

传了 `--trash` 还会多出一节「漏报候选」：拦截日志只记"被拦住"的调用，**漏掉的根本不产生记录**；唯一能自动采集的漏报信号是 `manifest.jsonl` 里 `note` 含「原文件已消失」的条目（文件没走 `trash` 工具就消失了）。这些条目必须逐条归四类——①规则没覆盖的新写法 ②AI 换写法绕过成功 ③正常移动/重命名 ④git 等工具改写的内部文件——只有①②算真漏。

**夜间定时任务**：每天 `00:00`（Asia/Shanghai）在一个独立会话里跑分析器、读报告、逐条裁决误判候选，把结论写进 `reports/优化建议-<日期>.md`，**只出建议不改代码**（改代码需人批准并重启 dsh 才生效）。

**边界**：①日志含命令原文，虽默认脱敏但仍可能残留敏感信息，**不要外发**；②写日志失败只 `warn`，绝不影响拦截判定；③调试日志与 `_trash` 台账是两套数据，互不覆盖；④日志目录在 E 盘根、与工作区无关，多个工作区共用一个目录。

## 4. 安装

**本机当前状态（2026-11-10 实测）**：代码本体在 `D:\Users\Administrator\.dsh\plugins\dsh-trash-guard\`，profile 里只有一行引用——`profiles\web\cordis.patch.yml` 第 39-44 行。

```yaml
- insert:
    - id: trash-guard
      name: 'dsh-trash-guard'
      config:
        trashDir: '_trash'
```

**为什么用裸包名而不是 `file:///` 绝对路径**：DSH 设置里的「内置插件」列表通过 `readPluginMeta()` 取显示文本，而它只对**包名**（bare specifier）生效——`file:///` 或绝对路径会被判为"非包"，于是列表里只剩路径短名、也没有介绍。改成包名后，列表会读：

| 来源 | 字段 | 本机内容 |
|---|---|---|
| `locale/zh.json` | `meta.title` / `meta.description` | 垃圾箱守卫（删除拦截）／把删除意图改道到工作区垃圾箱 _trash/，删除内容可随时恢复… |
| `locale/en.json` | 英文回退 | Trash Guard (delete interception)／… |
| `package.json` | `description` 兜底 | 删除拦截插件…（中文） |

**解析路径**：`package.json` 的 `exports` 必须导出 `./package.json` 与 `./locale/*.json`（否则读不到 locale）；包本体与解析入口通过 junction 连起来：
`%DSH_HOME%\node_modules\dsh-trash-guard` → `%DSH_HOME%\plugins\dsh-trash-guard`（改代码只改后者，单份真源）。

**关键事实：这是 profile 级安装，不绑定任何工作区。** 任何用 `web` profile 打开的目录都会被保护，`_trash/` 落在各自的工作区里——换项目、换盘符都不用重装。

**状态自查（中文/英文关键词都能搜到）**：

| 想确认什么 | 在哪查 | 搜什么关键词 |
|---|---|---|
| 活没活（最权威） | `plugin_manager` 的 `list_plugins`（本条目在末尾，`offset: 195` 起可见） | `trash-guard`、`dsh-trash-guard`、`fiberPhase: active`、`enabled: true` |
| 装没装（配置层） | `D:\...\.dsh\profiles\web\cordis.patch.yml`（第 39-44 行） | 中文 `删除`、`垃圾箱`；英文 `trash`、`trashDir`、`dsh-trash-guard` |
| 列表里的中文名 | 设置 → 内置插件（搜 `删除` 即可命中） | `垃圾箱守卫`、`删除拦截`、`删除` |
| 显示文本来源 | `plugins\dsh-trash-guard\locale\zh.json`（语言 id 只能是 `zh`/`en`，写 `zh-CN` 会落空） | `meta.title`、`meta.description` |
| 组合树对不对 | `node <dsh>/lib/bin.js --profile web --dump-config`（exit 0 为准） | `trash-guard`、`trashDir` |
| 代码在不在 | `D:\...\.dsh\plugins\dsh-trash-guard\` | 中文 `删除`；英文 `dsh-trash-guard`、`index.js` |
| 真干活了没 | `<workspace>\_trash\.shadow\`、`<workspace>\_trash\manifest.jsonl` | `_trash`、`"op":"trash"`、`"op":"restore"` |
| 工具注入模型没 | `<DSH_HOME>\sessions\...\session.v4.jsonl.zstd`（zstd 解压后搜） | `tool-addition`、`"toolName":"trash"` |
| 有没有独立日志文件 | `D:\...\.dsh\` 下只有 `data\desktop-notice\notice.log` 与 `continue-guard\guard.log` | **没有**本插件的日志文件，别白搜 |

验证过程与结果（2026-11-10）：

1. `node <dsh>/lib/bin.js --profile web --dump-config` → exit 0，组合树里出现该条目；
2. `import()` 拿到 `{ apply, inject, name }`，`inject = ['tools']`；
3. 工具调用后 `<workspace>/_trash/.shadow/` 自动出现、镜像与原文件同 file ID（硬链接）→ `tools/pre-execute` 钩子在真实 dsh 进程里运行；
4. 会话日志出现 `tool-addition: trash, restore` → 两个工具已注册（fiberPhase=active）；
5. `trash` → `restore` 往返实测：样本 113 B / SHA256 `104AC565…` 移入 `_trash/<stamp>/1-样本.txt`、manifest 记 `op=trash`，restore 后回到原位且哈希逐字节一致、manifest 追加 `op=restore`；
6. 插件自带三套断言全过：`smoke` 54 项、`e2e` 145 项、`extreme` 41 项 → 240 项 `ALL PASS`（exit 0）。

改动前的备份：patch 在 `D:\Users\Administrator\.dsh\backup\dsh-patch-backup\cordis.patch.yml_<时间戳>.bak`，插件文件在 `D:\Users\Administrator\.dsh\backup\dsh-plugin-backup\<时间戳>\`。

**卸载**：删掉那段 `- insert:` 块，重启 dsh 即可；`_trash/` 留着不影响任何东西。

> ⚠️ **热重载不可靠**：Node 的 ESM 按 URL 缓存，改 `index.js` 不会重新 import；反复改 `cordis.patch.yml` 里的插件条目还可能出现"钩子还在、`trash` 工具却没了"的半挂载状态（本机踩到过）。**改完代码或配置，直接重启 dsh。**

**装到别的 profile**：每个 profile 各有自己的 `cordis.patch.yml`，把上面那段插进去即可（`name` 用同一个绝对 file URL）。

## 5. 配置

| 字段 | 默认 | 说明 |
|------|------|------|
| `trashDir` | `_trash` | 垃圾箱目录，相对工作区。须与工作区同卷才能 `rename` |
| `workspace` | 宿主 cwd | 工作区根；不给就用 `process.cwd()` |
| `denyOutsideWorkspace` | `true` | 拒绝把工作区外的路径移进垃圾箱 |
| `scanScriptWrites` | `true` | 扫描 `write` 写出的脚本正文 |
| `scanLaunchedScripts` | `true` | 启动命令里引用的 `.ps1/.bat/.cmd/...` 在启动前读正文扫描（含脚本间递归） |
| `allow` | `[]` | 例外白名单（正则源串），命中即放行 —— 逃生门 |
| `shadow.enabled` | `true` | 影子层总开关 |
| `shadow.maxFiles` | `20000` | 单次扫描上限；达到上限本轮放弃全量建影并告警 |
| `shadow.skipDirs` | `.git, node_modules, __pycache__, .venv` | 不建影的顶层目录 |

## 6. 垃圾箱结构

```
_trash/
  manifest.jsonl          # 每行一条：op / id / from / to / kind / note
  <UTC 时间戳>/
    1-原文件名            # trash 工具移进来的
    2-...
  .shadow/                # 影子层：工作区文件的硬链接（同 inode，不复制字节）
  .retired/               # 已被 trash 工具结案的影子（避免重复记账）
```

`restore({ ids: [...] })` 按 id 原样移回；`restore({ ids: ["?"] })` 只列出最近可恢复的 20 条。

## 7. 验证

```powershell
node test/smoke.mjs     # 54 项：挂载、schema、判定表、trash/restore、影子层
node test/e2e.mjs       # 145 项：真实文件的 .ps1/.bat 启动扫描 + 命令层全表 + 长脚本/编码 + 逃逸样本
node test/extreme.mjs   # 41 项：极端案例（编码矩阵/折行变形/启动形态/路径对抗/压力/健壮性/误伤回归）
```

三套共 **240 项断言全过**（`ALL PASS`）。另有 **真实环境端到端验证**（2026-11-10，在 `测试临时\_sandbox` 内限定范围实测，见 `经验记录.md` 结论 11）：
- 启用插件时，`Remove-Item` / `cmd /c "del /f /s /q …"` / `rd /s /q` / `.Delete()` / 含删除的 `.ps1` `.bat` 全部被拒，夹具 4/4 存活；
- 把插件从 profile 注释掉后，同一条 `Remove-Item` **真的删掉了文件**；重新启用后又恢复拦截。

e2e 的分节结果：

```
66/66  A 命令层      # pwsh + cmd 的各种删除写法（含管道、脚本块、forfiles、.NET、方法调用）
 6/6   B 写入侧      # write 出 .ps1/.md 的判定
21/21  C 启动侧      # 真实 .ps1 文件：-File / & / Start-Process / 嵌套 / 带空格路径 / 无害放行
28/28  D 批处理      # 真实 .bat/.cmd：行首 del、if exist ... del、for ... do rd、call 子批、echo 不误伤
 3/3   E 逃逸        # 主动构造的绕过样本（如实记为放行，由影子层兜底）
16/16  H 长脚本      # ≈300KB/≈800KB 长脚本、删除埋在中段、UTF-16LE/UTF-8 BOM、反引号折行、函数内删除、60KB 内联命令
 4/4   F 影子层      # 建影 → 文件消失 → 收箱 → 内容完好 → restore 复位
 1/1   G 真实执行    # 无害 .ps1 用 powershell.exe 真跑一遍，确认没被误伤
```

> 测试里的删除指令只作为"被检测的输入样本"或写进 `测试临时\_sandbox\` 的惰性夹具，**一条都没执行**；需要"删除已发生"的场景统一用 `rename()` 移走模拟（等价效果、零删除调用）。

## 8. 已知边界

1. **影子层按工具调用边界收敛**：删了之后要到"下一个改动型工具调用"才进箱；如果之后再无调用，则停留在 `.shadow/` 里（内容仍在，不会丢）。
2. **硬链接要求同卷**：工作区与 `trashDir` 跨卷时，影子建不起来（会告警跳过，不影响主流程）。
3. **`.shadow/` 会让 `grep -r` 之类的全盘遍历看到重复路径**；`trashDir` 名建议保留前导下划线/点，并加入项目忽略规则。
4. **大工作区的影子层成本**：已用**父目录 mtime 增量**优化（目录 mtime 没变就不 stat 其子项），本机 300 文件实测：首次建影 0.58s、**稳态重扫 14ms**（优化前 0.49s）。默认 `maxFiles: 5000`，超限当轮只处理前 5000 个变更文件并告警（多轮自然收敛）。
5. **启动扫描的三条硬边界**：路径要能静态解析出来（`& $cmd`、`& "$dir\x.ps1"` 这类变量算路径的解析不出）；单文件超过 `maxScriptBytes`（默认 8MB）时只扫前 8MB；脚本间递归深度 ≤2（4 层链会漏）、总数 ≤24。
6. **启动扫描的已知误伤面**：`@"..."@` here-string 里成段出现的 `Remove-Item` 文字会被当成删除动作拒绝——它的设计取向是"宁可多拦一次，让人来解释"。
7. **编码已处理**：按 BOM 解码（UTF-16LE/BE、UTF-8 BOM），无 BOM 时按 NUL 占比猜 UTF-16——PowerShell 5.1 的 `>` / `Out-File` 默认写 UTF-16LE，不处理就会整篇扫不到。
7. **不接管宿主自带的 `fs` 工具删除路径**（`fs/delete-intent` 钩子没接）：本 profile 没有独立 delete 工具，`apply_patch` 默认关闭；若将来开了，另加一个钩子即可。
8. 本插件**不做** Windows 回收站集成（它会被系统按配额自动清空，且需要 `IFileOperation`，与本机"零删除"约定冲突）。
