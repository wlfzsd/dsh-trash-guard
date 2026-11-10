# dsh-trash-guard

> 给 DeepSeek Harness（DSH）用的小插件：把 AI 的"删除"从**销毁字节**改成**移进工作区垃圾箱**，并且在拦截时明确告诉模型下一步该做什么。
>
> 单文件、零依赖、只用 `node:` 内置模块；不 import 任何 DSH 包（profile 里没有 node_modules 也能跑）。

---

## 一、它解决什么问题

| 真实事故形态 | 不装它会发生什么 | 装了它怎么处理 |
|---|---|---|
| AI 写出 `Get-ChildItem -Recurse -Force \| Remove-Item -Force`、`cmd /c del /s /q`、`rd /s /q`、`foreach{ $f.Delete() }` 这类**递归/循环/通配**删除 | 一条命令清掉整个目录树，且**没有回收站、没有台账** | **执行前**（`tools/pre-execute`）直接拒绝，命令根本不会跑；拒绝理由里点名"递归/通配/盘符根/循环/管道/强制"这些放大因子 |
| AI 把删除写进 `.ps1` / `.bat` / `.py` 再启动 | 命令文本里看不到 `Remove-Item`，只看到 `pwsh -File x.ps1` | **启动前**把脚本正文读出来扫（含脚本间递归），有删除动作就拒绝；`write` 写脚本时也扫正文 |
| 真发生了删除（原生 exe、下载的脚本、变量拼出的路径） | 文件没了就没了 | **影子层**：每次改动型工具调用前给工作区每个文件建硬链接；下次调用时发现"影子还在、原文件没了"，就把影子（握着原 inode）收进垃圾箱 |
| 删错了想恢复 | 靠回忆、靠备份软件、靠运气 | 所有删除只产生**一种状态**：`_trash/<时间戳>/` + `_trash/manifest.jsonl` 台账；`restore({ids})` 或 `restore({paths})` 按**原始路径批量还原**，原位置被占用时记 `failed` 而不是覆盖 |
| 被拦之后 AI 反复重试、不知道怎么改，最后乱写 | 死循环烧 token，或者换个写法绕过 | **三段式拒绝文案**：①你被拦了+原因 ②唯一替换指令（`trash`）③提交前必须自查的 5 项；并声明"原样重试/换写法同样被拒、不要连试" |
| 备份/恢复源自己也被递归操作带走 | 删工作区根 → 连 `_trash` 一起没了 | `_trash` **自保护**：目标包含 `_trash` 就拒绝整体移动；影子层按路径段名跳过 `_trash` |

一句话：**它不阻止"删除"这个需求，只强制"删除"走一条可审计、可恢复、且只产生一种状态的路径。**

---

## 二、执行逻辑（三层拦截 + 两个工具）

插件通过 DSH 的 `tools` 服务挂载（`export const inject = ['tools']`），在 `apply(ctx)` 里做三件事：

```
                 ┌─────────────────────────────── 模型发起一次工具调用 ───────────────────────────────┐
                 │                                                                                 │
  ① 文本层 deny  │  ctx.on('tools/pre-execute', handler, { prepend: true })                        │
   (执行前)      │    · pwsh / bash  → 扫命令字符串（12 条规则）                                     │
                 │    · write        → 扫要落盘的脚本正文（.ps1/.bat/.sh/.py/...）                    │
                 │    · apply_patch  → 扫 "*** Delete File:"                                        │
                 │  命中 → 返回 { kind:'deny', reason: <三段式文案>, info:{code:'DELETE_BLOCKED'} }  │
                 │  未命中 ↓                                                                        │
  ② 启动前扫描    │    · 命令里要启动的脚本 → 读正文再扫（递归 ≤2 层、≤24 个文件、单文件 ≤8MB）        │
                 │      -File / & x.ps1 / Start-Process / cmd /c x.bat / call x.bat                │
                 │  命中 → 同样 deny                                                               │
                 │  未命中 ↓                                                                        │
  ③ 顺带维护影子  │    · 改动型工具（pwsh/bash/write/edit/apply_patch/trash/restore）调用前：          │
                 │      先"收尸"（影子有、原文件没了 → 移进 _trash 并记账），再"建影"（硬链接，不复制字节）│
                 │    · 全程只用 link() / rename()，不调用任何删除 API                                │
                 └─────────────────────────────────────────────────────────────────────────────────┘

  ④ 两个工具：trash({ paths, note }) —— 唯一的"删除"实现：rename() 进 _trash/<时间戳>/N-原名 + 追加 manifest.jsonl
             restore({ ids }) / restore({ paths }) —— 按 id 或原路径（manifest 的 from 字段）批量还原
```

### 2.1 文本层命中的规则（12 条）

`Remove-Item / Clear-Item / rm / del / erase / rd / rmdir / unlink`、`Clear-Content`、`Set-Content -Value ''/$null`、`.NET ::Delete`、对象上的 `.Delete()`、`git clean / reset --hard / checkout -- .`、`-EncodedCommand`、`robocopy /MIR|/PURGE`、`shutil.rmtree / os.remove / fs.rm` 等脚本 API、`diskpart / Clear-Disk / Format-Volume`、`Move-Item -Force`（覆盖即消失）、`cmd /c del|erase|rd`。

**为什么循环也能拦**：删除动词只允许出现在 `^`、换行、`;`、`|`、`&`、`(`、`{` 之后（语句起始锚点）。所以
`Get-ChildItem -Recurse | Remove-Item`（`|` 后）、`foreach($f in $x){ $f.Delete() }`（`{` 后 + 方法规则）、
`while($true){ rm }`、`cmd /c "for /r %f in (*) do del %f"`（cmd-wrapper 规则）都会命中。

### 2.2 被拦时模型看到的文案（三段式）

```
【1｜你被拦截了】权限拒绝（DENY / code=DELETE_BLOCKED），本次调用没有执行：命令里出现删除类高危动作（…）。
   命中片段：…
【风险】本条指令被识别出的放大因子：递归遍历；盘符根路径（会波及整个盘）；循环构造；管道串联；强制开关…
【2｜换成这个】唯一合法做法（不要自选别的方案、不要跳步）：把"删"改成"移进垃圾箱" ——
   trash({ paths: ["<路径>"], note: "<为什么要移除>" })；落点固定 _trash/<时间戳>/ + manifest.jsonl。
   需要"清空/覆盖某文件"也只能先 trash 原件、再写新文件，禁止就地覆盖。
【3｜提交前必须自查（逐条写下结论再动手）】
   a) 范围有界吗：有没有盘符根、..、* / ? 通配、-Recurse / /s 这类会扩散到整棵树的东西？
   b) 有循环吗：for / foreach / while / 管道串联 会不会对"遍历出来的每一项"重复执行？
   c) 转义会让范围变形吗：引号、$()、反引号折行、变量展开会不会把字面路径变成通配或另一条路径？
   d) 会碰到恢复源吗：目标里有没有 _trash？
   e) 可回滚吗：_trash 里有副本、manifest 里有记录，才算可回滚。
【纪律】原样重试或换写法绕过都会得到同样拒绝，不要连试；只有 trash 返回 failed 才停止并上报。
【批量还原】恢复一律以 _trash/manifest.jsonl 为唯一台账：restore({ids}) 或 restore({paths})。
```

设计取舍（很重要）：

- **只有一条路**，不是"三选一"——避免模型每次随机挑一套方案，把文件改得乱七八糟；
- **降级是终点**：`trash` 返回 `failed` 就停手上报（`路径＋原始错误`），**不允许**改名 `.bak` 散落、不允许换别的删除写法；
- 放大因子只用于提示，**不参与 allow/deny 判定**（判定仍由规则表决定，避免"关键词恐惧"误伤）。

### 2.3 影子层（事后兜底，不关心是谁删的）

- 每次改动型工具调用前，为工作区每个文件在 `_trash/.shadow/` 建**硬链接**（同 inode，不复制字节）；
- 下一次调用前扫一遍：影子还在、原路径的文件没了 → 把影子（仍握着原 inode 的内容）`rename()` 进 `_trash/<时间戳>/` 并记账；
- 因此 `.ps1` 里的原生删除、exe、其它语言、运行期生成的脚本，**一律能收尸**；
- 优化：父目录 mtime 没变就跳过其子项（300 文件实测：首次建影 0.58s、稳态重扫 14ms）；
- 上限：默认 `shadow.maxFiles = 5000`，超限当轮只处理变更文件并告警。

### 2.4 自保护（备份不会被自己吃掉）

| 攻击面 | 行为 |
|---|---|
| `trash({paths:["<工作区根>"]})` 于是把含 `_trash` 的目录整体搬走 | 拒绝：`目标包含垃圾箱目录 …，拒绝对其整体移动` |
| `trash` 目标已经在垃圾箱里 | 拒绝：`目标已经在垃圾箱里，不需要再移一次` |
| 影子层把 `_trash` 也建影 | `isSkipped()` 按路径段名剔除 `_trash`，从不索引 |
| 删除命令指向 `_trash` | 文本层照拦（只看动作、不看目标） |

---

## 三、安装

### 方式 A（推荐）：当"包"装，设置里能显示中文名与中文介绍

```text
%DSH_HOME%\plugins\dsh-trash-guard\           ← 包本体（index.js / package.json / locale / test）
%DSH_HOME%\node_modules\dsh-trash-guard       ← junction → 上面那个目录（Node 按裸包名解析）
```

profile 的 `cordis.patch.yml` 加：

```yaml
- insert:
    - id: trash-guard
      name: 'dsh-trash-guard'
      config:
        trashDir: '_trash'
```

> 为什么必须用裸包名：DSH 的插件列表用 `readPluginMeta()` 取显示文本，而它只对**包名**生效；`file:///` 或绝对路径会被判为"非包"，列表里只剩路径短名、也没有介绍。

### 方式 B：直接引用文件

```yaml
- insert:
    - id: trash-guard
      name: 'file:///C:/Users/<you>/.dsh/plugins/dsh-trash-guard/index.js'
      config:
        trashDir: '_trash'
```

能正常拦截，但设置页不会显示中文名/介绍。

### 显示文本（`locale/*.json`）

语言 id 只认 `zh` / `en`（`LOCALE_IDS = ["zh","en"]`），写 `zh-CN.json` 会落空：

```json
{ "meta": { "title": "垃圾箱守卫（删除拦截）", "description": "把删除意图改道到工作区垃圾箱 _trash/，删除内容可随时恢复…" } }
```

---

## 四、配置

| 字段 | 默认 | 说明 |
|---|---|---|
| `trashDir` | `_trash` | 垃圾箱目录，相对工作区；须与工作区同卷才能 `rename` |
| `workspace` | 宿主 cwd | 工作区根；不给就用会话工作目录/进程 cwd |
| `denyOutsideWorkspace` | `true` | 拒绝把工作区外的路径移进垃圾箱 |
| `scanScriptWrites` | `true` | 扫 `write` 落盘的脚本正文 |
| `scanLaunchedScripts` | `true` | 启动命令引用的 `.ps1/.bat/...` 启动前读正文扫描（含递归） |
| `maxScriptBytes` | `8MB` | 单文件扫描上限 |
| `allow` | `[]` | 例外白名单（正则源串），命中即放行——逃生门 |
| `shadow.enabled` | `true` | 影子层总开关 |
| `shadow.maxFiles` | `5000` | 单次扫描上限 |
| `shadow.skipDirs` | `.git, node_modules, __pycache__, .venv` | 不建影的顶层目录 |

---

## 五、测试

三套断言，共 **240 项**，全部只喂字符串给分类函数、不执行任何删除：

```bash
node test/smoke.mjs     # 54 项：挂载、工具 schema、判定表、trash/restore 往返、影子层
node test/e2e.mjs       # 145 项：命令层 66 条 + 写入侧 + 真实 .ps1/.bat 启动扫描 + 长脚本/编码 + 逃逸样本
node test/extreme.mjs   # 41 项：编码矩阵、折行变形、启动形态、路径对抗、压力、健壮性、误伤回归
```

真机端到端也验证过（见提交历史/issue）：开启时递归删除命令被拒且文件哈希不变；关闭插件后同一命令真的销毁文件；`trash → restore` 往返内容逐字节一致。

---

## 六、边界（能做什么 / 不能做什么）

**做得到**

- 命令文本、脚本正文、启动脚本这三个入口的删除意图：执行前拒绝；
- 任何"文件消失"（含 exe/其它语言/运行期脚本）：影子层收尸进垃圾箱；
- 删除只产生一种状态（`_trash` + manifest），可按 id 或原路径批量还原。

**做不到（如实列）**

- **不接管 Windows 回收站**：系统回收站会按配额自动清空，且需要 `IFileOperation`，与本插件"零删除"取向冲突；
- 路径由**变量算出**的启动脚本（`& $cmd`、`& "$dir\x.ps1"`）解析不出，只剩影子层；
- 递归超过 24 个脚本 / 深度 >2 / 单文件 >8MB 的启动扫描会漏；
- 运行期下载、heredoc 拼出的脚本：写入层看不见，靠影子层；
- **`_trash` 必须与工作区同卷**（`rename` 需要），所以它待在工作区里；绕过文本层的原生程序在工作区内递归删，会连 `_trash` 一起波及——那一类只能靠沙箱 ACL + 不跑未审计二进制；
- 影子层按"下一次改动型调用"收敛：删完再无调用，内容会停留在 `.shadow/` 里（不丢，但未进垃圾箱）。

---

## 七、目录结构

```text
dsh-trash-guard/
├── index.js            # 全部实现（单文件，零依赖）
├── package.json        # name/description/keywords + exports（含 ./locale/*.json）
├── locale/
│   ├── en.json         # 英文显示名与介绍
│   └── zh.json         # 中文显示名与介绍（语言 id 只能用 zh / en）
├── test/
│   ├── smoke.mjs       # 54 项
│   ├── e2e.mjs         # 145 项
│   ├── extreme.mjs     # 41 项
│   └── probe-long.mjs  # 长脚本探针
└── README.md
```

垃圾箱结构：

```text
<workspace>/_trash/
├── manifest.jsonl          # 每行一条：op / id / from / to / kind / note
├── <UTC 时间戳>/           # 1-原名、2-...（trash 移进来的）
├── .shadow/                # 影子层：工作区文件的硬链接（同 inode，不复制字节）
└── .retired/               # 已被 trash 结案的影子（避免重复记账）
```

---

## 八、许可

MIT
