# 可重复的 Go 测试工作流

入口是 [`.github/workflows/test-plan.yml`](../.github/workflows/test-plan.yml)。测试使用同一个提交的 Go full、minimal 和测试工具，自动部署临时测试环境，保留每个阶段的结果和原始记录，再生成 Markdown、HTML 和 JSON 报告。旧的 131 成绩不作为本次运行的成绩。

## 执行范围

| 阶段 | 环境 | 验证内容 | 结果名称 |
| --- | --- | --- | --- |
| 功能回归 | GitHub Ubuntu runner | full/minimal/full-pprof 全套 Go 测试、Python 控制器回归 | `unit-full`、`unit-minimal`、`unit-full-pprof` |
| 并发回归 | GitHub Ubuntu runner | 域名匹配、query_context、cache、concurrent_map 和 cache 插件的 race 检查 | `race-full`、`race-minimal` |
| 构建 | GitHub Ubuntu runner | 固定 Go 1.26.0，构建 amd64/arm64 的 baseline/full/minimal、dnsbench、routerproxy；记录大小及 SHA256 | `build-amd64`、`build-arm64` |
| 受控性能及 nftset | GitHub Ubuntu runner 的独立 network namespace | 合成 CN-site、确定性 DNS 上游、热/冷缓存、UDP/TCP、并发 1/4、交替顺序两轮；原生 nftset 学习与缓存重建 | `hosted` |
| 131 实际分流 | 手动请求的私有 self-hosted runner | 通过 SSH 部署隔离测试，验证真实默认 DNS、WireGuard 出口、集合及资源恢复 | `router131` |
| 复杂页面 | 同一个私有 runner | QQ/淘宝首次及重复加载、多资源访问、DNS 与集合观测 | `pages131` |

默认运行 hosted 阶段。访问私有设备的阶段仅从手动 `workflow_dispatch` 入口请求，使用 `router131` GitHub Environment 和 `mosdns-lab` runner 标签。GitHub 托管 runner 不能直接访问 `192.168.100.131`。PR 测试不取得路由器凭据。

在 Actions → Reproducible test plan → Run workflow 选择分支，填入 `expected_commit` 的完整 40 位提交。设备测试只允许 `main`：勾选 `router`；需要页面测试时同时勾选 `pages`。`pages=true` 要求 `router=true`，输入提交必须与实际 checkout 一致。

**hosted 的 DNS 响应和 111,361 条域名是合成数据。** 这轮结果验证实现、性能变化和 Linux nftables 行为，不代表完整真实 CN-site 名单、公网 DNS、131 的 CPU/内存表现、WireGuard 或网页表现。报告将两个环境分开列出。

## 构建与基准条件

baseline 固定为上游提交 `9cfb7ce985599c087cb7ccfb1531d0c0f4021242`。它与当前 full/minimal 使用相同的 Go 版本、目标架构及去符号构建参数：`CGO_ENABLED=0`、`-mod=readonly -trimpath -buildvcs=false -pgo=off -p=2` 和 `-s -w -buildid=`。baseline 的版本字符串绑定 baseline 提交，其他产物绑定当前提交。

二进制大小按 ELF 原文件字节数统计；bundle 记录文件 SHA256、源码提交和架构。报告计算同架构 baseline→full、baseline→minimal、full→minimal 的大小变化。这些文件未使用 UPX。

hosted 基准一次只运行一个版本。热缓存先预热，冷缓存使用唯一查询名；正式样本之前单独校准固定查询次数，同一场景的三个版本使用相同次数。默认两轮、第二轮反转版本顺序，共 48 行。`--requests` 可指定固定次数，避免校准；短样本仍保留，但不能据此宣称吞吐提升。

QPS 为成功请求数除以整行持续时间；P50/P95/P99 只统计成功 exchange。错误、超时、RSS/HWM、cgroup 信息与性能指标分别记录。资源限制使用已经委派的 cgroup 控制器；hosted 使用 64 MiB 内存上限和 `GOMEMLIMIT=48MiB`，控制器不可用时记录覆盖限制，不修改 root 控制器。它与此前 131 的 32 MiB 历史矩阵属于不同环境，不能直接拼接比较。

hosted 已观测到旧 baseline 的 UDP/TCP 读取超时和 `dns: id mismatch`。仅这两类 baseline 错误允许继续收集剩余矩阵；该行仍标为失败，排除性能比较，整个 suite 仍失败。full/minimal 的任何错误、错误回答或未识别的 baseline 错误会立即终止，保留原始日志与资源记录。所有版本使用相同的 2 秒查询期限。

## 私有测试环境部署

在能访问 131 的 Linux X64 机器安装 Python 3.9+（含 venv）、OpenSSH 客户端及 Chromium 系统依赖。通过仓库 Settings → Actions → Runners → New self-hosted runner 获取官方 Linux X64 archive 及 SHA256，下载后运行：

```sh
bash scripts/testworkflow/install-runner.sh \
  --archive /absolute/download/actions-runner-linux-x64-VERSION.tar.gz \
  --sha256 OFFICIAL_ARCHIVE_SHA256 \
  --directory /absolute/private/mosdns-runner-unique \
  --repo xfy-see/mosdns
```

脚本强制校验 archive SHA256，拒绝已有目录、checkout 内目录、root 用户和不安全压缩包路径。GitHub 官方 `config.sh` 交互请求新注册 token，脚本不从已有凭据中读取 token。默认添加 `mosdns-lab`，runner 的默认标签提供 `self-hosted`、`Linux`、`X64`。使用 ephemeral 模式接一个 job 后退出并注销；下次运行需要新的临时 runner 目录与注册 token。`--extract-only` 可先校验和解包。[GitHub 官方 ephemeral runner 说明](https://docs.github.com/en/actions/reference/runners/self-hosted-runners)。

runner 运行账户应能创建自己的临时目录。页面阶段在 `RUNNER_TEMP` 创建 Python venv，按版本化 `pages-requirements.txt` 安装 Playwright 和 Chromium，结束后删除该临时 venv。测试二进制从同一轮 hosted 构建下载，私有 runner 不编译 Go。

在仓库 Settings → Environments 建立 `router131`，限定允许执行的分支；如需额外审批，可配置 reviewers。手动触发前，源码和远端构建产物均可审阅。不要把 self-hosted runner 开放给不受信任的 PR。

设备私有配置、SSH 私钥、固定 `known_hosts` 和完整 CN-site/CN-IP 数据应放在 runner 的受限目录，**位于仓库 checkout 和结果目录之外**。复制 [`router-config.example.json`](../scripts/testworkflow/router-config.example.json) 到该目录，填写真实路径、已核对的 SSH 指纹、现有 WireGuard/直连接口及 mark。在 `router131` Environment 的 Variables 设置 `MOSDNS_ROUTER_CONFIG` 为该私有 JSON 的绝对路径。不要把私钥、WireGuard peer 配置写入仓库、日志、Actions artifact。

131 的 `/root` 必须有足够闪存容纳本轮完整 payload，并保留 32 MiB 余量；脚本在创建资源前和上传前分别检查，进程日志有单文件大小上限。

131 必须已有可用的 WireGuard peer、相应 mark 路由、nft socket cgroupv2 支持，以及已委派 memory/pids 控制器的测试 cgroup parent。预检发现缺失时返回 `blocked`，保留诊断；正式测试部署自己拥有的应用、临时集合、代理和监听。首次部署前核对 131 的当前固件、SSH 主机密钥和可用资源；不能沿用历史 boot ID 或默认 DNS 地址作为本次证明。可先单独预检：

```sh
python3 scripts/testworkflow/router.py \
  --config /absolute/private/router131.json \
  --artifacts /absolute/download/test-plan-build-arm64 \
  --commit FULL_40_CHARACTER_COMMIT_SHA \
  --output /absolute/results/new-router-preflight \
  --preflight-only
```

正式执行在相同参数上使用 `--run`，页面测试再加 `--pages-script /absolute/checkout/scripts/testworkflow/pages.py`。输出目录必须是新目录；预检与正式阶段分开保存，失败样本不会被重试覆盖。

设备阶段使用独占锁、唯一测试目录、独立端口和 nft 表，部署结束后关闭测试进程、删除本轮拥有的规则和目录，再验证设备状态恢复。真实 DNS 策略为：CN-site → 本次发现的默认 DNS、直连；其他域名 → `1.1.1.1:53`、WireGuard。国内首查 `223.5.5.5` 和按 CN-IP 筛选 DNS 回答不属于该策略。页面测试代理对匹配 CN-site 的域名或命中静态 CN-IP 的目标使用直连，其余使用 WireGuard；实际出口通过接口规则和计数验证。代理不读取动态学习集合，因此仅由学习集合决定出口的其他别名场景尚未覆盖，不能用 DNS 上游方向代替网站出口证明。

设备阶段要求前置回归、构建和 hosted 阶段成功；即使 hosted 仅有旧 baseline 错误，它仍会失败并阻止部署 131。脚本已实现不代表实机测试已执行，最终报告分别记录这些状态。

131 的受控矩阵先以配置中的 `benchmark.queries`（默认 2,000）执行独立校准，再按每个场景最快三个版本的观测，确定三版共用的固定查询数，目标时长为 `minimum_seconds + 1`、上限 100,000。校准单独标记 `excluded_from_formal`，不进入正式性能比较。正式矩阵热/冷 × UDP/TCP × 并发 1/4 × baseline/full/minimal × 两轮共 48 行；三版同一单元使用相同查询名及字节。显式关闭矩阵会使完整 `router131` suite 显示 `blocked`，保留已经执行的功能回归成绩。

集合生命周期记录首次学习、缓存重建、手工删除、再次写入及自然过期；在 timeout 的一半再次进行缓存查询，要求无上游包，并检查原过期边界是否被延长。计时包括 SSH、调度和快照开销，报告保留最大轮询间隔及观测边界，不将其称为内核 syscall 耗时。

复杂页面使用 131 上的临时代理，让源站 DNS/TCP 由 131 发起；HTTPS 保留证书校验。每个版本访问 QQ 和淘宝的首次/重复页面，观察 DOM 就绪后资源及滚动触发的请求。页面资源失败、公网限速或网站限制要保留原始记录，并与 DNS 阻塞分别解释。AAAA 集合学习不证明公网 IPv6 页面传输。

## 版本化脚本

| 文件 | 作用 |
| --- | --- |
| [`scripts/testworkflow/validate.py`](../scripts/testworkflow/validate.py) | 运行 profile/race 回归，保存 Go JSON 事件、退出码和 suite 结果 |
| [`scripts/testworkflow/build.py`](../scripts/testworkflow/build.py) | 在 GitHub Actions 构建固定 baseline 和当前 profiles，生成 `bundle.json` |
| [`benchmarks/build-go-profiles.py`](../benchmarks/build-go-profiles.py) | 冻结构建输入、参数、依赖和 profile manifest |
| [`benchmarks/dnsbench/main.go`](../benchmarks/dnsbench/main.go) | mock/load/probe，测量 DNS 语义、成功 QPS 和延迟 |
| [`scripts/testworkflow/hosted_lab.py`](../scripts/testworkflow/hosted_lab.py) | 自动创建隔离 Linux namespace、合成名单、上游、性能矩阵及 nftset 测试，再清理 |
| [`scripts/testworkflow/deploy-lab.sh`](../scripts/testworkflow/deploy-lab.sh) | 检查 Linux namespace/nftables 环境前置条件 |
| [`scripts/testworkflow/install-runner.sh`](../scripts/testworkflow/install-runner.sh) | 校验官方 runner archive，部署仓库外的 ephemeral Linux X64 runner |
| [`scripts/testworkflow/router.py`](../scripts/testworkflow/router.py) | 校验 bundle 与 SSH 主机、预检 131、部署隔离实例、测试并精确清理 |
| [`scripts/testworkflow/router-config.example.json`](../scripts/testworkflow/router-config.example.json) | 私有设备配置字段模板，实际配置在 runner checkout 外 |
| [`scripts/testworkflow/pages.py`](../scripts/testworkflow/pages.py) | Chromium 经回环 SSH 代理访问 QQ/淘宝，保留页面数据和截图 |
| [`scripts/testworkflow/pages-requirements.txt`](../scripts/testworkflow/pages-requirements.txt) | 固定页面测试的 Python 依赖版本 |
| [`benchmarks/routerproxy/main_linux.go`](../benchmarks/routerproxy/main_linux.go) | 131 上的临时 HTTP/HTTPS CONNECT 代理，经测试 DNS 解析并带 mark 建立源站连接 |
| [`scripts/testworkflow/report.py`](../scripts/testworkflow/report.py) | 汇总 suite JSON、Go 事件和 binary manifest，生成报告及 Actions Summary |

所有脚本源码随工作流提交，可以直接审阅、复用及修改。设备和页面脚本的参数也随仓库版本固定；私有部署配置不包含在公开代码中。

## 本地查看和重新生成报告

本地负责代码编辑、下载产物和检查证据。下载某次 workflow 的结果 artifact，保持各 suite 子目录及原始文件的相对结构；打开 `test-plan-report/report.html`，或者重新生成：

```sh
gh run download RUN_ID --repo xfy-see/mosdns \
  --pattern 'test-plan-report-*' --dir .build/test-plan/RUN_ID
```

该 artifact 同时包含 `test-plan-report/report.html` 和 `test-plan-evidence/`；解压后保留两者的相对位置。GitHub CLI 可能另创建 artifact 名称子目录，直接进入该子目录查看上述文件。也可在 Actions 页面下载 ZIP。只需重新生成报告时，使用下面的 CLI；输入目录对应下载内容中的 `test-plan-evidence/`。

```sh
python3 scripts/testworkflow/report.py \
  --input .build/test-plan/RUN_ID/test-plan-evidence \
  --output .build/test-plan/RUN_ID/test-plan-report \
  --commit FULL_40_CHARACTER_COMMIT_SHA \
  --required-suites unit-full,unit-minimal,unit-full-pprof,race-full,race-minimal,build-amd64,build-arm64,hosted
```

请求了设备或页面阶段时，将 `router131` 或 `pages131` 加入 `--required-suites`。这样，即使设备 job 没有启动、前置阶段失败或 runner 不可用，报告也会把缺失阶段列为 `blocked` 并返回非零退出码。未请求的设备/页面阶段显示 `skipped`。每个结果都必须绑定报告的完整源码提交，不能把另一轮或历史数据放入目录后合并成成功。

工作流通过 `--github-summary "$GITHUB_STEP_SUMMARY"` 展示阶段、检查、性能数据、大小变化和原始证据链接。artifact 同时保留 `report.md`、可离线打开的 `report.html`、机器可读的 `results.json` 及原始日志。Actions Summary 中的相对原始链接用于对应 artifact 内容；完整离线浏览应下载并解压整个证据 artifact。报告不会自动发布公网测试页面。

## Suite 结果协议

每个阶段写入如下结构。`artifacts` 路径可相对于 suite JSON 所在目录，或整个输入证据目录；绝对路径、`..`、符号链接和逃出输入目录的路径被拒绝。

```json
{
  "schema_version": 1,
  "suite": "hosted",
  "status": "passed",
  "source_commit": "FULL_40_CHARACTER_COMMIT_SHA",
  "checks": [{"name": "DNS response semantics", "status": "passed", "detail": "A/AAAA, ID, Question and TTL checked"}],
  "measurements": [{"profile": "minimal", "cache": "hot", "protocol": "udp", "qps": 1234, "p95_ms": 0.8, "rss_kib": 12000}],
  "environment": {"kind": "hosted-synthetic", "architecture": "amd64"},
  "limitations": ["Synthetic upstream; not a real router measurement"],
  "artifacts": [{"path": "benchmark.json"}]
}
```

示例中的数值仅说明格式。状态为 `passed`、`failed`、`blocked` 或 `skipped`；失败检查不能被 suite 的 `passed` 覆盖。相同 suite 重复出现、源码提交不一致、文件身份不一致和必需阶段缺失都会使报告失败。Go 事件计数包含子测试，不等于独立测试案例数量；没有测试文件的 package skip 单独显示。
