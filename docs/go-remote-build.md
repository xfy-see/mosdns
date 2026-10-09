# Go 远端构建与本地验证

Go 的代码修改在本地完成，提交到 GitHub 后由 [Go profiles workflow](../.github/workflows/go-profiles.yml) 负责测试与编译。本地下载同一 commit 的成功产物，再执行配置检查、131 分流与性能测试；下载工具不调用 Go 编译器，也不安装或运行下载的程序。

## 远端流水线

修改 Go 源码、模块依赖、共享测试输入或构建流水线后，push 自动触发；pull request 执行同样的测试，生产产物仅由 push/手动运行发布。可通过 `workflow_dispatch` 手动构建已推送的分支，必须指定精确的 `expected_commit`。若分支在提交请求后移动，流水线失败，避免编译另一个 commit。

编译器固定为 **Go 1.26.0**，运行环境为 Ubuntu 24.04。先执行三个完整测试版本 `full`、`mosdns_minimal`、`pprof`，以及 full/minimal 两组关键包 race：域名匹配、请求上下文、缓存、并发 map、缓存插件。full 测试任务还执行 Python 标准库的 release 与下载验真回归，不调用本地 Go 编译器。所有测试成功后，复用 [冻结输入构建脚本](../benchmarks/build-go-profiles.py) 交叉编译 Linux ARM64 与 amd64 的 full/minimal。CI 测试在 Linux amd64 执行，ARM64 的实际运行验证仍由 131 承担。

生产产物 `CGO_ENABLED=0`，不启用 pprof、不使用 UPX，目标基线分别为 `GOARM64=v8.0`、`GOAMD64=v1`。编译参数与当前生产版本一致：

```text
-mod=readonly -trimpath -buildvcs=false -pgo=off -p=2
-ldflags="-s -w -buildid= -X main.version=git-<完整 commit SHA>"
```

每种架构发布一个 artifact，名称包含架构、完整 commit SHA、run attempt，避免将重新执行前后的产物混用。artifact 内有 full/minimal ELF、`manifest.json`、`.tar.gz` 包和 `SHA256SUMS`。压缩包还保存此次构建的冻结源码、依赖图和命令日志；不上传设备配置、凭据或历史性能报告。二进制保留 30 天，测试日志保留 14 天，可从同一 commit 再次触发构建。

manifest 绑定项目输入 SHA256、输入树摘要、生产依赖图、Go 版本与编译器摘要、参数、架构，以及 GitHub 仓库、commit、run ID、attempt 和工作流/构建脚本摘要。发布阶段逐项核对冻结源码与该 commit 中的 Git blob。

## 本地操作

准备 Python 3.9+ 和已登录的 GitHub CLI。通过 `gh auth login` 登录；也可由 CLI 读取已经配置的 `GH_TOKEN`，不要把凭据写入命令参数、仓库或测试报告。脚本的 `--repo` 和 `--commit` 必须显式给出，不能使用缩写 SHA 或“最新成功产物”。

查看同一 commit 的运行记录：

```sh
python3 scripts/go-remote-build.py list \
  --repo OWNER/REPOSITORY --commit FULL_COMMIT_SHA
```

下载已有成功运行的两种架构产物：

```sh
python3 scripts/go-remote-build.py download \
  --repo OWNER/REPOSITORY --commit FULL_COMMIT_SHA --run-id RUN_ID
```

手动触发已推送的分支，等待成功并自动下载：

```sh
python3 scripts/go-remote-build.py build-wait \
  --repo OWNER/REPOSITORY --commit FULL_COMMIT_SHA --ref codex/BRANCH
```

可指定 `--arch arm64` 仅下载 131 所需的架构，或用 `--gh /path/to/gh` 指定 CLI。默认等待上限 3,600 秒，每 30 秒查询状态；超时不会取消已提交的运行，错误不会自动重试或删除现场。

下载到仓库 `.build/github-actions/<run-id>/linux-arm64/` 和 `linux-amd64/`，已有 run 目录一律拒绝覆盖，包括失败的下载。根目录记录 `github-run.json` 与 `verification.json`。只使用 `verification.json` 中 `status: verified` 的文件：校验包含远端整个运行成功、commit/工作流/run/attempt 身份、文件 SHA256、manifest、构建参数、ELF 架构及无动态解释器、包内外二进制一致、冻结源码和流水线文件与 GitHub commit 的 Git blob 一致。

校验通过后，对下载的 ARM64 ELF 做本地/131 隔离验证：先核对 `version`、配置检查和启动/退出，再用独立端口对 full/minimal 执行相同的 UDP/TCP、热/冷缓存及并发 1/4 基准；真实分流中核对 CN-site 查询当次默认 DNS、其他域名经 WireGuard 查询、缓存命中重建 `cn_site4/6`、错误出口计数为零，并测试 QQ/淘宝页面的多次集合写入。每轮记录 boot ID、CPU/RSS、延迟、QPS、超时、OOM 及网络恢复情况。

将 commit、run ID、版本、文件 SHA256 与下载验证记录一起绑定到本地测试报告。设备地址、接口、路由、规则及凭据留在本地，不提交到公开仓库。构建成功与下载校验不代替实际分流、性能、稳定性测试。不要修改已下载的 ELF；新代码重新提交，使用新的成功 run。

没有本地 `gh` 时，可由 GitHub API/插件下载 artifact，并保存该运行的 `GET /repos/OWNER/REPOSITORY/actions/runs/RUN_ID` 与 `GET /repos/OWNER/REPOSITORY/git/trees/FULL_COMMIT_SHA?recursive=1` 原始 JSON，再执行相同的离线内容校验：

```sh
python3 scripts/go-remote-build.py verify \
  --repo OWNER/REPOSITORY --commit FULL_COMMIT_SHA --arch arm64 \
  --artifact-dir .build/github-actions/RUN_ID/linux-arm64 \
  --run-json .build/github-actions/RUN_ID/github-run.json \
  --tree-json .build/github-actions/RUN_ID/github-tree.json \
  --receipt .build/github-actions/RUN_ID/verification-arm64.json
```

`verify` 不刷新运行状态，输入 JSON 应来自刚完成的 GitHub API 读取；输出会记录这一限制及两份元数据 SHA256，校验记录也拒绝覆盖。

当前实现使用 GitHub Actions。尚未配置应用 Your dot 的构建后端；如果后续改用它，仍应保留精确 commit、输入/工具链/参数 manifest 和下载后校验的边界。
