# mosdns

Go 版保持现有 coremain/pkg/plugin 分层和 sequence 设计，配置支持 YAML/YML/JSON。HTTP/2 和缓存 gzip 使用标准库，缓存 v2 文件格式保持兼容；指标使用 [`pkg/metrics`](pkg/metrics/README.md) 的文本输出，业务指标名与标签保持，部分 Go/进程指标和自定义 Go 插件接口有调整。默认不注册 profiling 路由，调试构建使用 `go build -tags=pprof`。Cobra、Zap、DoQ 和 DoH3 保留。HTTP/2 响应头上限仍为 4096 B，标准库映射同时把上游 HTTP/1 响应头上限收紧到 3776 B。行为回归数据位于 [`tests/fixtures`](tests/fixtures/)。

Go 还提供 `mosdns_minimal` 构建标签，只保留当前 CN-site 分流需要的 UDP/TCP、域名规则、内存缓存、sequence 和 nftset。全功能与最小版的能力范围、构建脚本和配置示例见 [Go 两版本说明](docs/go-profiles.md)。最小版不含 HTTP API、业务指标、磁盘 dump 或加密 DNS；两版都可独立运行，不需要预先安装 Go runtime。

后续在本地编写代码，在 GitHub Actions 编译和运行源码回归，再下载绑定提交 SHA 的产物进行本地与目标设备验证。流程见 [远端编译与下载验证](docs/go-remote-build.md)。

功能概述、配置方式、教程等，详见: [wiki](https://irine-sistiana.gitbook.io/mosdns-wiki/)

下载预编译文件、更新日志，详见: [release](https://github.com/IrineSistiana/mosdns/releases)

docker 镜像: [docker hub](https://hub.docker.com/r/irinesistiana/mosdns)
