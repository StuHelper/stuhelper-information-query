---
type: index
status: Accepted
updated: 2026-11-22
---

# StuHelper 信息查询

更新日期：2026-11-22。

信息查询通过各业务模块的公开接口解析线索和查询记录，由本模块统一检查权限和范围。完整查询审计记录目标账号键和披露类别。批量预览只向发起人回显线索，预览审计以类型和摘要记录线索。业务模块各自管理数据和读取权限。

当前 develop 提供分组查询、审计查询、能力预检和管理端批量预览。宿主按线索类型和业务域注入解析器与提供方，独立维护身份负责到期清理。生产组合及候选功能状态见 [装配与实施状态](docs/development/integration.md#验证与剩余工作)。

- [HTTP 接口定义](contracts/information-query.openapi.json)
- [宿主装配、数据权限与实施状态](docs/development/integration.md)
- [依赖和场景登记](module.yaml)

## 本地检查

安装 `.go-version`、`.node-version` 和 `package.json` 指定的工具链及 PostgreSQL，以普通用户执行：

```bash
make setup
bash scripts/check-with-postgres.sh
```

脚本在独立 Unix socket 上启动临时 PostgreSQL，执行 `make check` 并在退出时清理。通过 `STUHELPER_TEST_PG_BIN` 可指定 PostgreSQL 程序目录。直接运行 `make check` 时，`STUHELPER_INFORMATION_QUERY_TEST_DSN` 必须指向隔离测试服务器。

检查使用 `GOWORK=off`，覆盖生成一致性、仓库规则、文档、SQL 边界、场景登记、Go race 测试、构建及工作流配置。修改 OpenAPI 后执行 `make generate` 同步 SDK。需要暂存区检查时执行 `pnpm run hooks`。

项目使用 [AGPL-3.0-only](LICENSE)。
