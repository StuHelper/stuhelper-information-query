---
type: guide
status: Accepted
updated: 2026-11-21
---

# 工程约定

更新日期：2026-11-21。

遵循 [主工作区工程约定](https://github.com/StuHelper/stuhelper/blob/develop/AGENTS.md)。

- 按 [装配文档](docs/development/integration.md) 维护线索类型、业务域、查询权限和审计规则。业务域通过公开接口读取，接收解析后的平台完整账号键。审计及保留记录的 SQL 留在 `postgres/`。
- HTTP 接口先维护 [OpenAPI](contracts/information-query.openapi.json)，再执行 `make generate`。为权限、候选隔离、分页、审计失败与保留边界新增场景时，在 [模块清单](module.yaml) 的 `scenario_tests` 登记实际测试函数。
- 运行、维护、迁移和管理争议保留分别使用独立数据库身份。测试夹具和诊断使用合成或脱敏数据。原始线索、材料及完整身份字段仅在授权请求中处理。
- 用隔离 PostgreSQL 验证审计事务、权限隔离、迁移和清理。检查命令见 [README](README.md#本地检查)。
