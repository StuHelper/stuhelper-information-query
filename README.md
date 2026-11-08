# StuHelper 信息查询

更新日期：2026-11-09。

信息查询模块通过业务模块公开接口查阅关联记录。模块仅持久化查询审计，不保存身份原始值或查询投影，不读取其他模块的数据库。

当前实现包括单次分页查询、业务域授权、学校和群范围检查、敏感字段分层、机器人渠道检查和审计查询。业务 Provider 尚待所属模块提供或适配，批量预览、导出文件及审计保留期清理尚未实现。

- [接口定义](contracts/information-query.openapi.json)
- [装配、权限和接口缺口](docs/development/integration.md)
- [模块场景登记](module.yaml)

## 本地检查

```bash
pnpm install --frozen-lockfile
pnpm run hooks
make generate
bash scripts/check-with-postgres.sh
```

数据库脚本创建仅监听独立 Unix socket 的临时 PostgreSQL 集群，退出时清理。可用 `STUHELPER_TEST_PG_BIN` 指定 PostgreSQL 二进制目录。`make check` 要求设置隔离测试库 DSN，执行生成一致性、工程检查、文档、架构边界、race 测试、构建和工作流检查。

`GOWORK=off` 独立构建。平台依赖固定为 `0efdba00ff59cddc9d7894092aace9b9212696f0`。不修改 backend 或工作区锁文件。

项目使用 AGPL-3.0-only。
