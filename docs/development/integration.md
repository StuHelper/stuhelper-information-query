---
type: development
status: InReview
updated: 2026-11-09
---

# 信息查询装配与实施状态

## 当前接口

| 方法 | 路径 | 行为 |
| --- | --- | --- |
| POST | `/api/v1/information-query/query` | 按姓名、学校内学号、QQ 或内部账号线索分页查询 |
| POST | `/api/v1/information-query/audit/query` | 独立授权的分页审计查询 |

请求字段以 OpenAPI 为准。每页最多 100 条，最多选择七个业务域。`after` 是上页最后一个业务记录 ID，所有 Provider 使用排他下界。满页返回游标，最后一页恰好满页时可能再返回一个空页。

请求显式声明学校、群和业务模块范围。`*` 表示申请全范围，必须拥有覆盖该范围的授权。学号查询必须指定学校。多个学校的受限管理员应分别提交学校范围，不根据关联对象自动扩展权限。

结果保留内部对象 ID、学校和群范围、关联来源、变更时间和当前绑定标记。姓名相同的记录保持独立，历史解绑记录不标记为当前绑定。内部 ID 不得包含原始身份值。

未装配的已授权业务域列入 `unavailable_domains`。已装配 Provider 失败时返回 503。申请任何未授权域或敏感类别返回 403；响应不包含部分业务结果。已授权域可以单独查询。

## 平台能力

| 能力 | 用途 |
| --- | --- |
| `information-query.<domain>.read` | 查询指定业务域，domain 为七个可选模块之一 |
| `information-query.identity.read` | 查看完整姓名、学号、手机号、QQ |
| `information-query.document.read` | 查看证件号码 |
| `information-query.material.read` | 查看认证原始材料 |
| `information-query.refund.read` | 查看退款收款资料 |
| `information-query.bot` | 允许机器人查询 |
| `information-query.audit.read` | 查询本模块审计 |

业务域和敏感能力均传入 `admin.Service.Evaluate`，携带当前请求人及真实对象范围。平台管理员的全部能力由平台可信身份判断提供。普通群管理员没有隐含财务、认证或敏感字段能力。

未申请完整身份类别时返回固定掩码 `***`。未申请证件、材料或退款收款类别时省略字段。Provider 同时执行所属模块的授权，必须准确标记字段类别，不能通过业务字段或来源字符串携带敏感值。

## Backend 装配步骤

1. 将本模块源码固定到 backend 的依赖组合，登记可选 Provider。此任务不修改 backend 的 go.mod、go.sum 或工作区锁文件。
2. 用迁移身份执行 `postgres.Repository.Migrate`。运行身份仅授予 information_query schema 的 USAGE、audit 表的 SELECT/INSERT 和 audit_id_seq 的 USAGE。
3. 用运行身份建立 `pgxpool.Pool`，创建 `postgres.Repository`。把当前平台 `admin.Service` 注入 `Service.Auth`，把仓库注入 `Service.Repo`。
4. 按业务域向 `Service.Providers` 注册公开接口适配器。配置在启动后保持不可变，网络适配器必须遵守 context 的超时与取消。
5. 挂载 `httpapi.Handler`。可信认证中间件生成 Principal、请求 ID 和 Delivery，不能从客户端提交的角色、身份或渠道头直接构造。
6. 机器人适配器从已验证的发信账号和会话构造 Delivery。显式开启 BotEnabled 后仍检查机器人能力。群聊直接把获准结果回到原群，并向使用者说明群成员可以看到回复。
7. 进程停止时关闭连接池。业务依赖和审计库不可用时不得返回敏感结果。backend 应提供对应就绪状态及脱敏故障指标。

HTTP 仅接受 POST，限制请求体 16 KiB，拒绝未知字段和尾随 JSON。响应设置 `Cache-Control: no-store`。查询整体限时 10 秒，审计提交使用独立的 3 秒期限。原始请求体、查询线索和结果正文不得写入日志。

## Provider 接口要求与现有缺口

`Provider.Query(ctx, principal, query)` 返回所属模块的 Record。必须先按请求人的当前权限、真实学校和群范围过滤，再按全局唯一的 `<domain>:<id>` 排序分页。模块最多返回请求的 limit 条记录，并执行字段授权。

返回记录再次经信息查询服务核验范围、能力及字段类别。每次聚合限制为 1 MiB 字段文本，超限返回 503。该上限不替代 Provider 对远程响应大小、数据库查询次数及处理量的限制。

| 模块 | 当前可复用接口 | 所需补充 |
| --- | --- | --- |
| profiles | `Get`、`Public` | 按姓名、学号、QQ 查询候选内部账号，携带真实范围、关联来源与历史绑定 |
| verification | `AdminCredential`、`StudentProfile`、`PublicProfileFacts` | 管理员按线索和目标账号分页读取学籍、学习经历、实名结论，并独立授权证件与材料 |
| catalog | `AdminRead`、`AdminList`、`AdminLookup` | 从账号公开关联事实取得学校、课程及导师 ID，按实际授权范围组成记录 |
| reviews | `AdminGet`、`AdminList` | 按目标作者分页查询评价，保留原模块的身份披露规则 |
| resources | `Get`、`List` | 按目标账号查询资料和解锁记录，并提供明确的学校和群范围 |
| billing | `AdminAccount`、`AdminRefunds` | 对接当前平台能力，取得目标的真实学校和群范围，独立屏蔽退款收款字段 |
| groups | 本轮独立实施中 | 提供成员资格、入群认证和群管理记录的分页查询及范围信息 |

profiles 当前不拥有完整 QQ 历史绑定事实。QQ 关联适配器必须向实际拥有绑定数据的模块调用公开接口，或由 profiles 提供组合接口，不能读取绑定表或以展示昵称推断账号归属。

当前没有生产 Provider 实现，不使用演示记录兜底。端到端业务联调须等待以上接口与 backend 装配。若后续采用查询投影，必须按 EVENT-DELIVERY.md 通过 outbox、relay 和 inbox 构建，并处理重复、旧修订和乱序事件。

## 审计与验证

每次业务查询、拒绝和审计查询保存操作者、请求 ID、用途、申请范围、字段类别、所需能力、目标内部标识、时间、结果数量、结果码和投递渠道。群聊记录实际目标群。日志和审计均不复制查询值或敏感字段正文。

审计写入完成后才返回查询结果，写入失败返回 503。运行身份不能更新或删除审计，也不能读取其他模块表。多域查询的审计范围采用请求的整体范围，因此查看该审计需要覆盖整体范围的审计授权。

IQ-01 至 IQ-08 对应的服务测试登记在 module.yaml。测试覆盖姓名候选分离、范围外拒绝、业务域隔离、独立敏感权限、机器人默认关闭、权限撤销、审计失败和渠道记录。平台管理员测试使用真实 admin.Service.Evaluate。

隔离 PostgreSQL 测试验证迁移重复执行、并发审计写入、分页、学校范围过滤，以及运行身份的允许权限和越界拒绝。HTTP 测试验证伪造身份字段、超长正文及尾随 JSON 被拒绝。

待完成：真实 Provider 与 backend 联调、批量查询和导出权限及预览、导出文件有效期与下载再授权、审计默认 12 个月保留期的清理及争议保留。当前 HTTP 接口不开放批量或导出能力。

2026-11-09 本地完整检查通过：Go 1.27.3、GOWORK=off、隔离 PostgreSQL 18.6，执行生成一致性、repository、docs、模块场景登记、gofmt、go vet、race 测试、build 和 workflows。另用数据库只读事务验证敏感结果在审计提交失败时被丢弃。尚无远程 CI 或真实账号验收结果。
