---
type: development
status: InReview
updated: 2026-11-19
---

# 信息查询装配与实施状态

## 当前接口

| 方法 | 路径 | 行为 |
| --- | --- | --- |
| POST | `/api/v1/information-query/query` | 按线索解析候选，再按账号查询业务域 |
| POST | `/api/v1/information-query/audit/query` | 独立授权的分页审计查询 |

OpenAPI 版本为 0.2.0。查询 kind 为 name、student_id、qq、account。student_id 必须指定学校。响应 groups 按候选分组，每组包含 candidate 与 items，候选保留 account、source、current、changed_at、scope 和掩码 label。

0.2.0 具有不兼容变化：subject 改为 account，student_number 改为 student_id，退款收款字段类别改为 refund_payee，平铺 items 改为 groups。消费者需重新生成 SDK，更新分组展示并清除旧游标。两个 HTTP 路径保持不变。

同名候选分开展示，同一账号的不同来源或历史绑定也保持独立。历史绑定 current=false，显示来源和变更时间。account 直接形成一个候选，source=account、current=true，changed_at 取首页请求时间，在同一续页链保持一致。首次出现的空候选正常展示，已展示候选在续页耗尽时直接前进到下一候选，审计只记录本页展示的目标。

每页最多返回 100 条业务记录、50 个候选。after 是组合游标，绑定请求人和查询条件，保存候选位置与业务记录位置。服务端使用 HMAC-SHA256 验证游标。字段和域的选择顺序不影响续页。每页重新授权，来源事实变化返回 503。

多副本宿主可为 Service.CursorKey 注入同一独立的 32 字节随机密钥。默认密钥在进程启动时生成。旧格式、密钥不同或轮换后的游标返回 400，客户端需从首页重新查询。

候选按 Resolver 的顺序处理，各候选内按全局记录 ID 排序。每页最多检查 50 个候选、返回 100 条记录。按域前缀顺序取剩余条数，满页即停，续页只给游标所属域传入记录位置。掩码和省略后，返回字段与候选标签的文本预算为 1 MiB，单域单次原始字段文本上限为 8 MiB。满页后可能需要一次空查询确认结束。客户端持续读取到 next_cursor 为空。

已授权但未装配的业务域列入 unavailable_domains。Resolver 缺失、解析故障或 Provider 故障返回 503，不猜测账号。没有候选返回空 groups。申请未授权域返回 403，响应不含部分结果；已授权域可单独查询。

## 端口与装配

```go
Resolve(ctx context.Context, principal account.Principal, lead Lead) ([]Candidate, string, error)
Query(ctx context.Context, principal account.Principal, query Query) ([]Record, error)
PruneAudit(ctx context.Context, before time.Time, limit int) (int, error)
```

Lead 包含 Kind、Value、Scope、Purpose、Limit、After。Candidate 包含 Account、Source、Current、ChangedAt、Scope、Label。

Account 使用平台 Principal.Key() 生成的完整账号键，最多 2048 字节。直接输入无效账号键返回 400，解析器给出无效账号键返回 503，两种情况均在访问业务域前结束。其他线索最多 256 个 Unicode 码点。

Service.Resolvers 按 kind 装配：name、student_id 接 verification，qq 接 qq-binding。Resolver 先按操作者有效范围过滤，再按稳定排他游标分页，端口上限为 50。编排每次请求一个候选，直到候选上限或业务记录预算耗尽。

Resolver 的 Label 只含区分候选所需的掩码字段，不得把原始线索放入来源、账号键或游标。编排再次检查候选范围、掩码和字段大小。候选披露之前检查所有申请域的权限，并在返回前提交审计。

Service.Providers 按业务域装配。Provider 仅接收 kind=account 与完整账号键，先授权、按范围过滤，再按 ID 升序分页。After 是排他记录 ID，Limit 上限 100。记录 ID 使用 `<domain>:<id>`，Subject 必须与查询账号一致。

提供方使用所属包的 DTO，backend 负责转换，不依赖 information-query。查询依赖均为可选依赖，缺失影响对应解析或业务域。模块仅保存审计，不读取其他模块的数据库。真实适配器与 backend 装配需由对应任务完成。

用迁移身份执行 postgres.Repository.Migrate。运行身份需要 schema 的 USAGE、audit 和 audit_scopes 的 SELECT、INSERT，以及 audit_id_seq 的 USAGE。范围明细与审计正文在同一语句提交，删除审计时级联清理明细。连接池为空时返回 ErrUnavailable。

旧记录按请求范围可见。新记录同时保存实际范围，每组学校、群、模块作为整体匹配。学校、群及模块的分页索引按审计 ID 排序，读取时裁剪范围外目标。

每次查询、拒绝和审计查询保存操作者、请求 ID、用途、范围、字段类别、权限依据、目标内部标识、时间、数量、结果与渠道。审计读取按 ID 降序分页，按实际涉及的学校、群与模块匹配，并为受限范围审计员裁剪范围外的目标标识。

Service.Auth 注入平台 admin.Service，Providers 与 Resolvers 在启动后保持不可变。HTTP 可信中间件构造 Principal、请求 ID、Delivery。机器人适配器从已验证发信账号及会话构造渠道，BotEnabled 默认关闭。

HTTP 先验证登录态，再检查渠道和媒体类型。匿名请求返回 401，无审计写入。POST 仅接受 application/json，可带 charset 参数。415、404、405 均返回 JSON，405 携带 Allow: POST。

HTTP 限制正文 16 KiB，拒绝未知字段及尾随 JSON，响应 no-store。已登录请求的解析和渠道拒绝按入口写一条审计。查询整体限时 10 秒，审计提交独立限时 3 秒。依赖须遵守 context；原始线索、正文和敏感结果不得进入日志。

## 权限与审计

| 能力 | 用途 |
| --- | --- |
| `information-query.<domain>.read` | 查询 profiles、verification、catalog、reviews、resources、billing、groups |
| `information-query.identity.read` | 完整身份字段 |
| `information-query.document.read` | 证件号码 |
| `information-query.material.read` | 认证原始材料 |
| `information-query.refund.read` | refund_payee 类别的退款收款资料 |
| `information-query.bot` | 机器人查询 |
| `information-query.audit.read` | 审计查询 |

每次 Query 对同一操作者、能力和完整范围只执行一次成功的编排层授权检查。不同学校、群和模块分别检查，每次翻页重新授权。各域 Provider 继续独立授权。未申请完整身份字段时返回固定掩码，其他敏感类别未申请时省略。退款收款字段类别使用 refund_payee，权限名保留 refund.read。

每次查询、拒绝和审计查询保存操作者、请求 ID、用途、范围、字段类别、权限依据、目标内部标识、时间、数量、结果与渠道。用途支持换行和制表符，最多 512 个 Unicode 码点；审计仅记录申请或实际明文披露的敏感类别，无权拒绝统一记为 denied，落盘前清洗非法范围、控制字符与空切片。候选与敏感结果在审计写入成功后返回，写入失败返回 503。群聊查询额外记录目标群标识。

## 审计保留与维护

postgres.Maintenance 使用单独连接池，仅授予 schema USAGE 和 audit SELECT/DELETE。维护身份不能 INSERT/UPDATE，运行身份不能 DELETE/UPDATE。维护接口不挂载 HTTP，也不放入运行 Repository 接口。

RetentionMonths=0 时默认保留 12 个自然月，可由维护进程配置为 1 至 1200 个月。截止时间按 UTC 当前时间 AddDate(0,-months,0) 计算。before 必须不晚于保留截止时间，清理严格早于 before 的记录，边界记录保留。

PruneAudit 每次 limit 为 1 至 1000，按 created_at、id 稳定选择并在单条 SQL 中删除，返回实际删除数。超时为 3 秒；失败不产生部分提交，可重试。维护任务应监控积压、失败与最早到期时间，分批执行并限制调度次数。

争议保留的逐对象排除尚未实现。有保留义务时，维护人暂停相关清理或使用覆盖保留范围的更早 before；不能直接用默认截止时间清理争议数据。恢复后开放服务前须重新执行到期规则，恢复演练仍待验证。

## 验证与剩余工作

module.yaml 登记 IQ-01 至 IQ-08 及实现补充场景 IQ-09（解析故障与隔离）、IQ-10（组合分页及预算）、IQ-11（保留与维护权限）。测试覆盖三类线索、同名分离、历史绑定、跨域授权、候选变更、账号隔离和分页不重不漏。

隔离 PostgreSQL 测试覆盖建表与重复执行、并发审计写入、敏感响应提交要求、有界删除、截止时间边界、重复清理、维护身份与运行身份的权限分离。2026-11-09 已通过 GOWORK=off、隔离 PostgreSQL 18.6 完整检查：生成一致性、repository、docs、场景登记、gofmt、vet、race、build 和 workflows。

待完成：真实 Resolver/Provider 与 backend 联调，消费者 0.2.0 升级及实际组合验证，批量预览和导出，争议保留自动排除，恢复演练。未执行真实账号验收、发行或部署。
