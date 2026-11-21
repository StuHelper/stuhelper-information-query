---
type: development
status: InReview
updated: 2026-11-22
---

# 信息查询装配与实施状态

## 当前接口

| 方法 | 路径 | 行为 |
| --- | --- | --- |
| POST | `/api/v1/information-query/query` | 按线索解析候选，再按账号查询业务域 |
| POST | `/api/v1/information-query/preview` | 按行回显线索，返回掩码候选和计数 |
| POST | `/api/v1/information-query/audit/query` | 独立授权的分页审计查询 |
| POST | `/api/v1/information-query/capabilities` | 当前操作者在指定范围下的只读能力与装配预检 |

OpenAPI 版本为 0.2.0。查询 kind 为 name、student_id、staff_id、qq、account。student_id 与 staff_id 必须指定学校。响应 groups 按候选分组，每组包含 candidate、items 与 has_more，候选保留 account、source、current、changed_at、scope 和区分标签 label。

客户端使用与宿主锁定提交一致的 SDK。判断能力预检、预览或审计筛选是否可用时，核对组合所用的 OpenAPI 快照与路由。当前 develop 与生产标签的 OpenAPI 版本号同为 0.2.0。

同名候选、同一账号的各来源与历史绑定均分组记录。历史绑定的 `current` 为 `false`，并附带来源和变更时间。`account` 线索直接形成一个候选，`changed_at` 取首页请求时间，在同一续页链保持一致。

首次出现的空候选正常返回。已展示的候选在续页耗尽时直接前进到下一候选，审计记录本页返回的目标。

每页最多检查 50 个候选并返回 100 条业务记录。`after` 是经 HMAC-SHA256 签名的组合游标，绑定请求人及查询条件，记录候选与业务记录的位置。字段和域选择的排列顺序不影响续页。每页重新授权，续页候选事实改变时返回 503。

多副本宿主可为 Service.CursorKey 注入同一独立的 32 字节随机密钥。默认密钥在进程启动时生成。旧格式、密钥不同或轮换后的游标返回 400，客户端需从首页重新查询。

候选按 Resolver 顺序处理，各候选内按带域前缀的记录 ID 升序取数。多读一条可见记录可确认当前候选的 `has_more`。续页只向游标所在域传入原记录位置。

掩码和省略后，返回字段与候选标签的文本预算为 1 MiB，单域单次原始字段文本上限为 8 MiB。单次提供方调用上限为 100 条，满 100 条时单独探测一条。客户端持续读取到 next_cursor 为空。

已授权但未装配的业务域列入 unavailable_domains。Resolver 缺失、解析故障或 Provider 故障返回 503。没有候选时返回空 `groups`。申请未授权域时整次请求返回 403。操作者可单独选择已授权域。

失败响应保留 code，并通过可选 reason、domain、field 返回细分机器码（如 school_required、candidate_changed、domain_forbidden、field_forbidden）与受阻枚举标识，从不回显原始查询值。

`capabilities` 接收可选 `scope`，默认全局范围。响应分别返回当前操作者的域、敏感类别、审计和机器人能力，以及宿主已装配的域和线索类型。预检限时 3 秒，成功或失败均不追加查询审计。

批量预览每次接收 1 至 20 条同类型唯一线索，所有类型均限制为 256 个 Unicode 码点。请求限于 `admin` 渠道，要求 `information-query.batch.read` 和所选域的读取权限。

审计提交后，只向发起人按输入顺序返回 `entries`。各条目的 `index` 对应输入下标，`value` 保留线索原值。每条线索最多返回 5 个候选，每批最多 50 个。各候选按域返回最多 20 条记录的计数，并标记是否还有更多。

候选保留完整账号键与掩码标签。预览接口拒绝 `fields` 参数，响应只含线索、候选和业务记录计数。

## 端口与装配

```go
Resolve(ctx context.Context, principal account.Principal, lead Lead) ([]Candidate, string, error)
Query(ctx context.Context, principal account.Principal, query Query) ([]Record, error)
PruneAudit(ctx context.Context, before time.Time, limit int) (int, error)
```

Lead 包含 Kind、Value、Scope、Purpose、Limit、After。Candidate 包含 Account、Source、Current、ChangedAt、Scope、Label。

完整查询的账号线索与解析后的账号键均使用平台 Principal.Key() 生成的完整账号键，最多 2048 字节。完整查询的其他线索最多 256 个 Unicode 码点。直接输入无效账号键返回 400，解析器给出无效账号键返回 503。

Service.Resolvers 按 kind 装配：name、student_id、staff_id 接 verification，qq 接 qq-binding。Resolver 先按操作者有效范围过滤，再按稳定排他游标分页，端口上限为 50。编排每次请求一个候选，直到候选上限或业务记录预算耗尽。

候选 `label` 只含区分重名和师生身份所需的掩码字段或非敏感标签，均标记 `masked=true`。来源、账号键和游标使用业务标识，禁止嵌入原始姓名、学号、教工号或 QQ 号。

返回候选前，编排检查所有申请域的权限，并复核候选范围、掩码和字段大小。响应等待审计提交。

Service.Providers 按业务域装配。Provider 仅接收 kind=account 与完整账号键，先授权、按范围过滤，再按 ID 升序分页。After 是排他记录 ID，Limit 上限 100。记录 ID 使用 `<domain>:<id>`，Subject 必须与查询账号一致。

提供方定义本领域的数据结构，宿主转换至信息查询接口。information-query 拥有查询编排、HTTP 契约和审计数据。线索与业务记录的权威数据仍由所属模块管理。

| 清单声明 | 模块或能力 | 装配影响 |
| --- | --- | --- |
| 必需依赖 | platform | 提供平台账号、权限与范围模型 |
| 可选依赖 | verification、qq-binding | 分别提供姓名、学号、教工号解析和 QQ 解析，宿主按当前提供方版本装配 |
| 可选依赖 | profiles、verification、catalog、reviews、resources、billing、groups | 对应业务域按宿主已注入的 Provider 可用 |
| 对外能力 | `information-query.query`、`information-query.audit` | 宿主分别挂载查询与审计入口，操作者仍须具备相应权限 |

可选解析器缺失时，对应线索查询返回 503。已授权但缺少提供方的域列入 `unavailable_domains`，其余已装配域继续查询。清单的模块依赖与操作者权限分别校验。

用迁移身份执行 postgres.Repository.Migrate。迁移在 information_query.schema_migrations 记录已执行版本，每个未执行脚本都在独立事务内原子执行。

运行身份需要 schema 的 USAGE、audit 和 audit_scopes 的 SELECT、INSERT，以及 audit_id_seq 的 USAGE。范围明细与审计正文在同一语句提交，删除审计时级联清理明细。连接池为空时返回 ErrUnavailable。

旧记录按请求范围可见。新记录同时保存实际范围，每组学校、群、模块作为整体匹配。学校、群及模块的分页索引按审计 ID 排序，读取时裁剪范围外目标。

Service.Auth 注入平台 admin.Service，Providers 与 Resolvers 在启动后保持不可变。HTTP 可信中间件构造 Principal、请求 ID、Delivery。机器人适配器从已验证发信账号及会话构造渠道，BotEnabled 默认关闭。

Service.Observe 可选接收诊断事件，仅含请求 ID、阶段（auth、resolve、provider、contract、audit）、域、线索类型、脱敏状态码和耗时，编译期不接收查询原值或字段值。

HTTP 先匹配路由和方法，再验证登录态、渠道与媒体类型。匿名调用已声明的 POST 路由返回 401，无审计写入。POST 接受 `application/json`，可带 charset。405 响应携带 `Allow: POST`。

HTTP 限制正文 16 KiB，拒绝未知字段与尾随 JSON，响应 `no-store`。已登录用户的查询、预览和审计查询在入口按操作记录拒绝。查询和预览各限时 10 秒，审计写入另有 3 秒。依赖须响应取消，日志只记录脱敏诊断。

## 权限与审计

| 能力 | 用途 |
| --- | --- |
| `information-query.<domain>.read` | 查询 profiles、verification、catalog、reviews、resources、billing、groups |
| `information-query.identity.read` | 完整身份字段 |
| `information-query.document.read` | 证件号码 |
| `information-query.material.read` | 认证原始材料 |
| `information-query.refund.read` | refund_payee 类别的退款收款资料 |
| `information-query.bot` | 机器人查询 |
| `information-query.batch.read` | 管理端有界批量线索预览 |
| `information-query.audit.read` | 审计查询 |

每次 Query 对同一操作者、能力和完整范围复用已通过的编排层授权，翻页重新授权。完整查询默认掩码显示姓名、学号、手机号和 QQ 号。操作者主动申请 `identity` 且通过编排层和提供方的类别授权后，获得完整值并留下披露审计。

查询与审计查询记录操作者、请求 ID、事由、范围、数量、时间、结果、渠道和权限依据。业务查询记录目标账号键和敏感类别，群聊查询另记目标群。事由支持换行和制表符，最多 512 个 Unicode 码点。

预览审计使用固定事由，以 `lead_kind` 和 `lead_digest` 记录线索。摘要按整批输入顺序计算，绑定请求 ID，使用 `Service.CursorKey` 的 HMAC-SHA256。预览日志与主审计、提供方审计均省略原始线索和目标账号键。提供方写审计时须保留调用上下文。

响应在对应审计写入成功后返回。写入失败返回 503。记录只保留申请或实际明文披露的敏感类别，无权结果记为 `denied`。落盘前清洗数据，姓名、学号、教工号、QQ 线索、请求正文和业务字段值不写入审计。

审计查询按 ID 倒序返回最新记录。`after` 为可选的排他上界游标，首页可省略。支持按范围、操作者、目标、操作、结果、渠道及时间段筛选。读取时裁剪超出审计员权限范围的目标。

`purpose` 是本次读取审计的事由，记录于新增的 `audit.query` 审计行。历史记录筛选使用上述查询字段。

## 审计保留与维护

postgres.Maintenance 使用单独连接池，仅授予 schema USAGE 和 audit SELECT/DELETE。维护身份不能 INSERT/UPDATE，运行身份不能 DELETE/UPDATE。维护接口不挂载 HTTP，也不放入运行 Repository 接口。

RetentionMonths=0 时默认保留 12 个自然月，可由维护进程配置为 1 至 1200 个月。截止时间按 UTC 当前时间 AddDate(0,-months,0) 计算。before 必须不晚于保留截止时间，清理严格早于 before 的记录，边界记录保留。

`PruneAudit` 每次删除 1 至 1000 条候选记录，按 `created_at` 和 `id` 选择，返回实际删除数。事务限时 3 秒，失败可整批重试。

`Maintenance.PendingStats` 返回最早的待清理记录创建时间和有界积压数，上限 10001。统计排除仍在争议保留范围内的记录。

争议保留通过 information_query.audit_holds 与 postgres.HoldStore 管理，支持按 audit_id、request_id 或 target_account 登记保留依据与复核日期。治理身份获得 `audit_holds` 的 SELECT、INSERT、UPDATE。清理排除未释放的匹配记录，释放后纳入常规到期清理。

## 验证与剩余工作

### 当前生产组合

StuHelper v0.1.31 启用后台信息查询。Backend v0.1.46 固定本模块的 Go 发布标签 v0.1.0，装配查询与审计两条路由，接入 verification 的姓名、学号解析与 qq-binding 的 QQ 解析。机器人与群服务在该组合中关闭。见 [StuHelper v0.1.31 组件清单](https://github.com/StuHelper/stuhelper/releases/download/v0.1.31/COMPONENTS.json)。

Backend 已按启用的模块注入业务域，catalog 适配器限本人在指定学校的选课。各域的可查范围仍由当前权限和提供方判断。

### 源码与持续集成

[module.yaml](https://github.com/StuHelper/stuhelper-information-query/blob/develop/module.yaml) 的 `scenario_tests` 登记 IQ-01 至 IQ-12，覆盖线索解析、候选隔离、范围权限、敏感字段、审计提交、机器人渠道、组合分页、保留清理和批量预览。检查脚本验证登记所指的文件和测试函数存在。

develop 源码 `6cbd87f` 已通过隔离 PostgreSQL 的 Information query checks，覆盖生成一致性、文档、架构边界、race 测试、迁移、运行与维护身份隔离及构建。见 [CI 运行](https://github.com/StuHelper/stuhelper-information-query/actions/runs/44355069955)。

### 待验证

- 批量预览、能力预检、教工号解析、审计多维检索与争议保留已在 develop 实现。升级宿主和调用方后，待核对路由、数据库角色与已锁定的跨仓组合。
- 真实账号场景和审计恢复演练待验证。批量导出尚无实现，保留待确认。
