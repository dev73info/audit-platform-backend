# audit-platform API 契约 v1

前后端与各后端模块的**唯一事实源**。改接口先改这份文档，再改实现。
设计基线见 [`设计文档.md`](设计文档.md) 第 6 章。

## 一、通用约定

| 项 | 约定 |
| --- | --- |
| 管理端前缀 | `/api/admin/v1` |
| 开放 API 前缀 | `/open/v1` |
| 编码 | UTF-8 JSON（`Content-Type: application/json; charset=utf-8`） |
| 时间 | ISO8601 带时区，如 `2026-10-21T10:00:00+08:00`；时间戳字段为毫秒 |
| 分页 | `page`（从 1 起）、`page_size`（20/50/100） |
| 排序 | `sort=created_at:desc,result:asc`；字段必须在服务端排序白名单内 |
| 筛选 | `filter[status]=ACTIVE,PAUSED`、`filter[created_at_from]=…` |
| 鉴权 | 管理端 `Authorization: Bearer <access_token>`；开放 API 用签名头 |
| 追踪 | 请求可带 `X-Trace-Id`，不带则服务端生成；响应回 `trace_id` |

### 统一响应封装

```json
{
  "code": 0,
  "message": "OK",
  "data": {},
  "trace_id": "8f3c1a9e-...",
  "cost_ms": 42
}
```

`code` 为 0 表示成功；非 0 时 `message` 是错误码（见下表），`data` 可带补充信息。

列表的 `data` 结构：

```json
{ "items": [], "total": 1234, "page": 1, "page_size": 20, "has_more": true }
```

### 错误码

| HTTP | code | 含义 |
| --- | --- | --- |
| 400 | `INVALID_PARAM` | 参数校验失败，`data.field_errors` 给出字段与原因 |
| 400 | `INVALID_SIGNATURE` | 开放 API 签名错误 |
| 400 | `TIMESTAMP_EXPIRED` | 时间戳偏差超过 5 分钟 |
| 400 | `REPLAY_ATTACK` | Nonce 重复 |
| 400 | `CAPTCHA_REQUIRED` | 连续失败后需要图形验证码 |
| 401 | `UNAUTHORIZED` | 未认证或令牌失效 |
| 401 | `MFA_REQUIRED` | 敏感操作需二次验证 |
| 401 | `ACCOUNT_LOCKED` | 账号被锁定 |
| 403 | `PERM_DENIED` | 功能权限不足 |
| 403 | `PROJECT_OUT_OF_SCOPE` | 越权访问他项目数据 |
| 403 | `QUOTA_EXCEEDED` | 项目配额超限 |
| 403 | `GLOBAL_POOL_EXHAUSTED` | 全局连接池额度不足 |
| 403 | `PROJECT_PAUSED` | 项目已暂停 |
| 403 | `PROJECT_DELETED` | 项目已删除（在回收站） |
| 403 | `READ_ONLY` | 项目处于只读模式 |
| 404 | `NOT_FOUND` | 对象不存在 |
| 409 | `CODE_CONFLICT` | 编码冲突 |
| 409 | `DUPLICATED_TASK` | 幂等命中，`data.task_id` 是已有任务 |
| 409 | `VERSION_CONFLICT` | 配置版本冲突，需重新拉取 |
| 409 | `DEPENDENCY_MISSING` | 依赖配置缺失（如动作引用了不存在的 API） |
| 422 | `CONNECTION_TEST_FAILED` | 连接测试失败 |
| 422 | `INVALID_SQL` | SQL 动作未通过安全校验 |
| 429 | `RATE_LIMITED` | 限流，响应带 `Retry-After` |
| 500 | `INTERNAL_ERROR` | 服务内部错误 |
| 503 | `DOWNSTREAM_UNAVAILABLE` | 第三方依赖不可用 |

### 枚举

| 枚举 | 取值 |
| --- | --- |
| 项目状态 `ProjectStatus` | `ACTIVE` / `PAUSED` / `DISABLED` / `DELETED` |
| 项目环境 `ProjectEnv` | `dev` / `test` / `staging` / `prod` |
| 审核状态 `AuditStatus` | `DRAFT` / `ACTIVE` / `PAUSED` / `DELETED` |
| 触发源类型 `TriggerType` | `REDIS` / `POLLING` / `WEBSOCKET` / `OPENAPI` |
| 任务状态 `TaskStatus` | `RECEIVED` / `LOCKED` / `QUEUED` / `WAITING_QUOTA` / `PROCESSING` / `RULE_EVALUATING` / `MEDIA_REVIEWING` / `ROUTING` / `REVIEW_PENDING` / `SUCCESS` / `FAILED` / `DUPLICATED` / `DEAD_LETTER` |
| 审核结论 `TaskResult` | `PASS` / `REJECT` / `REVIEW` / `UNKNOWN` |
| 去重标记 `DedupeFlag` | `NORMAL` / `DUPLICATED` / `NO_DEDUPE` |
| 动作类型 `ActionType` | `HTTP` / `REDIS` / `MYSQL` / `WEBHOOK` / `MQ` |
| 配置类型 `ConfigType` | `REDIS` / `MYSQL` / `API` / `OSS` / `MQ` |

## 二、管理端 API

### 2.1 认证

```
POST   /api/admin/v1/auth/login        { username, password, captcha?, mfa_code? }
POST   /api/admin/v1/auth/refresh      { refresh_token }
POST   /api/admin/v1/auth/logout
GET    /api/admin/v1/auth/me
```

`login` 响应 `data`：

```json
{
  "access_token": "...",
  "refresh_token": "...",
  "expires_in": 7200,
  "user": { "id": 1, "username": "admin", "display_name": "系统管理员",
            "role": "SUPER_ADMIN", "roles": ["SUPER_ADMIN"],
            "permissions": ["project:read", "..."], "projects": [4001] }
}
```

`me` 响应同上 `user` 部分。

### 2.2 项目

```
GET    /api/admin/v1/projects            列表：filter[status] filter[env] keyword sort page page_size
POST   /api/admin/v1/projects            { name, code, env, owner_id, description?, quota? }
GET    /api/admin/v1/projects/{id}
PUT    /api/admin/v1/projects/{id}       { name?, env?, owner_id?, description?, version }
POST   /api/admin/v1/projects/{id}/enable
POST   /api/admin/v1/projects/{id}/pause  { reason }
POST   /api/admin/v1/projects/{id}/quota  { max_concurrency, max_qps, max_mysql_pool, ... }
DELETE /api/admin/v1/projects/{id}?force=true
```

删除响应 `data`：

```json
{ "recycle_id": 9001,
  "affected": { "audits": 4, "trigger_sources": 6, "rules": 12 },
  "running_tasks": 0,
  "expire_at": "2026-11-20T10:00:00+08:00" }
```

项目对象：

```json
{ "id": 4001, "name": "演示项目", "code": "demo", "env": "dev", "status": "ACTIVE",
  "owner_id": 1, "owner_name": "系统管理员", "description": "",
  "retain_days": 30, "quota": { "max_concurrency": 20, "max_qps": 50, "max_mysql_pool": 10,
  "max_redis_conn": 10, "max_media_size_mb": 50, "max_daily_tasks": null,
  "max_api_call_per_task": 10 },
  "stats": { "audit_count": 1, "task_today": 0, "task_total": 0, "queue_backlog": 0 },
  "version": 1, "created_at": "2026-10-21T10:00:00+08:00", "updated_at": "2026-10-21T10:00:00+08:00" }
```

### 2.3 项目连接配置

```
GET    /api/admin/v1/projects/{pid}/configs
GET    /api/admin/v1/projects/{pid}/configs/{cid}
PUT    /api/admin/v1/projects/{pid}/configs/{cid}     { type, name, config, pool?, tags? }
POST   /api/admin/v1/projects/{pid}/configs            新建
POST   /api/admin/v1/projects/{pid}/configs/test       { type, config, pool? } 仅测试不落库
POST   /api/admin/v1/projects/{pid}/configs/{cid}/rollback  { version }
GET    /api/admin/v1/projects/{pid}/configs/{cid}/versions
POST   /api/admin/v1/projects/{pid}/configs/{cid}/reveal  { password } 二次确认
DELETE /api/admin/v1/projects/{pid}/configs/{cid}
```

配置对象（密钥字段脱敏为 `***abcd`）：

```json
{ "id": 5001, "type": "MYSQL", "name": "biz_db", "version": 3,
  "config": { "host": "10.0.0.5", "port": 3306, "database": "biz",
              "username": "audit", "password": "***b2c1", "ssl_mode": "DISABLED" },
  "pool": { "max_pool_size": 20, "min_idle": 5, "connection_timeout_ms": 30000,
            "idle_timeout_ms": 600000, "max_lifetime_ms": 1800000, "read_only": false },
  "tags": ["BUSINESS"], "test_status": "OK", "test_message": "连接正常",
  "tested_at": "2026-10-21T10:00:00+08:00",
  "created_at": "...", "updated_at": "..." }
```

测试连接响应：

```json
{ "type": "MYSQL", "ok": true, "latency_ms": 12, "server_info": "8.0.32",
  "max_connections": 500, "current_used": 183, "global_limit": 400,
  "remain_for_project": 217, "warnings": ["maxLifetime(1800000ms) 接近 wait_timeout(1800000ms)，建议下调"] }
```

### 2.4 审核定义

```
GET    /api/admin/v1/projects/{pid}/audits
POST   /api/admin/v1/projects/{pid}/audits
GET    /api/admin/v1/audits/{aid}
PUT    /api/admin/v1/audits/{aid}
DELETE /api/admin/v1/audits/{aid}
POST   /api/admin/v1/audits/{aid}/enable
POST   /api/admin/v1/audits/{aid}/pause
POST   /api/admin/v1/audits/{aid}/clone
```

审核对象：

```json
{ "id": 4201, "project_id": 4001, "project_name": "演示项目", "name": "社区文本审核",
  "code": "demo_text", "media_types": ["text"], "status": "ACTIVE", "concurrency": 5,
  "timeout_ms": 30000, "dedupe_window_sec": 86400, "media_hash_in_key": true,
  "retry_policy": { "max_attempts": 3, "backoff": "exponential", "base_ms": 500 },
  "default_result": "REVIEW", "on_model_fail": "REVIEW",
  "media_review": { "text": { "api_ref": "", "enable_keyword": true, "keyword_groups": ["违禁"] } },
  "triggers": [ { "id": 4601, "type": "REDIS", "name": "main-queue", "priority": 10,
                  "status": "ACTIVE", "config": { "stream": "demo_text" } } ],
  "rules": [ { "id": 4301, "name": "命中高危词直接驳回", "priority": 10, "logic": "OR",
               "stop_on_hit": true, "on_hit_result": "REJECT", "status": "ACTIVE",
               "items": [ { "id": 4401, "field": "media.text", "operator": "contains_any",
                            "value": ["违禁词A"], "case_sensitive": false, "negate": false } ] } ],
  "routes": { "PASS": { "exec_mode": "sequential", "on_error": "to_review", "actions": [] },
              "REJECT": { "exec_mode": "sequential", "on_error": "to_review", "actions": [ {} ] },
              "REVIEW": { "exec_mode": "sequential", "on_error": "to_review", "actions": [] } },
  "stats": { "task_today": 0, "pass_rate": 0 },
  "config_version": 1, "created_at": "...", "updated_at": "..." }
```

### 2.5 触发源

```
GET    /api/admin/v1/audits/{aid}/trigger-sources
POST   /api/admin/v1/audits/{aid}/trigger-sources
GET    /api/admin/v1/trigger-sources/{tid}
PUT    /api/admin/v1/trigger-sources/{tid}
DELETE /api/admin/v1/trigger-sources/{tid}
POST   /api/admin/v1/trigger-sources/{tid}/enable | /pause
POST   /api/admin/v1/trigger-sources/{tid}/test      发送测试消息
GET    /api/admin/v1/trigger-sources/{tid}/recent    最近 50 条消费记录
```

触发源对象：

```json
{ "id": 4601, "audit_id": 4201, "project_id": 4001, "type": "REDIS", "name": "main-queue",
  "priority": 10, "status": "ACTIVE", "config": { "stream": "demo_text", "group": "cg_demo_text",
  "batch_size": 16, "visibility_timeout_ms": 60000 },
  "success_count": 0, "fail_count": 0, "last_consume_at": null, "last_error": null,
  "created_at": "...", "updated_at": "..." }
```

### 2.6 规则

```
GET    /api/admin/v1/audits/{aid}/rules
POST   /api/admin/v1/audits/{aid}/rules
GET    /api/admin/v1/rules/{rid}
PUT    /api/admin/v1/rules/{rid}
DELETE /api/admin/v1/rules/{rid}
POST   /api/admin/v1/audits/{aid}/rules/dry-run   { sample }
```

`dry-run` 响应：

```json
{ "final_result": "REJECT", "matched_rule": "命中高危词直接驳回",
  "trace": [ { "rule_id": 4301, "rule": "命中高危词直接驳回", "logic": "OR", "hit": true,
    "items": [ { "field": "media.text", "operator": "contains_any",
                 "actual": "…违禁词A…", "expected": ["违禁词A"], "hit": true } ] },
    { "rule_id": 4302, "rule": "低风险快速通过", "hit": false, "skipped": true } ] }
```

### 2.7 结果路由

```
GET    /api/admin/v1/audits/{aid}/routes
PUT    /api/admin/v1/audits/{aid}/routes/{result_type}
POST   /api/admin/v1/audits/{aid}/routes/apply-template   { template }
POST   /api/admin/v1/audits/{aid}/routes/preview           { result_type, sample } 预览渲染
```

`apply-template` 的 `template` 取值：`reject_all_except_pass`（除通过外均驳回）、
`same_actions_all`（三条路线相同动作）、`callback_only`（仅回调）、
`pass_release_review_manual`（通过放行 + 待议人工）。

### 2.8 任务

```
GET    /api/admin/v1/tasks        filter[project_id] filter[audit_id] filter[source_type]
                                     filter[result] filter[status] filter[dedupe_flag]
                                     filter[duration_min] filter[duration_max]
                                     filter[created_at_from] filter[created_at_to] keyword
POST   /api/admin/v1/tasks/{id}/retry
POST   /api/admin/v1/tasks/{id}/retry-action   { action_exec_id }
POST   /api/admin/v1/tasks/{id}/stop
POST   /api/admin/v1/tasks/{id}/review         { conclusion, reason_code?, remark? }
POST   /api/admin/v1/tasks/batch-retry         { task_ids: [] }
POST   /api/admin/v1/tasks/export              { filters } → 导出任务 ID
```

任务列表项：

```json
{ "id": 180000000000001, "task_no": "T20261021000001", "project_id": 4001,
  "project_name": "演示项目", "audit_id": 4201, "audit_name": "社区文本审核",
  "source_type": "OPENAPI", "biz_key": "post:9527", "media_type": "text",
  "status": "SUCCESS", "result": "PASS", "dedupe_flag": "NORMAL",
  "retry_count": 0, "duration_ms": 152, "error_code": null, "error_message": null,
  "created_at": "2026-10-21T10:00:00+08:00", "finished_at": "2026-10-21T10:00:00+08:00" }
```

任务详情 `data`：

```json
{ "id": 180000000000001, "task_no": "T20261021000001", "status": "SUCCESS", "result": "PASS",
  "media": [ { "id": 1, "type": "text", "url": "", "content": "待审核文本",
               "hash": null, "size_bytes": 18 } ],
  "ext": { "user_id": "u123" },
  "reasons": [ { "source": "rule", "rule": "低风险快速通过" },
               { "source": "model", "label": "porn", "score": 0.97 } ],
  "rule_hit": [ { "rule_id": 4302, "rule": "低风险快速通过", "hit": true,
                  "items": [ { "field": "media.text_len", "operator": "lte",
                               "actual": 18, "expected": 200, "hit": true } ] } ],
  "actions": [ { "id": 1, "route_type": "PASS", "action_id": "a1", "action_type": "WEBHOOK",
                 "action_name": "回调业务方", "status": "SUCCESS", "retry_count": 0,
                 "duration_ms": 42, "request": {}, "response": {}, "error_message": null } ],
  "events": [ { "from_status": "QUEUED", "to_status": "PROCESSING", "message": null,
                "cost_ms": 3, "created_at": "2026-10-21T10:00:00+08:00" } ],
  "payload": {}, "trace_id": "8f3c", "created_at": "...", "finished_at": "..." }
```

### 2.9 待议复核

```
GET    /api/admin/v1/reviews        filter[project_id] filter[audit_id] filter[source_type] sort
GET    /api/admin/v1/reviews/{task_id}
```

列表项与任务列表项同构，额外带 `waiting_ms`、`reviewer_id`、`reviewer_name`。

### 2.10 回收站

```
GET    /api/admin/v1/recycle-bin         filter[object_type] filter[project_id] keyword sort
POST   /api/admin/v1/recycle-bin/{id}/restore
DELETE /api/admin/v1/recycle-bin/{id}/purge      { confirm_name }
POST   /api/admin/v1/recycle-bin/batch-purge    { ids, confirm_text }
GET    /api/admin/v1/cleanup-tasks
```

回收站列表项：

```json
{ "id": 9001, "object_type": "PROJECT", "object_id": 4001, "object_name": "演示项目",
  "object_code": "demo", "project_id": 4001, "project_name": "演示项目",
  "deleted_by": 1, "deleted_by_name": "系统管理员", "deleted_at": "2026-10-21T10:00:00+08:00",
  "expire_at": "2026-11-20T10:00:00+08:00", "remain_days": 30,
  "purge_status": "NONE", "children_count": 6 }
```

### 2.11 审计日志

```
GET    /api/admin/v1/audit-logs     filter[operator] filter[action] filter[object_type]
                                      filter[object_id] filter[project_id] filter[result]
                                      filter[created_at_from] filter[created_at_to] keyword
POST   /api/admin/v1/audit-logs/export
```

列表项：

```json
{ "id": 1, "project_id": 4001, "operator": "admin", "operator_id": 1, "operator_ip": "127.0.0.1",
  "action": "PROJECT_UPDATE", "object_type": "PROJECT", "object_id": "4001",
  "result": "SUCCESS", "detail": {}, "trace_id": "8f3c",
  "created_at": "2026-10-21T10:00:00+08:00" }
```

### 2.12 监控指标

```
GET    /api/admin/v1/metrics?scope=global|project|audit&id=&range=1h|6h|24h|7d
GET    /api/admin/v1/metrics/alerts
GET    /api/admin/v1/metrics/overview
```

`overview` 响应：

```json
{ "task_total": 1234, "task_today": 56, "pass": 900, "reject": 200, "review": 134,
  "failed": 12, "dedupe_hit": 33, "backlog": 5, "dead_letter": 0,
  "duration_p50": 120, "duration_p95": 480, "duration_p99": 900,
  "action_total": 820, "action_failed": 6, "action_success_rate": 0.9927,
  "series": [ { "ts": "2026-10-21T10:00:00+08:00", "pass": 10, "reject": 2, "review": 1, "failed": 0 } ],
  "projects": [ { "project_id": 4001, "project_name": "演示项目", "health": "HEALTHY",
                  "task_total": 100, "backlog": 0, "error_rate": 0.01,
                  "mysql_pool_in_use": 3, "redis_conn_in_use": 2 } ],
  "alerts": [ { "id": 1, "name": "队列积压", "level": "P2", "status": "FIRING",
                "message": "队列积压 1200 条", "started_at": "..." } ] }
```

### 2.13 用户与开放 API 客户端

```
GET    /api/admin/v1/users
POST   /api/admin/v1/users
PUT    /api/admin/v1/users/{id}
POST   /api/admin/v1/users/{id}/reset-password
GET    /api/admin/v1/users/{id}/projects
PUT    /api/admin/v1/users/{id}/projects   { project_ids }

GET    /api/admin/v1/projects/{pid}/api-clients
POST   /api/admin/v1/projects/{pid}/api-clients
PUT    /api/admin/v1/api-clients/{cid}
POST   /api/admin/v1/api-clients/{cid}/rotate-secret
DELETE /api/admin/v1/api-clients/{cid}
```

### 2.14 站内通知

```
GET    /api/admin/v1/notifications        ?page=1&page_size=20
POST   /api/admin/v1/notifications/{id}/read
POST   /api/admin/v1/notifications/read-all
```

列表项：

```json
{ "id": 1, "category": "ALERT", "title": "队列积压", "content": "项目 A 积压 1200 条",
  "link": "/console/metrics", "read_at": null, "created_at": "2026-10-21T10:00:00+08:00" }
```

## 三、开放 API

签名头：

```
X-Api-Key: {app_key}
X-Timestamp: {毫秒时间戳}
X-Nonce: {32 位随机串}
X-Signature: {HMAC-SHA256(AppSecret, CanonicalString) 十六进制小写}

CanonicalString = Method + "\n" + Path + "\n" + Timestamp + "\n" + Nonce + "\n" + SHA256HEX(Body)
```

服务端校验顺序：参数完整性 → AppKey 存在且启用 → 时间偏差 ≤ 5min → Nonce 未重复 →
签名比对 → IP 白名单 → 项目状态 → 限流。

### 端点

```
POST /open/v1/projects/{pid}/audits/{aid}/submit
GET  /open/v1/projects/{pid}/tasks/{task_id}
GET  /open/v1/projects/{pid}/audits/{aid}/poll?cursor=&size=
POST /open/v1/callbacks/register
WS   /open/v1/ws/projects/{pid}/audits/{aid}
```

提交请求体：

```json
{ "biz_key": "post:9527",
  "media": [ { "type": "text", "content": "待审核文本" },
             { "type": "image", "url": "https://oss.example.com/a.jpg" } ],
  "ext": { "user_id": "u123", "scene": "ugc_post" },
  "callback": { "url": "https://biz.example.com/cb" },
  "mode": "async",
  "dedupe_key": "可选，覆盖默认 biz_key" }
```

提交响应 `data`：

```json
{ "task_id": "180000000000001", "task_no": "T20261021000001", "dedupe": "NORMAL",
  "status": "QUEUED", "submit_at": "2026-10-21T10:00:00+08:00" }
```

命中去重时 HTTP 409、`message` 为 `DUPLICATED_TASK`，`data` 带 `origin_task_id`。

查询结果响应 `data`：

```json
{ "task_id": "180000000000001", "task_no": "T20261021000001", "status": "SUCCESS",
  "result": "REJECT",
  "reasons": [ { "source": "model", "label": "porn", "score": 0.97 },
               { "source": "rule", "rule": "命中高危词直接驳回" } ],
  "media": [ { "type": "image", "url": "https://...", "label": "porn", "score": 0.97 } ],
  "duration_ms": 1520, "finished_at": "2026-10-21T10:00:02+08:00" }
```

## 四、规则 DSL

### 内置字段

| 字段 | 含义 |
| --- | --- |
| `media.text` | 全部文本内容拼接 |
| `media.text_len` | 文本长度 |
| `media.count` | 媒体数量 |
| `media.type` | 媒体类型集合 |
| `media.size_bytes` | 总大小 |
| `media.hash` | 媒体指纹 |
| `ext.*` | 业务扩展字段 |
| `model.label` | 模型返回标签 |
| `model.score` | 模型置信度 0~1 |
| `model.risk_level` | 归一化风险等级 low/medium/high |
| `task.source_type` | 触发来源 |
| `task.submit_hour` | 提交小时 |

### 操作符

| 类别 | 操作符 |
| --- | --- |
| 比较 | `eq` `ne` `gt` `gte` `lt` `lte` `between` |
| 集合 | `in` `not_in` `contains` `not_contains` `contains_any` `contains_all` |
| 文本 | `starts_with` `ends_with` `regex` `length_gt` `length_lt` |
| 空值 | `is_null` `is_not_null` `is_empty` `is_not_empty` |
| 模型 | `score_gt` `score_lt` `label_in` `risk_in` |

### 执行语义

- 规则组按 `priority` 升序求值；`stop_on_hit` 为真时命中即停。
- 全部未命中 → 取 `default_result`（默认 `REVIEW`）。
- 模型不可用 → 取 `on_model_fail`（默认 `REVIEW`）。
- 单组表达式编译失败 → 跳过该组并记审计 `RULE_COMPILE_ERROR`。

## 五、动作 DSL

### 动作类型

| 类型 | 关键参数 |
| --- | --- |
| `HTTP` | `api_ref`、`method`、`path`、`headers`、`body`、`timeout_ms`、`retry` |
| `REDIS` | `command`（白名单）、`key`、`value`、`ttl_sec` |
| `MYSQL` | `datasource`、`sql`、`params`、`timeout_ms` |
| `WEBHOOK` | `url`、`sign`、`body`、`retry` |
| `MQ` | `target`、`topic`、`body` |

Redis 命令白名单：`SET` `HSET` `LPUSH` `SADD` `ZADD` `PUBLISH` `EXPIRE` `DEL`。

SQL 安全：仅允许参数化 `INSERT` / `UPDATE`；禁止 `DROP` `ALTER` `TRUNCATE` `DELETE`；
`UPDATE` 必须带 `WHERE`；参数只允许 `?` 占位。

### 模板语法

- 变量：`{{task.id}}` `{{task.result}}` `{{task.biz_key}}` `{{media.url}}` `{{model.score}}`
  `{{ext.user_id}}` `{{now}}` `{{now_ms}}`
- 过滤器：`{{ media.text | truncate:200 }}`、`{{ model.score | round:2 }}`、
  `{{ ext.user_id | default:'anonymous' }}`
- 内置函数：`uuid()` `sha256(x)` `json_escape(x)` `url_encode(x)`

## 六、幂等与去重

| 层 | 机制 |
| --- | --- |
| 接入层 | `dedupe_key = SHA256(project_id + audit_id + source_type + source_id + biz_key + [media_hash])` |
| 锁层 | Redis `SET key value NX EX 300`，value 为 `worker_id:ts`，Lua 校验后释放 |
| 存储层 | `idempotency_record` 唯一索引 `(project_id, dedupe_hash)` |
| 续租 | 处理中每 TTL/5 续租 |
| 窗口 | `dedupe_window_sec` 默认 24h |

无 `biz_key` 且无 `media_hash` 时不去重，标记 `NO_DEDUPE`。
