# audit-platform-backend —— 独立审核系统平台 · Rust 后端

多项目隔离的通用内容审核中台后端：**Actix Web 4 + sqlx(MySQL 8) + Redis**。

业务方通过四种触发方式（Redis 队列 / 轮询接口 / WebSocket / 开放 API）提交内容，
系统按配置完成去重、规则判定、媒体审核、结果路由与动作执行，再把结论回写给业务方。

配套的管理控制台：[`dev73info/audit-platform-frontend`](https://github.com/dev73info/audit-platform-frontend)

## 目录

| 路径 | 说明 |
| --- | --- |
| `src/` | Actix Web 服务：`modules/` 按业务模块分层（handlers / service / repositories / routes） |
| `src/engine/` | 规则引擎、动作引擎、媒体审核、模板渲染、异步 Worker |
| `db/` | MySQL 8 全量 DDL（`schema.sql`）与初始化数据（`seed.sql`） |
| `config/` | `default.toml` 默认配置、`local.example.toml` 本机配置样例（真实值写 `local.toml`，不入库） |
| `doc/` | 设计文档、API 契约、开发约定 |
| `deploy/` | 本地 MySQL + Redis 的 docker-compose |

## 快速开始

```bash
# 1. 起 MySQL 8 + Redis（MySQL: audit/audit，库 audit_platform）
docker compose -f deploy/docker-compose.yml up -d

# 2. 准备本机配置
cd config
cp local.example.toml local.toml     # 按需改数据库 / Redis / jwt_secret / encryption_key

# 3. 初始化库表与初始管理员
cd ..
cargo run --bin migrate

# 4. 启动后端（监听 8090）
cargo run --bin audit-platform
```

默认管理员：`admin` / `Test@123456`（见 `db/seed.sql`，上线前必须改）。

## 接口前缀

| 前缀 | 说明 |
| --- | --- |
| `/api/admin/v1` | 管理端 API（JWT 鉴权） |
| `/open/v1` | 开放 API（HMAC-SHA256 签名） |
| `/metrics` | Prometheus 指标 |

接口契约以 [`doc/API.md`](doc/API.md) 为唯一事实源；规则与动作 DSL 见该文档第四、五章。

## 校验

| 场景 | 命令 |
| --- | --- |
| 改代码后先跑 | `cargo check --all-targets` |
| 单元测试 | `cargo test --lib` |
| 生产构建 | `cargo build --release` |

## 安全约定

- 连接配置用 AES-256-GCM 加密落库（按项目派生子密钥），界面只出脱敏值。
- 开放 API 的 AppSecret 只在创建与轮换时明文返回一次。
- 第三方 API BaseURL 与 Webhook 地址禁止内网段（SSRF 防护）。
- SQL 动作白名单只允许参数化 `INSERT` / `UPDATE`，`UPDATE` 必须带 `WHERE`。
- 生产部署前必须替换 `local.toml` 里的 `jwt_secret` 与 `encryption_key`。
