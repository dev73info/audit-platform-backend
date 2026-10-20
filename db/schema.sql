-- =============================================================================
-- audit-platform 审核中台 · MySQL 8.0 全量建表脚本
-- 约定：InnoDB / utf8mb4 / datetime(3) / 主键统一 bigint unsigned 雪花 ID
-- 软删除表带 deleted_at / deleted_by；所有业务表带 project_id 并建索引
-- =============================================================================

CREATE DATABASE IF NOT EXISTS `audit_platform`
  DEFAULT CHARACTER SET utf8mb4 COLLATE utf8mb4_0900_ai_ci;
USE `audit_platform`;

-- -----------------------------------------------------------------------------
-- 一、账号与权限
-- -----------------------------------------------------------------------------

CREATE TABLE IF NOT EXISTS `admin_user` (
  `id`            BIGINT UNSIGNED NOT NULL COMMENT '雪花ID',
  `username`      VARCHAR(64)     NOT NULL,
  `password_hash` VARCHAR(255)    NOT NULL COMMENT 'argon2id',
  `mfa_secret`    VARBINARY(64)   DEFAULT NULL,
  `mfa_enabled`   TINYINT(1)      NOT NULL DEFAULT 0,
  `email`         VARCHAR(128)    DEFAULT NULL,
  `display_name`  VARCHAR(64)     DEFAULT NULL,
  `role_code`     VARCHAR(32)     NOT NULL COMMENT 'SUPER_ADMIN/PROJECT_ADMIN/AUDIT_CONFIGURER/REVIEWER/READONLY',
  `status`        VARCHAR(16)     NOT NULL DEFAULT 'ACTIVE' COMMENT 'ACTIVE/LOCKED/DISABLED',
  `fail_count`    INT             NOT NULL DEFAULT 0,
  `locked_until`  DATETIME(3)     DEFAULT NULL,
  `last_login_at` DATETIME(3)     DEFAULT NULL,
  `last_login_ip` VARCHAR(64)     DEFAULT NULL,
  `created_at`    DATETIME(3)     NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
  `updated_at`    DATETIME(3)     NOT NULL DEFAULT CURRENT_TIMESTAMP(3) ON UPDATE CURRENT_TIMESTAMP(3),
  PRIMARY KEY (`id`),
  UNIQUE KEY `uk_username` (`username`),
  KEY `idx_role_status` (`role_code`, `status`),
  KEY `idx_created_at` (`created_at`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci COMMENT='后台账号';

CREATE TABLE IF NOT EXISTS `role` (
  `id`          BIGINT UNSIGNED NOT NULL,
  `code`        VARCHAR(32)  NOT NULL,
  `name`        VARCHAR(64)  NOT NULL,
  `description` VARCHAR(255) DEFAULT NULL,
  `builtin`     TINYINT(1)   NOT NULL DEFAULT 0,
  `created_at`  DATETIME(3)  NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
  `updated_at`  DATETIME(3)  NOT NULL DEFAULT CURRENT_TIMESTAMP(3) ON UPDATE CURRENT_TIMESTAMP(3),
  PRIMARY KEY (`id`),
  UNIQUE KEY `uk_code` (`code`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci COMMENT='角色';

CREATE TABLE IF NOT EXISTS `permission` (
  `id`          BIGINT UNSIGNED NOT NULL,
  `code`        VARCHAR(64)  NOT NULL COMMENT '如 project:config:write',
  `name`        VARCHAR(64)  NOT NULL,
  `module`      VARCHAR(32)  NOT NULL,
  `description` VARCHAR(255) DEFAULT NULL,
  PRIMARY KEY (`id`),
  UNIQUE KEY `uk_code` (`code`),
  KEY `idx_module` (`module`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci COMMENT='权限点';

CREATE TABLE IF NOT EXISTS `role_permission` (
  `id`            BIGINT UNSIGNED NOT NULL,
  `role_id`       BIGINT UNSIGNED NOT NULL,
  `permission_id` BIGINT UNSIGNED NOT NULL,
  PRIMARY KEY (`id`),
  UNIQUE KEY `uk_role_perm` (`role_id`, `permission_id`),
  KEY `idx_permission` (`permission_id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci COMMENT='角色权限';

CREATE TABLE IF NOT EXISTS `user_project_scope` (
  `id`         BIGINT UNSIGNED NOT NULL,
  `user_id`    BIGINT UNSIGNED NOT NULL,
  `project_id` BIGINT UNSIGNED NOT NULL,
  `created_at` DATETIME(3)  NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
  PRIMARY KEY (`id`),
  UNIQUE KEY `uk_user_project` (`user_id`, `project_id`),
  KEY `idx_project` (`project_id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci COMMENT='用户项目授权';

CREATE TABLE IF NOT EXISTS `refresh_token` (
  `id`         BIGINT UNSIGNED NOT NULL,
  `user_id`    BIGINT UNSIGNED NOT NULL,
  `token_hash` CHAR(64)     NOT NULL COMMENT 'sha256',
  `expires_at` DATETIME(3)  NOT NULL,
  `revoked_at` DATETIME(3)  DEFAULT NULL,
  `created_at` DATETIME(3)  NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
  PRIMARY KEY (`id`),
  UNIQUE KEY `uk_token_hash` (`token_hash`),
  KEY `idx_user` (`user_id`),
  KEY `idx_expires` (`expires_at`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci COMMENT='刷新令牌';

-- -----------------------------------------------------------------------------
-- 二、项目与配置
-- -----------------------------------------------------------------------------

CREATE TABLE IF NOT EXISTS `project` (
  `id`          BIGINT UNSIGNED NOT NULL,
  `name`        VARCHAR(64)  NOT NULL,
  `code`        VARCHAR(32)  NOT NULL,
  `env`         VARCHAR(16)  NOT NULL DEFAULT 'prod' COMMENT 'dev/test/staging/prod',
  `status`      VARCHAR(16)  NOT NULL DEFAULT 'ACTIVE' COMMENT 'ACTIVE/PAUSED/DISABLED/DELETED',
  `owner_id`    BIGINT UNSIGNED NOT NULL,
  `quota_json`  JSON         DEFAULT NULL,
  `retain_days` INT          NOT NULL DEFAULT 30,
  `description` VARCHAR(255) DEFAULT NULL,
  `deleted_at`  DATETIME(3)  DEFAULT NULL,
  `deleted_by`  BIGINT UNSIGNED DEFAULT NULL,
  `created_by`  BIGINT UNSIGNED NOT NULL,
  `created_at`  DATETIME(3)  NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
  `updated_at`  DATETIME(3)  NOT NULL DEFAULT CURRENT_TIMESTAMP(3) ON UPDATE CURRENT_TIMESTAMP(3),
  PRIMARY KEY (`id`),
  UNIQUE KEY `uk_code` (`code`),
  KEY `idx_status_env` (`status`, `env`),
  KEY `idx_owner` (`owner_id`),
  KEY `idx_created_at` (`created_at`),
  KEY `idx_updated_at` (`updated_at`),
  KEY `idx_deleted_at` (`deleted_at`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci COMMENT='项目';

CREATE TABLE IF NOT EXISTS `project_config` (
  `id`               BIGINT UNSIGNED NOT NULL,
  `project_id`       BIGINT UNSIGNED NOT NULL,
  `type`             VARCHAR(16)    NOT NULL COMMENT 'REDIS/MYSQL/API/OSS/MQ',
  `name`             VARCHAR(64)    NOT NULL COMMENT '配置名称，如 vendor_text_api',
  `config_encrypted` VARBINARY(4096) NOT NULL COMMENT 'AES-256-GCM 密文',
  `pool_json`        JSON          DEFAULT NULL COMMENT '连接池/超时/重试等参数',
  `tags`             JSON          DEFAULT NULL COMMENT '用途标签，如 ["TEXT","OCR"]',
  `version`          INT           NOT NULL DEFAULT 1,
  `test_status`      VARCHAR(16)   DEFAULT 'UNTESTED' COMMENT 'UNTESTED/OK/FAILED',
  `test_message`     VARCHAR(512)  DEFAULT NULL,
  `tested_at`        DATETIME(3)   DEFAULT NULL,
  `deleted_at`       DATETIME(3)   DEFAULT NULL,
  `created_at`       DATETIME(3)   NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
  `updated_at`       DATETIME(3)   NOT NULL DEFAULT CURRENT_TIMESTAMP(3) ON UPDATE CURRENT_TIMESTAMP(3),
  PRIMARY KEY (`id`),
  UNIQUE KEY `uk_project_type_name` (`project_id`, `type`, `name`),
  KEY `idx_project_type` (`project_id`, `type`),
  KEY `idx_deleted_at` (`deleted_at`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci COMMENT='项目连接配置';

CREATE TABLE IF NOT EXISTS `project_config_history` (
  `id`               BIGINT UNSIGNED NOT NULL,
  `project_id`       BIGINT UNSIGNED NOT NULL,
  `config_id`        BIGINT UNSIGNED NOT NULL,
  `version`          INT           NOT NULL,
  `config_encrypted` VARBINARY(4096) NOT NULL,
  `pool_json`        JSON          DEFAULT NULL,
  `operator_id`      BIGINT UNSIGNED NOT NULL,
  `change_note`      VARCHAR(255)  DEFAULT NULL,
  `created_at`       DATETIME(3)   NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
  PRIMARY KEY (`id`),
  UNIQUE KEY `uk_config_version` (`config_id`, `version`),
  KEY `idx_project_created` (`project_id`, `created_at`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci COMMENT='配置历史版本';

CREATE TABLE IF NOT EXISTS `resource_quota` (
  `id`                     BIGINT UNSIGNED NOT NULL,
  `project_id`             BIGINT UNSIGNED NOT NULL,
  `max_concurrency`        INT    NOT NULL DEFAULT 50,
  `max_qps`                INT    NOT NULL DEFAULT 100,
  `max_mysql_pool`         INT    NOT NULL DEFAULT 20,
  `max_redis_conn`         INT    NOT NULL DEFAULT 20,
  `max_media_size_mb`      INT    NOT NULL DEFAULT 50,
  `max_daily_tasks`        BIGINT DEFAULT NULL,
  `max_api_call_per_task`  INT    NOT NULL DEFAULT 10,
  `updated_by`             BIGINT UNSIGNED DEFAULT NULL,
  `updated_at`             DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3) ON UPDATE CURRENT_TIMESTAMP(3),
  PRIMARY KEY (`id`),
  UNIQUE KEY `uk_project` (`project_id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci COMMENT='项目资源配额';

-- -----------------------------------------------------------------------------
-- 三、审核定义
-- -----------------------------------------------------------------------------

CREATE TABLE IF NOT EXISTS `audit_definition` (
  `id`                BIGINT UNSIGNED NOT NULL,
  `project_id`        BIGINT UNSIGNED NOT NULL,
  `name`              VARCHAR(64)     NOT NULL,
  `code`              VARCHAR(32)     NOT NULL,
  `media_types`       JSON            NOT NULL COMMENT '["text","image","video"]',
  `status`            VARCHAR(16)     NOT NULL DEFAULT 'DRAFT' COMMENT 'DRAFT/ACTIVE/PAUSED/DELETED',
  `concurrency`       INT             NOT NULL DEFAULT 10,
  `timeout_ms`        INT             NOT NULL DEFAULT 30000,
  `retry_policy`      JSON            DEFAULT NULL,
  `dedupe_window_sec` INT             NOT NULL DEFAULT 86400,
  `media_hash_in_key` TINYINT(1)      NOT NULL DEFAULT 1,
  `config_json`       JSON            DEFAULT NULL COMMENT '规则/路由/媒体审核/默认结果等完整配置快照',
  `config_version`    INT             NOT NULL DEFAULT 1,
  `description`       VARCHAR(255)    DEFAULT NULL,
  `deleted_at`        DATETIME(3)     DEFAULT NULL,
  `deleted_by`        BIGINT UNSIGNED DEFAULT NULL,
  `created_by`        BIGINT UNSIGNED NOT NULL,
  `created_at`        DATETIME(3)     NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
  `updated_at`        DATETIME(3)     NOT NULL DEFAULT CURRENT_TIMESTAMP(3) ON UPDATE CURRENT_TIMESTAMP(3),
  PRIMARY KEY (`id`),
  UNIQUE KEY `uk_project_code` (`project_id`, `code`),
  UNIQUE KEY `uk_project_name` (`project_id`, `name`),
  KEY `idx_project_status` (`project_id`, `status`),
  KEY `idx_created_at` (`created_at`),
  KEY `idx_updated_at` (`updated_at`),
  KEY `idx_deleted_at` (`deleted_at`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci COMMENT='审核定义';

CREATE TABLE IF NOT EXISTS `trigger_source` (
  `id`               BIGINT UNSIGNED NOT NULL,
  `project_id`       BIGINT UNSIGNED NOT NULL,
  `audit_id`         BIGINT UNSIGNED NOT NULL,
  `type`             VARCHAR(16)    NOT NULL COMMENT 'REDIS/POLLING/WEBSOCKET/OPENAPI',
  `name`             VARCHAR(64)    NOT NULL,
  `config_json`      JSON           NOT NULL,
  `priority`         INT            NOT NULL DEFAULT 10,
  `status`           VARCHAR(16)    NOT NULL DEFAULT 'ACTIVE',
  `last_error`       VARCHAR(512)   DEFAULT NULL,
  `last_consume_at`  DATETIME(3)    DEFAULT NULL,
  `success_count`    BIGINT         NOT NULL DEFAULT 0,
  `fail_count`       BIGINT         NOT NULL DEFAULT 0,
  `deleted_at`       DATETIME(3)    DEFAULT NULL,
  `created_at`       DATETIME(3)    NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
  `updated_at`       DATETIME(3)    NOT NULL DEFAULT CURRENT_TIMESTAMP(3) ON UPDATE CURRENT_TIMESTAMP(3),
  PRIMARY KEY (`id`),
  UNIQUE KEY `uk_audit_name` (`audit_id`, `name`),
  KEY `idx_project_audit` (`project_id`, `audit_id`),
  KEY `idx_status_priority` (`status`, `priority`),
  KEY `idx_deleted_at` (`deleted_at`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci COMMENT='触发源';

CREATE TABLE IF NOT EXISTS `trigger_consume_log` (
  `id`            BIGINT UNSIGNED NOT NULL,
  `project_id`    BIGINT UNSIGNED NOT NULL,
  `audit_id`      BIGINT UNSIGNED NOT NULL,
  `trigger_id`    BIGINT UNSIGNED NOT NULL,
  `message_id`    VARCHAR(128)    DEFAULT NULL,
  `status`        VARCHAR(16)    NOT NULL COMMENT 'SUCCESS/FAILED',
  `duration_ms`   INT            DEFAULT NULL,
  `error_message` VARCHAR(512)   DEFAULT NULL,
  `created_at`    DATETIME(3)    NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
  PRIMARY KEY (`id`),
  KEY `idx_trigger_created` (`trigger_id`, `created_at`),
  KEY `idx_project_created` (`project_id`, `created_at`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci COMMENT='触发源最近消费记录';

CREATE TABLE IF NOT EXISTS `audit_rule` (
  `id`             BIGINT UNSIGNED NOT NULL,
  `project_id`     BIGINT UNSIGNED NOT NULL,
  `audit_id`       BIGINT UNSIGNED NOT NULL,
  `name`           VARCHAR(64)    NOT NULL,
  `priority`       INT            NOT NULL DEFAULT 100,
  `logic`          VARCHAR(8)     NOT NULL DEFAULT 'AND',
  `stop_on_hit`    TINYINT(1)     NOT NULL DEFAULT 1,
  `on_hit_result`  VARCHAR(16)    NOT NULL COMMENT 'PASS/REJECT/REVIEW',
  `status`         VARCHAR(16)    NOT NULL DEFAULT 'ACTIVE',
  `deleted_at`     DATETIME(3)    DEFAULT NULL,
  `created_at`     DATETIME(3)    NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
  `updated_at`     DATETIME(3)    NOT NULL DEFAULT CURRENT_TIMESTAMP(3) ON UPDATE CURRENT_TIMESTAMP(3),
  PRIMARY KEY (`id`),
  KEY `idx_audit_priority` (`audit_id`, `priority`),
  KEY `idx_project_audit` (`project_id`, `audit_id`),
  KEY `idx_deleted_at` (`deleted_at`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci COMMENT='规则组';

CREATE TABLE IF NOT EXISTS `rule_item` (
  `id`             BIGINT UNSIGNED NOT NULL,
  `rule_id`        BIGINT UNSIGNED NOT NULL,
  `field`          VARCHAR(128)   NOT NULL,
  `operator`       VARCHAR(32)    NOT NULL,
  `value_json`     JSON           NOT NULL,
  `case_sensitive` TINYINT(1)     NOT NULL DEFAULT 0,
  `negate`         TINYINT(1)     NOT NULL DEFAULT 0,
  `sort_order`     INT            NOT NULL DEFAULT 0,
  PRIMARY KEY (`id`),
  KEY `idx_rule` (`rule_id`, `sort_order`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci COMMENT='规则条件项';

CREATE TABLE IF NOT EXISTS `result_route` (
  `id`           BIGINT UNSIGNED NOT NULL,
  `project_id`   BIGINT UNSIGNED NOT NULL,
  `audit_id`     BIGINT UNSIGNED NOT NULL,
  `result_type`  VARCHAR(16)    NOT NULL COMMENT 'PASS/REJECT/REVIEW',
  `exec_mode`    VARCHAR(16)    NOT NULL DEFAULT 'sequential',
  `on_error`     VARCHAR(16)    NOT NULL DEFAULT 'to_review',
  `actions_json` JSON           NOT NULL,
  `status`       VARCHAR(16)    NOT NULL DEFAULT 'ACTIVE',
  `deleted_at`   DATETIME(3)    DEFAULT NULL,
  `updated_at`   DATETIME(3)    NOT NULL DEFAULT CURRENT_TIMESTAMP(3) ON UPDATE CURRENT_TIMESTAMP(3),
  PRIMARY KEY (`id`),
  UNIQUE KEY `uk_audit_result` (`audit_id`, `result_type`),
  KEY `idx_project_audit` (`project_id`, `audit_id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci COMMENT='结果路由';

-- -----------------------------------------------------------------------------
-- 四、任务与执行
-- -----------------------------------------------------------------------------

CREATE TABLE IF NOT EXISTS `audit_task` (
  `id`                BIGINT UNSIGNED NOT NULL,
  `task_no`           VARCHAR(32)    NOT NULL COMMENT '对外任务号',
  `project_id`        BIGINT UNSIGNED NOT NULL,
  `audit_id`          BIGINT UNSIGNED NOT NULL,
  `source_type`       VARCHAR(16)    NOT NULL,
  `source_id`         BIGINT UNSIGNED DEFAULT NULL,
  `biz_key`           VARCHAR(128)   DEFAULT NULL,
  `dedupe_hash`       CHAR(64)       DEFAULT NULL,
  `media_type`        VARCHAR(16)    NOT NULL COMMENT 'text/image/video/mixed',
  `status`            VARCHAR(24)    NOT NULL,
  `result`            VARCHAR(16)    DEFAULT 'UNKNOWN' COMMENT 'PASS/REJECT/REVIEW/UNKNOWN',
  `dedupe_flag`       VARCHAR(16)    DEFAULT 'NORMAL' COMMENT 'NORMAL/DUPLICATED/NO_DEDUPE',
  `payload_ref`       VARCHAR(512)   DEFAULT NULL,
  `payload_json`      JSON           DEFAULT NULL COMMENT '媒体与扩展字段快照',
  `rule_hit_json`     JSON           DEFAULT NULL,
  `model_result_json` JSON           DEFAULT NULL,
  `retry_count`       INT            NOT NULL DEFAULT 0,
  `error_code`        VARCHAR(64)    DEFAULT NULL,
  `error_message`     VARCHAR(512)   DEFAULT NULL,
  `duration_ms`       INT            DEFAULT NULL,
  `trace_id`          VARCHAR(64)    DEFAULT NULL,
  `created_at`        DATETIME(3)    NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
  `updated_at`        DATETIME(3)    NOT NULL DEFAULT CURRENT_TIMESTAMP(3) ON UPDATE CURRENT_TIMESTAMP(3),
  `finished_at`       DATETIME(3)    DEFAULT NULL,
  PRIMARY KEY (`id`, `created_at`),
  UNIQUE KEY `uk_task_no` (`task_no`, `created_at`),
  UNIQUE KEY `uk_dedupe` (`project_id`, `dedupe_hash`, `created_at`),
  KEY `idx_project_created` (`project_id`, `created_at`),
  KEY `idx_audit_status` (`audit_id`, `status`, `created_at`),
  KEY `idx_project_result` (`project_id`, `result`, `created_at`),
  KEY `idx_status_created` (`status`, `created_at`),
  KEY `idx_biz_key` (`project_id`, `biz_key`, `created_at`),
  KEY `idx_finished_at` (`finished_at`),
  KEY `idx_duration` (`duration_ms`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci COMMENT='审核任务'
PARTITION BY RANGE COLUMNS(`created_at`) (
  PARTITION p2026_01 VALUES LESS THAN ('2026-02-01'),
  PARTITION p2026_02 VALUES LESS THAN ('2026-03-01'),
  PARTITION p2026_03 VALUES LESS THAN ('2026-04-01'),
  PARTITION p2026_04 VALUES LESS THAN ('2026-05-01'),
  PARTITION p2026_06 VALUES LESS THAN ('2026-07-01'),
  PARTITION p2026_07 VALUES LESS THAN ('2026-08-01'),
  PARTITION p2026_08 VALUES LESS THAN ('2026-09-01'),
  PARTITION p2026_09 VALUES LESS THAN ('2026-10-01'),
  PARTITION p2026_10 VALUES LESS THAN ('2026-11-01'),
  PARTITION p2026_11 VALUES LESS THAN ('2026-12-01'),
  PARTITION p2026_12 VALUES LESS THAN ('2027-01-01'),
  PARTITION pmax    VALUES LESS THAN (MAXVALUE)
);

CREATE TABLE IF NOT EXISTS `idempotency_record` (
  `id`          BIGINT UNSIGNED NOT NULL,
  `project_id`  BIGINT UNSIGNED NOT NULL,
  `dedupe_hash` CHAR(64)       NOT NULL,
  `task_id`     BIGINT UNSIGNED NOT NULL,
  `status`      VARCHAR(16)    NOT NULL DEFAULT 'PROCESSING',
  `expire_at`   DATETIME(3)    NOT NULL,
  `created_at`  DATETIME(3)    NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
  PRIMARY KEY (`id`),
  UNIQUE KEY `uk_project_hash` (`project_id`, `dedupe_hash`),
  KEY `idx_expire` (`expire_at`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci COMMENT='幂等记录';

CREATE TABLE IF NOT EXISTS `media_asset` (
  `id`         BIGINT UNSIGNED NOT NULL,
  `task_id`    BIGINT UNSIGNED NOT NULL,
  `project_id` BIGINT UNSIGNED NOT NULL,
  `type`       VARCHAR(16)    NOT NULL,
  `url`        VARCHAR(1024)  NOT NULL,
  `oss_key`    VARCHAR(512)   DEFAULT NULL,
  `hash`       CHAR(64)       DEFAULT NULL,
  `size_bytes` BIGINT         DEFAULT NULL,
  `meta_json`  JSON           DEFAULT NULL,
  `created_at` DATETIME(3)    NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
  PRIMARY KEY (`id`),
  KEY `idx_task` (`task_id`),
  KEY `idx_project_hash` (`project_id`, `hash`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci COMMENT='媒体资产';

CREATE TABLE IF NOT EXISTS `task_event` (
  `id`         BIGINT UNSIGNED NOT NULL,
  `task_id`    BIGINT UNSIGNED NOT NULL,
  `project_id` BIGINT UNSIGNED NOT NULL,
  `from_status` VARCHAR(24)   DEFAULT NULL,
  `to_status`  VARCHAR(24)    NOT NULL,
  `message`    VARCHAR(512)   DEFAULT NULL,
  `cost_ms`    INT            DEFAULT NULL,
  `created_at` DATETIME(3)    NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
  PRIMARY KEY (`id`, `created_at`),
  KEY `idx_task_created` (`task_id`, `created_at`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci COMMENT='任务事件流水'
PARTITION BY RANGE COLUMNS(`created_at`) (
  PARTITION p2026_01 VALUES LESS THAN ('2026-02-01'),
  PARTITION p2026_02 VALUES LESS THAN ('2026-03-01'),
  PARTITION p2026_03 VALUES LESS THAN ('2026-04-01'),
  PARTITION p2026_04 VALUES LESS THAN ('2026-05-01'),
  PARTITION p2026_05 VALUES LESS THAN ('2026-06-01'),
  PARTITION p2026_06 VALUES LESS THAN ('2026-07-01'),
  PARTITION p2026_07 VALUES LESS THAN ('2026-08-01'),
  PARTITION p2026_08 VALUES LESS THAN ('2026-09-01'),
  PARTITION p2026_09 VALUES LESS THAN ('2026-10-01'),
  PARTITION p2026_10 VALUES LESS THAN ('2026-11-01'),
  PARTITION p2026_11 VALUES LESS THAN ('2026-12-01'),
  PARTITION p2026_12 VALUES LESS THAN ('2027-01-01'),
  PARTITION pmax    VALUES LESS THAN (MAXVALUE)
);

CREATE TABLE IF NOT EXISTS `action_exec_log` (
  `id`            BIGINT UNSIGNED NOT NULL,
  `task_id`       BIGINT UNSIGNED NOT NULL,
  `project_id`    BIGINT UNSIGNED NOT NULL,
  `route_type`    VARCHAR(16)    NOT NULL,
  `action_id`     VARCHAR(64)    NOT NULL,
  `action_type`   VARCHAR(16)    NOT NULL COMMENT 'HTTP/REDIS/MYSQL/WEBHOOK/MQ',
  `action_name`   VARCHAR(128)   DEFAULT NULL,
  `request_json`  JSON           DEFAULT NULL COMMENT '脱敏后',
  `response_json` JSON           DEFAULT NULL,
  `status`        VARCHAR(16)    NOT NULL COMMENT 'SUCCESS/FAILED/SKIPPED',
  `retry_count`   INT            NOT NULL DEFAULT 0,
  `duration_ms`   INT            DEFAULT NULL,
  `error_message` VARCHAR(512)   DEFAULT NULL,
  `created_at`    DATETIME(3)    NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
  PRIMARY KEY (`id`, `created_at`),
  KEY `idx_task` (`task_id`, `created_at`),
  KEY `idx_project_type_status` (`project_id`, `action_type`, `status`, `created_at`),
  KEY `idx_status_created` (`status`, `created_at`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci COMMENT='动作执行日志'
PARTITION BY RANGE COLUMNS(`created_at`) (
  PARTITION p2026_01 VALUES LESS THAN ('2026-02-01'),
  PARTITION p2026_02 VALUES LESS THAN ('2026-03-01'),
  PARTITION p2026_03 VALUES LESS THAN ('2026-04-01'),
  PARTITION p2026_04 VALUES LESS THAN ('2026-05-01'),
  PARTITION p2026_05 VALUES LESS THAN ('2026-06-01'),
  PARTITION p2026_06 VALUES LESS THAN ('2026-07-01'),
  PARTITION p2026_07 VALUES LESS THAN ('2026-08-01'),
  PARTITION p2026_08 VALUES LESS THAN ('2026-09-01'),
  PARTITION p2026_09 VALUES LESS THAN ('2026-10-01'),
  PARTITION p2026_10 VALUES LESS THAN ('2026-11-01'),
  PARTITION p2026_11 VALUES LESS THAN ('2026-12-01'),
  PARTITION p2026_12 VALUES LESS THAN ('2027-01-01'),
  PARTITION pmax    VALUES LESS THAN (MAXVALUE)
);

CREATE TABLE IF NOT EXISTS `review_opinion` (
  `id`          BIGINT UNSIGNED NOT NULL,
  `task_id`     BIGINT UNSIGNED NOT NULL,
  `project_id`  BIGINT UNSIGNED NOT NULL,
  `reviewer_id` BIGINT UNSIGNED NOT NULL,
  `conclusion`  VARCHAR(16)    NOT NULL COMMENT 'PASS/REJECT',
  `reason_code` VARCHAR(64)    DEFAULT NULL,
  `remark`      VARCHAR(512)   DEFAULT NULL,
  `created_at`  DATETIME(3)    NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
  PRIMARY KEY (`id`),
  UNIQUE KEY `uk_task` (`task_id`),
  KEY `idx_project_reviewer` (`project_id`, `reviewer_id`, `created_at`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci COMMENT='人工复核意见';

-- -----------------------------------------------------------------------------
-- 五、运维
-- -----------------------------------------------------------------------------

CREATE TABLE IF NOT EXISTS `recycle_bin` (
  `id`           BIGINT UNSIGNED NOT NULL,
  `project_id`   BIGINT UNSIGNED NOT NULL,
  `object_type`  VARCHAR(16)    NOT NULL COMMENT 'PROJECT/AUDIT',
  `object_id`    BIGINT UNSIGNED NOT NULL,
  `object_name`  VARCHAR(64)    NOT NULL,
  `object_code`  VARCHAR(32)    DEFAULT NULL,
  `snapshot_json` JSON          NOT NULL COMMENT '删除时快照，用于恢复校验',
  `deleted_by`   BIGINT UNSIGNED NOT NULL,
  `deleted_at`   DATETIME(3)    NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
  `expire_at`    DATETIME(3)    NOT NULL,
  `purge_status` VARCHAR(16)    DEFAULT 'NONE' COMMENT 'NONE/PURGING/PURGED',
  `purge_message` VARCHAR(512)  DEFAULT NULL,
  PRIMARY KEY (`id`),
  UNIQUE KEY `uk_object` (`object_type`, `object_id`),
  KEY `idx_project_deleted` (`project_id`, `deleted_at`),
  KEY `idx_expire` (`expire_at`),
  KEY `idx_name` (`object_name`),
  KEY `idx_deleted_by` (`deleted_by`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci COMMENT='回收站';

CREATE TABLE IF NOT EXISTS `audit_log` (
  `id`          BIGINT UNSIGNED NOT NULL,
  `project_id`  BIGINT UNSIGNED DEFAULT NULL,
  `operator`    VARCHAR(64)    NOT NULL,
  `operator_id` BIGINT UNSIGNED DEFAULT NULL,
  `operator_ip` VARCHAR(64)    DEFAULT NULL,
  `action`      VARCHAR(64)    NOT NULL,
  `object_type` VARCHAR(32)    DEFAULT NULL,
  `object_id`   VARCHAR(64)    DEFAULT NULL,
  `result`      VARCHAR(16)    NOT NULL DEFAULT 'SUCCESS',
  `detail_json` JSON           DEFAULT NULL,
  `trace_id`    VARCHAR(64)    DEFAULT NULL,
  `created_at`  DATETIME(3)    NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
  PRIMARY KEY (`id`, `created_at`),
  KEY `idx_project_created` (`project_id`, `created_at`),
  KEY `idx_operator` (`operator_id`, `created_at`),
  KEY `idx_action` (`action`, `created_at`),
  KEY `idx_object` (`object_type`, `object_id`, `created_at`),
  KEY `idx_result` (`result`, `created_at`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci COMMENT='审计日志'
PARTITION BY RANGE COLUMNS(`created_at`) (
  PARTITION p2026_01 VALUES LESS THAN ('2026-02-01'),
  PARTITION p2026_02 VALUES LESS THAN ('2026-03-01'),
  PARTITION p2026_03 VALUES LESS THAN ('2026-04-01'),
  PARTITION p2026_04 VALUES LESS THAN ('2026-05-01'),
  PARTITION p2026_05 VALUES LESS THAN ('2026-06-01'),
  PARTITION p2026_06 VALUES LESS THAN ('2026-07-01'),
  PARTITION p2026_07 VALUES LESS THAN ('2026-08-01'),
  PARTITION p2026_08 VALUES LESS THAN ('2026-09-01'),
  PARTITION p2026_09 VALUES LESS THAN ('2026-10-01'),
  PARTITION p2026_10 VALUES LESS THAN ('2026-11-01'),
  PARTITION p2026_11 VALUES LESS THAN ('2026-12-01'),
  PARTITION p2026_12 VALUES LESS THAN ('2027-01-01'),
  PARTITION pmax    VALUES LESS THAN (MAXVALUE)
);

CREATE TABLE IF NOT EXISTS `api_client` (
  `id`               BIGINT UNSIGNED NOT NULL,
  `project_id`       BIGINT UNSIGNED NOT NULL,
  `app_key`          VARCHAR(32)    NOT NULL,
  `secret_encrypted` VARBINARY(256) NOT NULL,
  `name`             VARCHAR(64)    NOT NULL,
  `status`           VARCHAR(16)    NOT NULL DEFAULT 'ACTIVE',
  `rate_limit_json`  JSON           DEFAULT NULL,
  `allow_ips`        JSON           DEFAULT NULL,
  `callback_url`     VARCHAR(512)   DEFAULT NULL,
  `callback_secret_encrypted` VARBINARY(256) DEFAULT NULL,
  `last_used_at`     DATETIME(3)    DEFAULT NULL,
  `created_at`       DATETIME(3)    NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
  `updated_at`       DATETIME(3)    NOT NULL DEFAULT CURRENT_TIMESTAMP(3) ON UPDATE CURRENT_TIMESTAMP(3),
  PRIMARY KEY (`id`),
  UNIQUE KEY `uk_app_key` (`app_key`),
  KEY `idx_project` (`project_id`, `status`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci COMMENT='开放 API 客户端';

CREATE TABLE IF NOT EXISTS `alert_rule` (
  `id`          BIGINT UNSIGNED NOT NULL,
  `project_id`  BIGINT UNSIGNED DEFAULT NULL COMMENT 'NULL 表示全局',
  `name`        VARCHAR(64)    NOT NULL,
  `metric`      VARCHAR(64)    NOT NULL,
  `expression`  VARCHAR(512)   NOT NULL,
  `level`       VARCHAR(8)     NOT NULL DEFAULT 'P3',
  `enabled`     TINYINT(1)     NOT NULL DEFAULT 1,
  `notify_json` JSON           DEFAULT NULL,
  `created_at`  DATETIME(3)    NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
  `updated_at`  DATETIME(3)    NOT NULL DEFAULT CURRENT_TIMESTAMP(3) ON UPDATE CURRENT_TIMESTAMP(3),
  PRIMARY KEY (`id`),
  KEY `idx_project_enabled` (`project_id`, `enabled`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci COMMENT='告警规则';

CREATE TABLE IF NOT EXISTS `alert_event` (
  `id`          BIGINT UNSIGNED NOT NULL,
  `project_id`  BIGINT UNSIGNED DEFAULT NULL,
  `rule_id`     BIGINT UNSIGNED DEFAULT NULL,
  `name`        VARCHAR(64)    NOT NULL,
  `level`       VARCHAR(8)     NOT NULL DEFAULT 'P3',
  `status`      VARCHAR(16)    NOT NULL DEFAULT 'FIRING' COMMENT 'FIRING/RESOLVED',
  `message`     VARCHAR(512)   DEFAULT NULL,
  `value`       VARCHAR(128)   DEFAULT NULL,
  `started_at`  DATETIME(3)    NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
  `resolved_at` DATETIME(3)    DEFAULT NULL,
  `created_at`  DATETIME(3)    NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
  PRIMARY KEY (`id`),
  KEY `idx_project_status` (`project_id`, `status`),
  KEY `idx_started_at` (`started_at`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci COMMENT='告警事件';

CREATE TABLE IF NOT EXISTS `project_hourly_stat` (
  `id`             BIGINT UNSIGNED NOT NULL,
  `project_id`     BIGINT UNSIGNED NOT NULL,
  `stat_hour`      DATETIME(3)    NOT NULL,
  `task_total`     BIGINT         NOT NULL DEFAULT 0,
  `task_pass`      BIGINT         NOT NULL DEFAULT 0,
  `task_reject`    BIGINT         NOT NULL DEFAULT 0,
  `task_review`    BIGINT         NOT NULL DEFAULT 0,
  `task_failed`    BIGINT         NOT NULL DEFAULT 0,
  `dedupe_hit`     BIGINT         NOT NULL DEFAULT 0,
  `duration_sum_ms` BIGINT        NOT NULL DEFAULT 0,
  `duration_max_ms` INT           NOT NULL DEFAULT 0,
  `action_total`   BIGINT         NOT NULL DEFAULT 0,
  `action_failed`  BIGINT         NOT NULL DEFAULT 0,
  `updated_at`     DATETIME(3)    NOT NULL DEFAULT CURRENT_TIMESTAMP(3) ON UPDATE CURRENT_TIMESTAMP(3),
  PRIMARY KEY (`id`),
  UNIQUE KEY `uk_project_hour` (`project_id`, `stat_hour`),
  KEY `idx_stat_hour` (`stat_hour`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci COMMENT='项目小时级汇总';

CREATE TABLE IF NOT EXISTS `saved_view` (
  `id`          BIGINT UNSIGNED NOT NULL,
  `user_id`     BIGINT UNSIGNED NOT NULL,
  `project_id`  BIGINT UNSIGNED DEFAULT NULL,
  `page_key`    VARCHAR(64)    NOT NULL COMMENT 'projects/audits/tasks/...',
  `name`        VARCHAR(64)    NOT NULL,
  `filters_json` JSON          DEFAULT NULL,
  `sort_json`   JSON           DEFAULT NULL,
  `columns_json` JSON          DEFAULT NULL,
  `density`     VARCHAR(16)    DEFAULT 'normal',
  `is_default`  TINYINT(1)     NOT NULL DEFAULT 0,
  `shared`      TINYINT(1)     NOT NULL DEFAULT 0,
  `created_at`  DATETIME(3)    NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
  `updated_at`  DATETIME(3)    NOT NULL DEFAULT CURRENT_TIMESTAMP(3) ON UPDATE CURRENT_TIMESTAMP(3),
  PRIMARY KEY (`id`),
  KEY `idx_user_page` (`user_id`, `page_key`),
  KEY `idx_project` (`project_id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci COMMENT='保存的列表视图';

CREATE TABLE IF NOT EXISTS `export_task` (
  `id`           BIGINT UNSIGNED NOT NULL,
  `project_id`   BIGINT UNSIGNED DEFAULT NULL,
  `requested_by` BIGINT UNSIGNED NOT NULL,
  `page_key`     VARCHAR(64)    NOT NULL,
  `filters_json` JSON           DEFAULT NULL,
  `format`       VARCHAR(16)    NOT NULL DEFAULT 'CSV',
  `status`       VARCHAR(16)    NOT NULL DEFAULT 'PENDING' COMMENT 'PENDING/RUNNING/DONE/FAILED',
  `total_rows`   INT            NOT NULL DEFAULT 0,
  `file_path`    VARCHAR(512)   DEFAULT NULL,
  `error_message` VARCHAR(512)  DEFAULT NULL,
  `created_at`   DATETIME(3)    NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
  `finished_at`  DATETIME(3)    DEFAULT NULL,
  PRIMARY KEY (`id`),
  KEY `idx_requester` (`requested_by`, `created_at`),
  KEY `idx_status` (`status`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci COMMENT='导出任务';

CREATE TABLE IF NOT EXISTS `cleanup_task` (
  `id`           BIGINT UNSIGNED NOT NULL,
  `recycle_id`   BIGINT UNSIGNED DEFAULT NULL,
  `object_type`  VARCHAR(16)    NOT NULL,
  `object_id`    BIGINT UNSIGNED NOT NULL,
  `object_name`  VARCHAR(64)    NOT NULL,
  `status`       VARCHAR(16)    NOT NULL DEFAULT 'PENDING' COMMENT 'PENDING/RUNNING/DONE/FAILED',
  `progress`     INT            NOT NULL DEFAULT 0,
  `step`         VARCHAR(64)    DEFAULT NULL,
  `error_message` VARCHAR(512)  DEFAULT NULL,
  `created_by`   BIGINT UNSIGNED NOT NULL,
  `created_at`   DATETIME(3)    NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
  `finished_at`  DATETIME(3)    DEFAULT NULL,
  PRIMARY KEY (`id`),
  KEY `idx_recycle` (`recycle_id`),
  KEY `idx_status` (`status`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci COMMENT='清理任务';

CREATE TABLE IF NOT EXISTS `notification` (
  `id`          BIGINT UNSIGNED NOT NULL,
  `user_id`     BIGINT UNSIGNED DEFAULT NULL COMMENT 'NULL 表示全体',
  `project_id`  BIGINT UNSIGNED DEFAULT NULL,
  `category`    VARCHAR(32)    NOT NULL COMMENT 'ALERT/EXPORT/CLEANUP/REVIEW',
  `title`       VARCHAR(128)   NOT NULL,
  `content`     VARCHAR(512)   DEFAULT NULL,
  `link`        VARCHAR(512)   DEFAULT NULL,
  `read_at`     DATETIME(3)    DEFAULT NULL,
  `created_at`  DATETIME(3)    NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
  PRIMARY KEY (`id`),
  KEY `idx_user_read` (`user_id`, `read_at`, `created_at`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci COMMENT='站内通知';
