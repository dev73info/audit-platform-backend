-- =============================================================================
-- audit-platform 初始化数据（角色 / 权限 / 授权矩阵 / 默认项目 / 开放 API 客户端）
-- 由 `cargo run --bin migrate` 在建表后执行；admin 账号由迁移程序按配置哈希写入。
-- =============================================================================
USE `audit_platform`;

-- 权限点 -----------------------------------------------------------------------
INSERT INTO `permission` (`id`, `code`, `name`, `module`) VALUES
  (1001, 'project:read',          '查看项目',           'project'),
  (1002, 'project:write',         '创建与编辑项目',     'project'),
  (1003, 'project:delete',        '删除项目',           'project'),
  (1004, 'project:config:read',   '查看项目连接配置',   'project'),
  (1005, 'project:config:write',  '修改项目连接配置',   'project'),
  (1006, 'project:config:reveal', '查看密钥明文',       'project'),
  (1007, 'audit:read',            '查看审核定义',       'audit'),
  (1008, 'audit:write',           '创建与编辑审核',     'audit'),
  (1009, 'audit:delete',          '删除审核',           'audit'),
  (1010, 'rule:read',             '查看规则',           'rule'),
  (1011, 'rule:write',            '编辑规则',           'rule'),
  (1012, 'route:read',            '查看结果路由',       'route'),
  (1013, 'route:write',           '编辑结果路由',       'route'),
  (1014, 'trigger:read',          '查看触发源',         'trigger'),
  (1015, 'trigger:write',         '编辑触发源',         'trigger'),
  (1016, 'task:read',             '查看任务',           'task'),
  (1017, 'task:retry',            '重试任务与动作',     'task'),
  (1018, 'task:stop',             '强制停止任务',       'task'),
  (1019, 'task:review',           '处理待议复核',       'task'),
  (1020, 'recycle:read',          '查看回收站',         'recycle'),
  (1021, 'recycle:restore',       '恢复回收站对象',     'recycle'),
  (1022, 'recycle:purge',         '永久删除回收站对象', 'recycle'),
  (1023, 'audit_log:read',        '查看审计日志',       'ops'),
  (1024, 'audit_log:export',      '导出审计日志',       'ops'),
  (1025, 'metrics:read',          '查看监控指标',       'ops'),
  (1026, 'user:read',             '查看用户',           'system'),
  (1027, 'user:write',            '管理用户与角色',     'system'),
  (1028, 'apiclient:read',        '查看开放 API 客户端','system'),
  (1029, 'apiclient:write',       '管理开放 API 客户端','system')
ON DUPLICATE KEY UPDATE `name` = VALUES(`name`), `module` = VALUES(`module`);

-- 角色 -----------------------------------------------------------------------
INSERT INTO `role` (`id`, `code`, `name`, `description`, `builtin`) VALUES
  (2001, 'SUPER_ADMIN',       '超级管理员',   '系统全局管理者，可管理全部项目', 1),
  (2002, 'PROJECT_ADMIN',     '项目管理员',   '被授权项目的负责人',            1),
  (2003, 'AUDIT_CONFIGURER',  '审核配置员',   '负责审核流程配置，不含密钥改写', 1),
  (2004, 'REVIEWER',          '审核员/复核员','处理待议与人工复核',            1),
  (2005, 'READONLY',          '只读用户',     '观察、排障与审计',              1)
ON DUPLICATE KEY UPDATE `name` = VALUES(`name`), `description` = VALUES(`description`);

-- 角色-权限授权矩阵 ------------------------------------------------------------
-- 超级管理员：全部
INSERT INTO `role_permission` (`id`, `role_id`, `permission_id`)
SELECT 300000 + p.`id`, 2001, p.`id` FROM `permission` p
ON DUPLICATE KEY UPDATE `role_id` = VALUES(`role_id`);

-- 项目管理员：除系统级管理外全给
INSERT INTO `role_permission` (`id`, `role_id`, `permission_id`)
SELECT 310000 + p.`id`, 2002, p.`id` FROM `permission` p
WHERE p.`code` IN (
  'project:read','project:write','project:config:read','project:config:write','project:config:reveal',
  'audit:read','audit:write','audit:delete',
  'rule:read','rule:write','route:read','route:write','trigger:read','trigger:write',
  'task:read','task:retry','task:stop','task:review',
  'recycle:read','recycle:restore',
  'audit_log:read','metrics:read','apiclient:read'
)
ON DUPLICATE KEY UPDATE `role_id` = VALUES(`role_id`);

-- 审核配置员：配置权，无密钥改写
INSERT INTO `role_permission` (`id`, `role_id`, `permission_id`)
SELECT 320000 + p.`id`, 2003, p.`id` FROM `permission` p
WHERE p.`code` IN (
  'project:read','project:config:read',
  'audit:read','audit:write',
  'rule:read','rule:write','route:read','route:write','trigger:read','trigger:write',
  'task:read','audit_log:read','metrics:read'
)
ON DUPLICATE KEY UPDATE `role_id` = VALUES(`role_id`);

-- 审核员 / 复核员
INSERT INTO `role_permission` (`id`, `role_id`, `permission_id`)
SELECT 330000 + p.`id`, 2004, p.`id` FROM `permission` p
WHERE p.`code` IN ('project:read','audit:read','task:read','task:review','metrics:read')
ON DUPLICATE KEY UPDATE `role_id` = VALUES(`role_id`);

-- 只读用户
INSERT INTO `role_permission` (`id`, `role_id`, `permission_id`)
SELECT 340000 + p.`id`, 2005, p.`id` FROM `permission` p
WHERE p.`code` IN ('project:read','audit:read','task:read','audit_log:read','metrics:read')
ON DUPLICATE KEY UPDATE `role_id` = VALUES(`role_id`);

-- 默认项目（演示用） -----------------------------------------------------------
INSERT INTO `project` (`id`, `name`, `code`, `env`, `status`, `owner_id`, `retain_days`, `description`, `created_by`)
VALUES (4001, '演示项目', 'demo', 'dev', 'ACTIVE', 1, 30, '内置演示项目，包含文本审核定义', 1)
ON DUPLICATE KEY UPDATE `name` = VALUES(`name`);

INSERT INTO `resource_quota` (`id`, `project_id`, `max_concurrency`, `max_qps`, `max_mysql_pool`, `max_redis_conn`, `max_media_size_mb`, `max_api_call_per_task`)
VALUES (4101, 4001, 20, 50, 10, 10, 50, 10)
ON DUPLICATE KEY UPDATE `max_concurrency` = VALUES(`max_concurrency`);

-- 演示审核定义：文本 + 规则 + 三条路线 ---------------------------------------
INSERT INTO `audit_definition`
  (`id`, `project_id`, `name`, `code`, `media_types`, `status`, `concurrency`, `timeout_ms`,
   `retry_policy`, `dedupe_window_sec`, `media_hash_in_key`, `config_json`, `description`, `created_by`)
VALUES (
  4201, 4001, '社区文本审核', 'demo_text',
  JSON_ARRAY('text'), 'ACTIVE', 5, 30000,
  JSON_OBJECT('max_attempts', 3, 'backoff', 'exponential', 'base_ms', 500),
  86400, 1,
  JSON_OBJECT(
    'default_result', 'REVIEW',
    'on_model_fail', 'REVIEW',
    'media_review', JSON_OBJECT(
      'text', JSON_OBJECT('api_ref', '', 'enable_keyword', TRUE, 'keyword_groups', JSON_ARRAY('违禁'))
    ),
    'rules', JSON_ARRAY(
      JSON_OBJECT('id', 4301, 'name', '命中高危词直接驳回', 'priority', 10, 'logic', 'OR',
        'stop_on_hit', TRUE, 'on_hit_result', 'REJECT', 'status', 'ACTIVE',
        'items', JSON_ARRAY(
          JSON_OBJECT('field', 'media.text', 'operator', 'contains_any',
            'value', JSON_ARRAY('违禁词A', '违禁词B'), 'case_sensitive', FALSE, 'negate', FALSE)
        )),
      JSON_OBJECT('id', 4302, 'name', '低风险快速通过', 'priority', 20, 'logic', 'AND',
        'stop_on_hit', TRUE, 'on_hit_result', 'PASS', 'status', 'ACTIVE',
        'items', JSON_ARRAY(
          JSON_OBJECT('field', 'media.text_len', 'operator', 'lte', 'value', 200,
            'case_sensitive', FALSE, 'negate', FALSE)
        ))
    )
  ),
  '演示用文本审核：命中高危词驳回，短文本通过，其余转待议', 1
)
ON DUPLICATE KEY UPDATE `name` = VALUES(`name`);

INSERT INTO `audit_rule` (`id`, `project_id`, `audit_id`, `name`, `priority`, `logic`, `stop_on_hit`, `on_hit_result`, `status`) VALUES
  (4301, 4001, 4201, '命中高危词直接驳回', 10, 'OR', 1, 'REJECT', 'ACTIVE'),
  (4302, 4001, 4201, '低风险快速通过',   20, 'AND', 1, 'PASS',   'ACTIVE')
ON DUPLICATE KEY UPDATE `name` = VALUES(`name`);

INSERT INTO `rule_item` (`id`, `rule_id`, `field`, `operator`, `value_json`, `case_sensitive`, `negate`, `sort_order`) VALUES
  (4401, 4301, 'media.text',     'contains_any', JSON_ARRAY('违禁词A', '违禁词B'), 0, 0, 0),
  (4402, 4302, 'media.text_len', 'lte',         CAST(200 AS JSON), 0, 0, 0)
ON DUPLICATE KEY UPDATE `field` = VALUES(`field`);

INSERT INTO `result_route` (`id`, `project_id`, `audit_id`, `result_type`, `exec_mode`, `on_error`, `actions_json`, `status`) VALUES
  (4501, 4001, 4201, 'PASS',   'sequential', 'to_review', JSON_ARRAY(), 'ACTIVE'),
  (4502, 4001, 4201, 'REJECT', 'sequential', 'to_review', JSON_ARRAY(
      JSON_OBJECT('id', 'a1', 'type', 'webhook', 'name', '回调业务方',
        'url', 'https://biz.example.com/cb',
        'body', JSON_OBJECT('task_id', '{{task.id}}', 'result', '{{task.result}}'),
        'retry', JSON_OBJECT('max_attempts', 3))), 'ACTIVE'),
  (4503, 4001, 4201, 'REVIEW', 'sequential', 'to_review', JSON_ARRAY(), 'ACTIVE')
ON DUPLICATE KEY UPDATE `actions_json` = VALUES(`actions_json`);

INSERT INTO `trigger_source` (`id`, `project_id`, `audit_id`, `type`, `name`, `config_json`, `priority`, `status`) VALUES
  (4601, 4001, 4201, 'REDIS',  'main-queue', JSON_OBJECT('stream', 'demo_text', 'group', 'cg_demo_text', 'batch_size', 16, 'visibility_timeout_ms', 60000), 10, 'ACTIVE'),
  (4602, 4001, 4201, 'OPENAPI', 'sync-api',   JSON_OBJECT('sync_wait_ms', 3000, 'require_biz_key', TRUE),                                    40, 'ACTIVE')
ON DUPLICATE KEY UPDATE `config_json` = VALUES(`config_json`);
