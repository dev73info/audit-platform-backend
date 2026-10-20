//! 业务枚举：与 `doc/API.md` 的枚举表一一对应。

use serde::{Deserialize, Serialize};

macro_rules! string_enum {
    (
        $(#[$meta:meta])*
        $name:ident { $( $variant:ident => $text:literal ),+ $(,)? }
    ) => {
        $(#[$meta])*
        #[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
        pub enum $name {
            $( #[serde(rename = $text)] $variant ),+
        }

        impl $name {
            /// 枚举的字面量。
            pub fn as_str(&self) -> &'static str {
                match self { $( $name::$variant => $text ),+ }
            }

            /// 从字面量解析，非法值返回 None。
            pub fn parse(raw: &str) -> Option<Self> {
                match raw.trim().to_ascii_uppercase().as_str() {
                    $( $text => Some($name::$variant), )+
                    _ => None,
                }
            }

            /// 全部取值。
            pub fn all() -> &'static [$name] {
                &[ $( $name::$variant ),+ ]
            }
        }

        impl std::fmt::Display for $name {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                f.write_str(self.as_str())
            }
        }
    };
}

string_enum! {
    /// 项目状态。
    ProjectStatus {
        Active => "ACTIVE",
        Paused => "PAUSED",
        Disabled => "DISABLED",
        Deleted => "DELETED",
    }
}

string_enum! {
    /// 项目环境。
    ProjectEnv {
        Dev => "dev",
        Test => "test",
        Staging => "staging",
        Prod => "prod",
    }
}

string_enum! {
    /// 审核定义状态。
    AuditStatus {
        Draft => "DRAFT",
        Active => "ACTIVE",
        Paused => "PAUSED",
        Deleted => "DELETED",
    }
}

string_enum! {
    /// 触发源类型。
    TriggerType {
        Redis => "REDIS",
        Polling => "POLLING",
        Websocket => "WEBSOCKET",
        Openapi => "OPENAPI",
    }
}

string_enum! {
    /// 任务流程状态。
    TaskStatus {
        Received => "RECEIVED",
        Locked => "LOCKED",
        Queued => "QUEUED",
        WaitingQuota => "WAITING_QUOTA",
        Processing => "PROCESSING",
        RuleEvaluating => "RULE_EVALUATING",
        MediaReviewing => "MEDIA_REVIEWING",
        Routing => "ROUTING",
        ReviewPending => "REVIEW_PENDING",
        Success => "SUCCESS",
        Failed => "FAILED",
        Duplicated => "DUPLICATED",
        DeadLetter => "DEAD_LETTER",
    }
}

string_enum! {
    /// 审核结论。
    TaskResult {
        Pass => "PASS",
        Reject => "REJECT",
        Review => "REVIEW",
        Unknown => "UNKNOWN",
    }
}

string_enum! {
    /// 去重标记。
    DedupeFlag {
        Normal => "NORMAL",
        Duplicated => "DUPLICATED",
        NoDedupe => "NO_DEDUPE",
    }
}

string_enum! {
    /// 动作类型。
    ActionType {
        Http => "HTTP",
        Redis => "REDIS",
        Mysql => "MYSQL",
        Webhook => "WEBHOOK",
        Mq => "MQ",
    }
}

string_enum! {
    /// 项目连接配置类型。
    ConfigType {
        Redis => "REDIS",
        Mysql => "MYSQL",
        Api => "API",
        Oss => "OSS",
        Mq => "MQ",
    }
}

string_enum! {
    /// 动作执行方式。
    ExecMode {
        Sequential => "sequential",
        Parallel => "parallel",
    }
}

string_enum! {
    /// 动作失败策略。
    OnError {
        Continue => "continue",
        Abort => "abort",
        ToReview => "to_review",
    }
}

string_enum! {
    /// 角色编码。
    RoleCode {
        SuperAdmin => "SUPER_ADMIN",
        ProjectAdmin => "PROJECT_ADMIN",
        AuditConfigurer => "AUDIT_CONFIGURER",
        Reviewer => "REVIEWER",
        Readonly => "READONLY",
    }
}

string_enum! {
    /// 回收站对象类型。
    ObjectType {
        Project => "PROJECT",
        Audit => "AUDIT",
    }
}

string_enum! {
    /// 规则逻辑。
    RuleLogic {
        And => "AND",
        Or => "OR",
    }
}

impl TaskStatus {
    /// 是否终态（不会再自动流转）。
    pub fn is_terminal(&self) -> bool {
        matches!(
            self,
            TaskStatus::Success
                | TaskStatus::Failed
                | TaskStatus::Duplicated
                | TaskStatus::DeadLetter
        )
    }

    /// 是否属于「运行中」——项目删除前要检查这一类任务。
    pub fn is_running(&self) -> bool {
        matches!(
            self,
            TaskStatus::Queued
                | TaskStatus::WaitingQuota
                | TaskStatus::Processing
                | TaskStatus::RuleEvaluating
                | TaskStatus::MediaReviewing
                | TaskStatus::Routing
                | TaskStatus::ReviewPending
        )
    }
}

impl TaskResult {
    /// 结论的严重程度：REJECT 最严，REVIEW 次之，PASS 最宽。
    pub fn severity(&self) -> u8 {
        match self {
            TaskResult::Pass => 0,
            TaskResult::Review => 1,
            TaskResult::Reject => 2,
            TaskResult::Unknown => 1,
        }
    }

    /// 取更严的结论。
    pub fn stricter(self, other: TaskResult) -> TaskResult {
        if other.severity() > self.severity() {
            other
        } else {
            self
        }
    }
}
