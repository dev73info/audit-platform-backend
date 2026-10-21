//! 雪花 ID 生成器：毫秒时间 + 节点 ID + 序列号，进程内单调递增。
//!
//! 落库用 `bigint unsigned`。**位布局必须守住 2^53**：
//! JavaScript 的 `Number.MAX_SAFE_INTEGER` 是 9007199254740991，超过它 JSON 里的
//! 数字解析就会丢精度——前端拿到的 ID 和库里对不上，接口直接 404。
//! 所以时间戳 41 位 + 节点与序列共 12 位 = 53 位，
//! 算下来 41 位毫秒够用到 2093 年。
//!
//! 取舍：节点 4 位（最多 16 个节点）、每毫秒 256 个序列。
//! 这套系统是「一套后台 + 一个 Worker 池」的单体部署，够用。

use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

/// 自定义纪元：2024-01-01T00:00:00Z，单位毫秒。
const EPOCH_MS: i64 = 1_704_067_200_000;
/// 节点 ID 位数：4 位 = 16 个节点。
const NODE_BITS: u32 = 4;
/// 序列号位数：8 位 = 每毫秒 256 个。
const SEQUENCE_BITS: u32 = 8;

#[derive(Debug)]
pub struct IdGenerator {
    node_id: u64,
    state: Mutex<State>,
}

#[derive(Debug, Default)]
struct State {
    last_ms: i64,
    sequence: u64,
}

impl IdGenerator {
    /// `node_id` 取 0~15；同一进程内重复不影响正确性。
    pub fn new(node_id: u64) -> Self {
        Self {
            node_id: node_id & ((1 << NODE_BITS) - 1),
            state: Mutex::new(State::default()),
        }
    }

    /// 从环境变量 `AUDIT_NODE_ID` 读取节点 ID，缺省 1。
    pub fn from_env() -> Self {
        let node_id = std::env::var("AUDIT_NODE_ID")
            .ok()
            .and_then(|v| v.parse::<u64>().ok())
            .unwrap_or(1);
        Self::new(node_id)
    }

    /// 生成下一个 ID。
    pub fn next_id(&self) -> u64 {
        let mut state = match self.state.lock() {
            Ok(guard) => guard,
            Err(poisoned) => poisoned.into_inner(),
        };

        let now = current_millis();
        if now == state.last_ms {
            state.sequence = (state.sequence + 1) & ((1 << SEQUENCE_BITS) - 1);
            if state.sequence == 0 {
                // 同一毫秒内序列号用尽，等下一毫秒
                let mut waited = current_millis();
                while waited <= state.last_ms {
                    waited = current_millis();
                    std::hint::spin_loop();
                }
                state.last_ms = waited;
            }
        } else {
            state.last_ms = now;
            state.sequence = 0;
        }

        let elapsed = (state.last_ms - EPOCH_MS).max(0) as u64;
        (elapsed << (NODE_BITS + SEQUENCE_BITS)) | (self.node_id << SEQUENCE_BITS) | state.sequence
    }
}

fn current_millis() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0)
}

/// 进程级默认生成器。
pub fn next_id() -> u64 {
    use std::sync::OnceLock;
    static GENERATOR: OnceLock<IdGenerator> = OnceLock::new();
    GENERATOR.get_or_init(IdGenerator::from_env).next_id()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ids_are_monotonic_and_unique() {
        let generator = IdGenerator::new(1);
        let mut previous = generator.next_id();
        for _ in 0..1000 {
            let current = generator.next_id();
            assert!(current > previous, "ID 必须单调递增");
            previous = current;
        }
    }

    #[test]
    fn different_nodes_produce_different_ids() {
        let a = IdGenerator::new(1);
        let b = IdGenerator::new(2);
        assert_ne!(a.next_id() >> SEQUENCE_BITS, b.next_id() >> SEQUENCE_BITS);
    }

    /// ID 必须落在 JavaScript 的安全整数范围内，否则前端 JSON 解析会丢精度。
    #[test]
    fn ids_fit_javascript_safe_integer() {
        const JS_MAX_SAFE_INTEGER: u64 = 9_007_199_254_740_991;
        let generator = IdGenerator::new(1);
        for _ in 0..1000 {
            let id = generator.next_id();
            assert!(
                id <= JS_MAX_SAFE_INTEGER,
                "ID {id} 超过 JavaScript 安全整数上限，前端会丢精度"
            );
        }
    }

    /// 位布局总共 53 位：41 位毫秒 + 4 位节点 + 8 位序列。
    #[test]
    fn bit_layout_stays_within_53_bits() {
        assert_eq!(NODE_BITS + SEQUENCE_BITS, 12);
    }
}
