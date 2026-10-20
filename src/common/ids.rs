//! 雪花 ID 生成器：毫秒时间 + 节点 ID + 序列号，进程内单调递增。
//!
//! 与 `backend_73info` 的 ID 口径一致：64 位正整数，落库用 `bigint unsigned`。

use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

/// 自定义纪元：2024-01-01T00:00:00Z，单位毫秒。
const EPOCH_MS: i64 = 1_704_067_200_000;
const NODE_BITS: u32 = 10;
const SEQUENCE_BITS: u32 = 12;

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
    /// `node_id` 取 0~1023；同一进程内重复不影响正确性。
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
}
