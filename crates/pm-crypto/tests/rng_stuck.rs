//! 单独的测试进程：注入"卡死"随机源，验证 RNG fail-closed。
use std::sync::atomic::Ordering;

use pm_crypto::rng;

#[test]
fn stuck_source_fails_closed() {
    rng::reset_for_test();
    rng::startup_health_test().unwrap();
    let mut a = vec![0u8; 100_000];
    rng::fill(&mut a).unwrap();
    rng::STUCK_SOURCE_FOR_TEST.store(true, Ordering::SeqCst);
    let mut b = [0u8; 32];
    let r1 = rng::fill(&mut b);
    let r2 = rng::fill(&mut b);
    assert!(r1.is_err() || r2.is_err(), "stuck source must be detected");
    rng::STUCK_SOURCE_FOR_TEST.store(false, Ordering::SeqCst);
    assert!(rng::fill(&mut b).is_err(), "must stay failed (fail-closed)");
    assert!(rng::is_failed());
    rng::reset_for_test();
    rng::fill(&mut b).unwrap();
}
