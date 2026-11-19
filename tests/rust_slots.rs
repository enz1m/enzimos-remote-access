// SPDX-License-Identifier: MIT
use enzimos_remote_access::slots::Slots;
use std::{
    sync::{Arc, Barrier},
    time::Duration,
};
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn abandoned_blocking_job_retains_its_slot_and_notifies_on_final_retirement() {
    let slots = Slots::new();
    let mut permits = (0..8).map(|_| slots.acquire().unwrap()).collect::<Vec<_>>();
    assert!(slots.acquire().is_err());
    let retained = permits.pop().unwrap();
    let gate = Arc::new(Barrier::new(2));
    let worker_gate = gate.clone();
    let (entered, ready) = tokio::sync::oneshot::channel();
    let job = tokio::task::spawn_blocking(move || {
        entered.send(()).unwrap();
        worker_gate.wait();
        drop(retained);
    });
    ready.await.unwrap();
    drop(job); // Caller retirement cannot abandon the blocking job's request bound.
    assert!(slots.acquire().is_err());
    drop(permits);
    assert!(!slots.idle());
    let remaining = (0..7).map(|_| slots.acquire().unwrap()).collect::<Vec<_>>();
    assert!(slots.acquire().is_err());
    drop(remaining);
    let waiter_slots = slots.clone();
    let waiter = tokio::spawn(async move {
        waiter_slots.settled().await;
    });
    tokio::time::sleep(Duration::from_millis(30)).await;
    assert!(!waiter.is_finished());
    gate.wait();
    tokio::time::timeout(Duration::from_secs(2), waiter)
        .await
        .unwrap()
        .unwrap();
    assert!(slots.idle());
}
