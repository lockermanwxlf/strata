//! Run against real services when present: a TPM (or `STRATA_TPM_TCTI`, e.g. a
//! software TPM) and a Secret Service daemon. Skipped where neither is reachable;
//! `core/tools/linux-protectors.sh` sets both up in WSL or CI.

use std::pin::pin;
use std::task::{Context as TaskContext, Poll, Waker};

use super::*;

/// The protectors finish their work before returning; nothing ever waits.
fn ready<F: std::future::Future>(f: F) -> F::Output {
    match pin!(f)
        .as_mut()
        .poll(&mut TaskContext::from_waker(Waker::noop()))
    {
        Poll::Ready(v) => v,
        Poll::Pending => panic!("the protector waited"),
    }
}

const SLOT: &str = "00112233445566778899aabbccddeeff";

#[test]
fn tpm_seals_to_the_pin() {
    if !Tpm::available() {
        eprintln!("no TPM: skipped");
        return;
    }
    let tpm = Tpm::with_pin(b"1234").unwrap();
    let secret = vec![7u8; 32];
    let blob = ready(tpm.wrap(SLOT.into(), secret.clone())).unwrap();
    assert_eq!(
        ready(tpm.unwrap(SLOT.into(), blob.clone())).unwrap(),
        secret
    );

    let wrong = Tpm::with_pin(b"4321").unwrap();
    assert!(matches!(
        ready(wrong.unwrap(SLOT.into(), blob.clone())),
        Err(ProtectorError::WrongPin)
    ));

    let mut mangled = blob;
    mangled.truncate(10);
    assert!(matches!(
        ready(tpm.unwrap(SLOT.into(), mangled)),
        Err(ProtectorError::KeyInvalidated)
    ));
}

#[test]
fn secret_service_wraps_per_slot() {
    let Some(keyring) = SecretService::new() else {
        eprintln!("no Secret Service: skipped");
        return;
    };
    let secret = vec![9u8; 32];
    let blob = ready(keyring.wrap(SLOT.into(), secret.clone())).unwrap();
    assert_eq!(
        ready(keyring.unwrap(SLOT.into(), blob.clone())).unwrap(),
        secret
    );
    // The slot ID is bound in: another slot's blob doesn't open as this one.
    assert!(matches!(
        ready(keyring.unwrap("ffeeddccbbaa99887766554433221100".into(), blob)),
        Err(ProtectorError::KeyInvalidated)
    ));
}
