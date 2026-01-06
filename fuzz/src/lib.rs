use rayhunter::{
    analysis::analyzer::{AnalyzerConfig, Harness},
    diag::DataType,
    qmdl::QmdlReader,
};
use std::io::Cursor;
use std::future::Future;
use std::task::{Context, Poll, RawWaker, RawWakerVTable, Waker};
use deku::DekuContainerWrite;

// Since we're using Cursor which never blocks, create a no-op waker
fn noop_raw_waker() -> RawWaker {
    fn noop(_: *const ()) {}
    fn clone(_: *const ()) -> RawWaker {
        noop_raw_waker()
    }

    static VTABLE: RawWakerVTable = RawWakerVTable::new(clone, noop, noop, noop);
    RawWaker::new(std::ptr::null(), &VTABLE)
}

/// Process data through QMDL parser and all default analyzers
pub fn fuzz_qmdl(data: &[u8]) {
    // Limit input size to 50 MB
    const MAX_SIZE: usize = 50 * 1024 * 1024;
    if data.len() > MAX_SIZE {
        return;
    }

    let waker = unsafe { Waker::from_raw(noop_raw_waker()) };
    let mut context = Context::from_waker(&waker);

    let mut future = Box::pin(async {
        let mut harness = Harness::new_with_config(&AnalyzerConfig::default());

        // Parse as QMDL
        let cursor = Cursor::new(data);
        let mut qmdl_reader = QmdlReader::new(cursor, Some(data.len()));

        while let Ok(Some(container)) = qmdl_reader.get_next_messages_container().await {
            // Filter to UserSpace data type (same as rayhunter-check does)
            if container.data_type == DataType::UserSpace {
                // Run all default analyzers against the QMDL messages
                for row in harness.analyze_qmdl_messages(container) {
                    // Process the analysis row to ensure all analyzers run
                    // This exercises all the analyzer code paths
                    let _events = row.events;
                    let _timestamp = row.packet_timestamp;
                    let _reason = row.skipped_message_reason;
                }
            }
        }
    });

    // Poll to completion - should always be Ready since Cursor never blocks
    loop {
        match future.as_mut().poll(&mut context) {
            Poll::Ready(_) => break,
            Poll::Pending => {
                // This should never happen with Cursor, but if it does, panic
                panic!("Future unexpectedly returned Pending with Cursor-based I/O");
            }
        }
    }
}

/// Split QMDL data into individual messages and call callback for each
pub fn fuzz_qmdl_split<F>(data: &[u8], mut callback: F)
where
    F: FnMut(&[u8]),
{
    let waker = unsafe { Waker::from_raw(noop_raw_waker()) };
    let mut context = Context::from_waker(&waker);

    let mut future = Box::pin(async {
        // Parse as QMDL
        let cursor = Cursor::new(data);
        let mut qmdl_reader = QmdlReader::new(cursor, Some(data.len()));

        while let Ok(Some(container)) = qmdl_reader.get_next_messages_container().await {
            // Filter to UserSpace data type (same as rayhunter-check does)
            if container.data_type == DataType::UserSpace {
                // Extract each individual message
                for message in container.messages {
                    if let Ok(bytes) = message.to_bytes() {
                        callback(&bytes);
                    }
                }
            }
        }
    });

    // Poll to completion
    loop {
        match future.as_mut().poll(&mut context) {
            Poll::Ready(_) => break,
            Poll::Pending => {
                panic!("Future unexpectedly returned Pending with Cursor-based I/O");
            }
        }
    }
}

/// Compare two Message results semantically (ignoring structural differences from deku upgrade)
fn messages_equal(
    new: &rayhunter::diag::Message,
    old: &rayhunter_old::diag::Message,
) -> bool {
    use rayhunter::diag::Message as New;
    use rayhunter_old::diag::Message as Old;

    match (new, old) {
        (
            New::Log {
                pending_msgs: pm_new,
                outer_length: ol_new,
                inner_length: il_new,
                log_type: lt_new,
                timestamp: ts_new,
                body: body_new,
            },
            Old::Log {
                pending_msgs: pm_old,
                outer_length: ol_old,
                inner_length: il_old,
                log_type: lt_old,
                timestamp: ts_old,
                body: body_old,
            },
        ) => {
            pm_new == pm_old
                && ol_new == ol_old
                && il_new == il_old
                && lt_new == lt_old
                && ts_new.ts == ts_old.ts
                && log_bodies_equal(body_new, body_old)
        }
        (
            New::Response {
                opcode1,
                opcode2,
                opcode3,
                opcode4,
                subopcode: sub_new,
                status: st_new,
                payload: pay_new,
            },
            Old::Response {
                opcode: op_old,
                subopcode: sub_old,
                status: st_old,
                payload: pay_old,
            },
        ) => {
            u32::from_le_bytes([*opcode1, *opcode2, *opcode3, *opcode4]) == *op_old
                && sub_new == sub_old
                && st_new == st_old
                && format!("{:?}", pay_new) == format!("{:?}", pay_old)
        }
        _ => false,
    }
}

/// Compare LogBody variants semantically
fn log_bodies_equal(
    new: &rayhunter::diag::LogBody,
    old: &rayhunter_old::diag::LogBody,
) -> bool {
    use rayhunter::diag::LogBody as New;
    use rayhunter_old::diag::LogBody as Old;

    match (new, old) {
        (
            New::Nas4GMessage {
                log_type: _,
                direction: dir_new,
                ext_header_version: ehv_new,
                rrc_rel: rr_new,
                rrc_version_minor: rvm_new,
                rrc_version_major: rvmaj_new,
                msg: msg_new,
            },
            Old::Nas4GMessage {
                direction: dir_old,
                ext_header_version: ehv_old,
                rrc_rel: rr_old,
                rrc_version_minor: rvm_old,
                rrc_version_major: rvmaj_old,
                msg: msg_old,
            },
        ) => {
            format!("{:?}", dir_new) == format!("{:?}", dir_old)
                && ehv_new == ehv_old
                && rr_new == rr_old
                && rvm_new == rvm_old
                && rvmaj_new == rvmaj_old
                && msg_new == msg_old
        }
        _ => format!("{:?}", new) == format!("{:?}", old),
    }
}

/// Differential fuzzing: compare old and new parser outputs
pub fn fuzz_differential(data: &[u8]) {
    use deku::DekuContainerRead as DekuNew;
    use deku_old::DekuContainerRead as DekuOld;

    let result_new = <rayhunter::diag::Message as DekuNew>::from_bytes((data, 0));
    let result_old = <rayhunter_old::diag::Message as DekuOld>::from_bytes((data, 0));

    match (result_new, result_old) {
        (Ok(((rest_new, _), msg_new)), Ok(((rest_old, _), msg_old))) => {
            if rest_new.len() != rest_old.len() {
                panic!(
                    "Different remaining bytes!\nInput: {:02x?}\nNew: {} bytes\nOld: {} bytes",
                    data,
                    rest_new.len(),
                    rest_old.len()
                );
            }
            if !messages_equal(&msg_new, &msg_old) {
                panic!(
                    "Messages differ!\nInput: {:02x?}\nNew: {:?}\nOld: {:?}",
                    data, msg_new, msg_old
                );
            }
        }
        (Ok(_), Err(e_old)) => {
            panic!(
                "New parser succeeded but old failed!\nInput: {:02x?}\nOld error: {:?}",
                data, e_old
            );
        }
        (Err(e_new), Ok(_)) => {
            panic!(
                "Old parser succeeded but new failed!\nInput: {:02x?}\nNew error: {:?}",
                data, e_new
            );
        }
        (Err(_e_new), Err(_e_old)) => {
            // Both parsers failed - this is acceptable.
            // Error message formatting may differ between deku versions,
            // so we don't compare the exact error strings.
        }
    }
}
