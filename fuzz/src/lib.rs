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
