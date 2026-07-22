#![no_main]
#![forbid(unsafe_code)]

use libfuzzer_sys::fuzz_target;
use unpackio::{CancellationToken, CompressedStream, Limits, StreamFormat, WorkBudget};

const MAXIMUM_FUZZ_INPUT: usize = 256 * 1024;
const MAXIMUM_GENERATED_PAYLOAD: usize = 255;

fn limits() -> Limits {
    Limits::builder()
        .max_stream_frames(64)
        .max_dictionary_bytes(25 * 1024 * 1024)
        .max_entry_output_bytes(1024 * 1024)
        .max_total_output_bytes(1024 * 1024)
        .max_total_input_bytes(512 * 1024)
        .build()
}

fn exercise(bytes: Vec<u8>, format: Option<StreamFormat>) {
    let cancellation = CancellationToken::new();
    let mut budget = WorkBudget::bounded(8 * 1024 * 1024);
    let opened = match format {
        Some(format) => {
            CompressedStream::open_bytes_as(bytes, format, limits(), &cancellation, &mut budget)
        }
        None => CompressedStream::open_bytes(bytes, limits(), &cancellation, &mut budget),
    };
    if let Ok(stream) = opened {
        let _ = stream.verify(&cancellation, &mut budget);
    }
}

fn exercise_generated(bytes: Vec<u8>, format: StreamFormat, expected: &[u8]) {
    let cancellation = CancellationToken::new();
    let mut budget = WorkBudget::bounded(8 * 1024 * 1024);
    let opened =
        CompressedStream::open_bytes_as(bytes, format, limits(), &cancellation, &mut budget);
    let Ok(stream) = opened else {
        panic!("in-process generated {format} stream was rejected");
    };
    let decoded = stream.decompress(&cancellation, &mut budget);
    let Ok(decoded) = decoded else {
        panic!("in-process generated {format} stream failed to decode");
    };
    assert_eq!(decoded, expected);
}

fn raw_lz4_frame(payload: &[u8]) -> Option<Vec<u8>> {
    let length = u32::try_from(payload.len()).ok()?;
    let mut frame = Vec::new();
    // Version 1, independent 64 KiB blocks. The descriptor checksum for
    // [0x60, 0x40] is 0x82.
    frame.extend_from_slice(&[0x04, 0x22, 0x4d, 0x18, 0x60, 0x40, 0x82]);
    if length != 0 {
        let block_header = length.checked_add(1_u32.checked_shl(31)?)?;
        frame.extend_from_slice(&block_header.to_le_bytes());
        frame.extend_from_slice(payload);
    }
    frame.extend_from_slice(&0_u32.to_le_bytes());
    Some(frame)
}

fn raw_zstandard_frame(payload: &[u8]) -> Option<Vec<u8>> {
    let length = u8::try_from(payload.len()).ok()?;
    let block_header = u32::from(length).checked_shl(3)?.checked_add(1)?;
    let serialized = block_header.to_le_bytes();
    let mut frame = Vec::new();
    frame.extend_from_slice(&[0x28, 0xb5, 0x2f, 0xfd, 0x20, length]);
    frame.extend_from_slice(serialized.get(..3)?);
    frame.extend_from_slice(payload);
    Some(frame)
}

fn unix_compress_stream(payload: &[u8]) -> Vec<u8> {
    let mut stream = Vec::new();
    stream.extend_from_slice(&[0x1f, 0x9d, 0x90]);
    stream.extend_from_slice(payload);
    stream
}

fuzz_target!(|data: &[u8]| {
    let arbitrary_end = data.len().min(MAXIMUM_FUZZ_INPUT);
    let arbitrary = match data.get(..arbitrary_end) {
        Some(bytes) => bytes,
        None => &[],
    };
    exercise(arbitrary.to_vec(), None);
    for format in [
        StreamFormat::Lz4,
        StreamFormat::Zstandard,
        StreamFormat::UnixCompress,
    ] {
        exercise(arbitrary.to_vec(), Some(format));
    }

    let payload_end = data.len().min(MAXIMUM_GENERATED_PAYLOAD);
    let payload = match data.get(..payload_end) {
        Some(bytes) => bytes,
        None => &[],
    };
    if let Some(frame) = raw_lz4_frame(payload) {
        exercise_generated(frame, StreamFormat::Lz4, payload);
    }
    if let Some(frame) = raw_zstandard_frame(payload) {
        exercise_generated(frame, StreamFormat::Zstandard, payload);
    }
    exercise(
        unix_compress_stream(arbitrary),
        Some(StreamFormat::UnixCompress),
    );
});
