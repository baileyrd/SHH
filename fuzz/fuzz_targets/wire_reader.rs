#![no_main]
//! Fuzz the bounds-checked wire cursor. Every primitive read must fail
//! gracefully (return `Err`) on truncated or garbage input — never panic,
//! never read out of bounds. See `src/wire/reader.rs`.

use libfuzzer_sys::fuzz_target;
use shh::wire::Reader;

fuzz_target!(|data: &[u8]| {
    if data.is_empty() {
        return;
    }
    // First byte seeds an opcode program; the rest is the buffer to parse.
    let (program, buf) = data.split_at(1);
    let mut r = Reader::new(buf);
    let mut op = program[0];
    // Drive a mixed sequence of primitive reads, cycling until the reader
    // errors or is exhausted. A panic on any path is the bug we hunt for.
    for _ in 0..128 {
        let step = match op % 8 {
            0 => r.byte().map(|_| ()),
            1 => r.boolean().map(|_| ()),
            2 => r.u32().map(|_| ()),
            3 => r.u64().map(|_| ()),
            4 => r.string().map(|_| ()),
            5 => r.utf8().map(|_| ()),
            6 => r.name_list().map(|_| ()),
            _ => {
                let _ = r.rest();
                Ok(())
            }
        };
        if step.is_err() || r.remaining() == 0 {
            break;
        }
        op = op.wrapping_mul(31).wrapping_add(7);
    }
    let _ = r.finish();
});
