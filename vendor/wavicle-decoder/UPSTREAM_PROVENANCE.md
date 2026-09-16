# Provenance

Which wavicle module derives from which reference source. Updated whenever a
port lands; see `ATTRIBUTION.md` for the license notices.

All ports are from **dbry/WavPack at tag 5.9.0** (the same version pinned as
the conformance oracle), read from copies kept outside this repo.

| Module | Derived from | Notes |
|---|---|---|
| `format` | `include/wavpack.h`, `src/wavpack_local.h` | constants only |
| `block`, `metadata` | header struct, `read_next_header` bounds, sub-block framing | M0 |
| `bitstream` | `wavpack_local.h` getbit/getbits macros, `open_utils.c` bs_open_read, `read_words.c` read_code and the unary/escape reads | M1; portable variant, not the CTZ/NEXT8 optimizations |
| `entropy` | `read_words.c` get_words_lossless, `entropy_utils.c` wp_exp2s + exp2 table, median macros in `wavpack_local.h` | M1; lossless path only |
| `decorr` | `decorr_utils.c` read_decorr_* + restore_weight, `unpack.c` decorr_mono_pass/decorr_stereo_pass, weight macros in `wavpack_local.h` | M1; inverse only |
| `float` | `unpack_floats.c` float_values + float_values_nowvx, f32 accessor macros in `wavpack_local.h`, `open_utils.c` read_float_info + the wvx new-format float prefix | M3; decode only |
| `decode` driver | `unpack.c` unpack_samples (shape, joint stereo, CRC, fixup lossless path incl. INT32_DATA and FLOAT_DATA), `open_utils.c` init_wvx_bitstream + read_int32_info | M1+M2+M3; hard-errors where the reference mutes |

| `bitstream` (writer) | `wavpack_local.h` putbit/putbits macros, `pack.c` bs_close_write | M4 |
| `entropy` (encoder) | `write_words.c` send_words_lossless + flush_word, `write_words.c` write_entropy_vars | M4; lossless path only |
| `decorr` (forward) | `pack.c` decorr_mono_buffer + decorr_stereo_pass (forward), inverse of the decode passes | M4; positive terms only |
| `float` (encode) | `pack_floats.c` scan_float_data + send_float_data | M5; the encode mirror of float_values |
| `encode` driver | `pack.c` pack_samples (block assembly order, CRC over originals, metadata framing, the wvx sub-block with its crc prefix) | M4+M5; single block, fixed one-term config |

The codec is round-trip complete for the tiny profile. No further reference
modules are required for it; remaining work (multi-block encode, decorrelation
tuning) builds on the ports already listed.

Deliberately NOT ported: `decorr_tables.h` (the encoder ships one fixed
decorrelation configuration instead of the reference's table-driven search),
`unpack3.c` (pre-4.0 legacy), DSD and hybrid sources, and all hand-written
assembly (scalar Rust only).
