# Diff Summary — `xray-lite-rs` (`v1.0.0`, Penambahan Transport XHTTP)

Ringkasan perubahan terbaru pada `xray-lite-rs` untuk menambahkan transport **XHTTP (SplitHTTP)** yang wire-compatible dengan `Xray-core-26.11.9` (versi `Cargo.toml` tetap `1.0.0`, **0 dependency baru**).

## Ringkasan File yang Berubah

| File | Status | Ringkasan Perubahan |
|---|---|---|
| `src/transport/xhttp.rs` | **Baru** | Implementasi penuh transport XHTTP (`XhttpHub`, auto-deteksi HTTP/2 `h2`/`h2c` & HTTP/1.1, mode `stream-one`, `stream-up`, `packet-up` + `stream-down`, min-heap reorder `seq`, reaper sesi yatim 30 detik, header `X-Padding`/`X-Accel-Buffering: no`/`text/event-stream`, ekstraksi `X-Forwarded-For`/`X-Real-IP`, + 2 unit test). |
| `src/transport/mod.rs` | Diubah | Mendaftarkan `pub mod xhttp;`. |
| `src/config.rs` | Diubah | Menambah struct `XhttpSettings`, field `xhttp_settings` (alias `splithttpSettings`) di `StreamSettings`, dukungan `accept_proxy_protocol()` serta validasi `"network": "xhttp" | "splithttp"`. |
| `src/lib.rs` | Diubah | Inisialisasi `Arc<XhttpHub>` per inbound XHTTP dan dispatch koneksi ke `serve_xhttp_connection()` lengkap dengan pengecekan `DynamicBlocklist`, `StatsRegistry`, dan `AccessLogger`. |
| `src/main.rs` | Diubah | Memperbarui banner `--version` menyertakan `XHTTP`. |
| `tests/integration_test.rs` | Diubah | Menambahkan integration test end-to-end `vless_over_xhttp_packet_up_and_stream_down`. |

## Detail Teknis XHTTP (`src/transport/xhttp.rs`)
- **Mode yang didukung**:
  - `stream-one` (`POST /path` atau `POST /path/`): full-duplex dalam 1 stream HTTP/2 atau HTTP/1.1.
  - `stream-up` + `stream-down` (`POST /path/<session>` + `GET /path/<session>`): uplink streaming terpisah dari downlink.
  - `packet-up` + `stream-down` (`POST /path/<session>/<seq>` + `GET /path/<session>`): unggahan per-paket dengan antrean min-heap terurut `0, 1, 2, ...` dan batas `scMaxBufferedPosts` (default `30`) serta `scMaxEachPostBytes` (default `1 MB`).
- **Auto-deteksi protokol HTTP**: Memeriksa 24-byte preface HTTP/2 (`PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n`); koneksi HTTP/2 dilayani via `h2::server` (mendukung multiplexing), sedangkan HTTP/1.1 dilayani dengan parser ringan yang mendukung `Transfer-Encoding: chunked` dan `keep-alive` di belakang Nginx `proxy_pass`.
- **Proteksi RAM 1-vCPU**: Buffer duplex `16 KB` per sesi dan pembersihan otomatis sesi yatim (`ORPHAN_SESSION_TTL = 30s`) jika `GET` downlink tidak pernah terhubung.
- **Test baru**:
  - Unit test: `extract_meta_handles_all_xhttp_modes`, `packet_up_reorders_out_of_order_sequences`.
  - Integration test: `vless_over_xhttp_packet_up_and_stream_down`.
