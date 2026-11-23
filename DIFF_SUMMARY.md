# Diff Summary — `xray-lite-rs` (`v1.0.0`, Fix Game Online Xray-core: Mux.Cool & XUDP Full Cone)

Ringkasan perubahan pada `xray-lite-rs` untuk menambahkan dukungan penuh **XUDP / Mux.Cool (`CMD_MUX = 0x03`)** pada VLESS dan VMess agar aplikasi berbasis Xray-core (NetMod, v2rayNG, dll.) dapat menjalankan game online & voice chat UDP dengan normal (versi `Cargo.toml` tetap `1.0.0`, **0 dependency baru**).

## Akar Masalah
- Client Xray-core (`cone = true` secara default) membungkus seluruh trafik UDP non-53/443 (port game online) ke **XUDP (`CMD_MUX = 0x03`, `v1.mux.cool:666`)**, di mana header VLESS/VMess tidak menyertakan field alamat tujuan.
- Sebelumnya `xray-lite-rs` hanya menangani `CMD_TCP (0x01)` dan `CMD_UDP (0x02)` (yang dipakai default sing-box/NekoBox), sehingga trafik game dari NetMod langsung ditolak.

## Ringkasan File yang Berubah

| File | Status | Ringkasan Perubahan |
|---|---|---|
| `src/protocol/mux.rs` | **Baru** | Implementasi Xray Mux.Cool + XUDP (`FrameMetadata` encoder/decoder, `SessionStatus` `New`/`Keep`/`End`/`KeepAlive`, Full Cone NAT UDP per `SessionID` dengan alamat sumber pada setiap frame balasan, dukungan sub-sesi TCP Mux, batas 128 sesi, integrasi `StatsRegistry` & `AccessLogger`, + 2 unit test). |
| `src/protocol/mod.rs` | Diubah | Mendaftarkan `pub mod mux;`. |
| `src/protocol/vless.rs` | Diubah | Menambah `CMD_MUX = 0x03`, melewati pembacaan `target` address saat `cmd == 0x03`, mengirim `[0x00, 0x00]`, dan meneruskan ke `mux::handle_mux()`. |
| `src/protocol/vmess.rs` | Diubah | Menambah `CMD_MUX = 0x03`, melewati pembacaan `target` address di `parse_vmess_request_header()` saat `cmd == 0x03`, dan menjembatani `ChunkCodec` ke `mux::handle_mux()`. |
| `tests/integration_test.rs` | Diubah | Menambah integration test end-to-end `vless_xudp_mux_udp_echo` (VLESS `CMD_MUX = 0x03` + frame XUDP + `GlobalID` 8 byte + verifikasi Full Cone response frame). |
