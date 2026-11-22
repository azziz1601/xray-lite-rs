use std::io;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use aes::cipher::BlockDecrypt;
use aes::Aes128;
use aes_gcm::aead::{Aead, KeyInit as AeadKeyInit, Payload};
use aes_gcm::{Aes128Gcm, Nonce};
use chacha20poly1305::ChaCha20Poly1305;
use md5::{Digest as Md5Digest, Md5};
use rand::RngCore;
use sha2::Sha256;
use sha3::digest::{ExtendableOutput, Update, XofReader};
use sha3::{Shake128, Shake128Reader};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::time::timeout;

use crate::address::{parse_vless_vmess_addr_slice, TargetAddr};
use crate::log_debug;
use crate::outbound::{bind_udp_for, dial_tcp, resolve_udp_target};
use crate::protocol::InboundRuntime;
use crate::transport::BoxedStream;

const KDF_SALT_VMESS_AEAD_KDF: &[u8] = b"VMess AEAD KDF";
const KDF_SALT_AUTH_ID_KEY: &[u8] = b"AES Auth ID Encryption";
const KDF_SALT_HEADER_LEN_KEY: &[u8] = b"VMess Header AEAD Key_Length";
const KDF_SALT_HEADER_LEN_IV: &[u8] = b"VMess Header AEAD Nonce_Length";
const KDF_SALT_HEADER_PAYLOAD_KEY: &[u8] = b"VMess Header AEAD Key";
const KDF_SALT_HEADER_PAYLOAD_IV: &[u8] = b"VMess Header AEAD Nonce";
const KDF_SALT_RESP_LEN_KEY: &[u8] = b"AEAD Resp Header Len Key";
const KDF_SALT_RESP_LEN_IV: &[u8] = b"AEAD Resp Header Len IV";
const KDF_SALT_RESP_PAYLOAD_KEY: &[u8] = b"AEAD Resp Header Key";
const KDF_SALT_RESP_PAYLOAD_IV: &[u8] = b"AEAD Resp Header IV";

const OPT_CHUNK_MASKING: u8 = 0x04;
const OPT_GLOBAL_PADDING: u8 = 0x08;
const OPT_AUTHENTICATED_LENGTH: u8 = 0x10;
const SEC_AES128_GCM: u8 = 3;
const SEC_CHACHA20_POLY1305: u8 = 4;
const SEC_NONE: u8 = 5;
const CMD_TCP: u8 = 1;
const CMD_UDP: u8 = 2;
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);
const UDP_IDLE_TIMEOUT: Duration = Duration::from_secs(90);
const MAX_CHUNK_PLAINTEXT: usize = 16 * 1024;

#[derive(Clone)]
pub struct VmessUser {
    pub uuid: [u8; 16],
    pub cmd_key: [u8; 16],
    pub auth_id_cipher: Aes128,
    pub email: String,
}

/// Derives VMess `cmdKey = MD5(uuid || "c48619fe-8f02-49e0-b9e9-edf763e17e21")`.
pub fn derive_cmd_key(uuid: &[u8; 16]) -> [u8; 16] {
    let mut h = Md5::new();
    Md5Digest::update(&mut h, uuid);
    Md5Digest::update(&mut h, b"c48619fe-8f02-49e0-b9e9-edf763e17e21");
    let digest = h.finalize();
    let mut out = [0u8; 16];
    out.copy_from_slice(&digest);
    out
}

/// Precomputes `KDF16(cmdKey, ["AES Auth ID Encryption"])` for fast AuthID matching.
pub fn derive_auth_id_key(cmd_key: &[u8; 16]) -> [u8; 16] {
    vmess_kdf16(cmd_key, &[KDF_SALT_AUTH_ID_KEY])
}

/// Exact recursive HMAC-SHA256 matching `proxy/vmess/aead/kdf.go`.
pub fn vmess_kdf(key: &[u8], path: &[&[u8]]) -> [u8; 32] {
    fn eval_hash(level: usize, path: &[&[u8]], data: &[u8]) -> [u8; 32] {
        if level == 0 {
            hmac_with_hash(KDF_SALT_VMESS_AEAD_KDF, data, |d| {
                let r = Sha256::digest(d);
                let mut out = [0u8; 32];
                out.copy_from_slice(&r);
                out
            })
        } else {
            let salt = path[level - 1];
            hmac_with_hash(salt, data, |d| eval_hash(level - 1, path, d))
        }
    }
    eval_hash(path.len(), path, key)
}

pub fn vmess_kdf16(key: &[u8], path: &[&[u8]]) -> [u8; 16] {
    let full = vmess_kdf(key, path);
    let mut out = [0u8; 16];
    out.copy_from_slice(&full[..16]);
    out
}

/// Standard RFC 2104 HMAC with 64-byte block size over an arbitrary 32-byte hash function `H`.
fn hmac_with_hash<F>(key: &[u8], msg: &[u8], hash_fn: F) -> [u8; 32]
where
    F: Fn(&[u8]) -> [u8; 32],
{
    let mut key_block = [0u8; 64];
    if key.len() > 64 {
        let hashed = hash_fn(key);
        key_block[..32].copy_from_slice(&hashed);
    } else {
        key_block[..key.len()].copy_from_slice(key);
    }

    let mut ipad = Vec::with_capacity(64 + msg.len());
    for &b in &key_block {
        ipad.push(b ^ 0x36);
    }
    ipad.extend_from_slice(msg);
    let inner = hash_fn(&ipad);

    let mut opad = [0u8; 64 + 32];
    for (i, &b) in key_block.iter().enumerate() {
        opad[i] = b ^ 0x5c;
    }
    opad[64..96].copy_from_slice(&inner);
    hash_fn(&opad)
}

fn generate_chacha20_key(key16: &[u8; 16]) -> [u8; 32] {
    let first = Md5::digest(key16);
    let second = Md5::digest(first);
    let mut out = [0u8; 32];
    out[..16].copy_from_slice(&first);
    out[16..].copy_from_slice(&second);
    out
}

fn fnv1a_32(data: &[u8]) -> u32 {
    let mut hash: u32 = 0x811c_9dc5;
    for &b in data {
        hash ^= b as u32;
        hash = hash.wrapping_mul(0x0100_0193);
    }
    hash
}

struct ShakeSizeParser {
    reader: Shake128Reader,
}

impl ShakeSizeParser {
    fn new(iv: &[u8; 16]) -> Self {
        let mut shake = Shake128::default();
        shake.update(iv);
        Self {
            reader: shake.finalize_xof(),
        }
    }

    fn next_u16(&mut self) -> u16 {
        let mut b = [0u8; 2];
        self.reader.read(&mut b);
        u16::from_be_bytes(b)
    }

    fn next_padding_len(&mut self) -> usize {
        (self.next_u16() % 64) as usize
    }

    fn decode_size(&mut self, raw: [u8; 2]) -> usize {
        let mask = self.next_u16();
        (u16::from_be_bytes(raw) ^ mask) as usize
    }

    fn encode_size(&mut self, size: u16) -> [u8; 2] {
        let mask = self.next_u16();
        (size ^ mask).to_be_bytes()
    }
}

enum ChunkCipher {
    Aes128Gcm(Aes128Gcm),
    ChaCha20Poly1305(ChaCha20Poly1305),
    None,
}

impl ChunkCipher {
    fn new(security: u8, key16: &[u8; 16]) -> io::Result<Self> {
        match security {
            SEC_AES128_GCM => Ok(Self::Aes128Gcm(Aes128Gcm::new(key16.into()))),
            SEC_CHACHA20_POLY1305 => {
                let k32 = generate_chacha20_key(key16);
                Ok(Self::ChaCha20Poly1305(ChaCha20Poly1305::new((&k32).into())))
            }
            SEC_NONE => Ok(Self::None),
            other => Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("unsupported VMess security type {other}"),
            )),
        }
    }

    fn overhead(&self) -> usize {
        match self {
            Self::None => 0,
            _ => 16,
        }
    }

    fn decrypt(&self, nonce12: &[u8; 12], ciphertext: &[u8]) -> io::Result<Vec<u8>> {
        let nonce = Nonce::from_slice(nonce12);
        match self {
            Self::Aes128Gcm(c) => c
                .decrypt(nonce, ciphertext)
                .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "VMess chunk decrypt failed")),
            Self::ChaCha20Poly1305(c) => c
                .decrypt(nonce, ciphertext)
                .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "VMess chunk decrypt failed")),
            Self::None => Ok(ciphertext.to_vec()),
        }
    }

    fn encrypt(&self, nonce12: &[u8; 12], plaintext: &[u8]) -> io::Result<Vec<u8>> {
        let nonce = Nonce::from_slice(nonce12);
        match self {
            Self::Aes128Gcm(c) => c
                .encrypt(nonce, plaintext)
                .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "VMess chunk encrypt failed")),
            Self::ChaCha20Poly1305(c) => c
                .encrypt(nonce, plaintext)
                .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "VMess chunk encrypt failed")),
            Self::None => Ok(plaintext.to_vec()),
        }
    }
}

struct ChunkCodec {
    cipher: ChunkCipher,
    len_cipher: Option<ChunkCipher>,
    iv: [u8; 16],
    count: u16,
    len_count: u16,
    shake: Option<ShakeSizeParser>,
    global_padding: bool,
}

impl ChunkCodec {
    fn new(
        security: u8,
        key16: &[u8; 16],
        auth_len_base_key: &[u8; 16],
        iv: [u8; 16],
        option: u8,
    ) -> io::Result<Self> {
        let cipher = ChunkCipher::new(security, key16)?;
        let chunk_masking = (option & OPT_CHUNK_MASKING) != 0;
        let global_padding = (option & OPT_GLOBAL_PADDING) != 0;
        let auth_length = (option & OPT_AUTHENTICATED_LENGTH) != 0 && security != SEC_NONE;

        if global_padding && !chunk_masking {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "VMess GlobalPadding requires ChunkMasking",
            ));
        }

        let shake = if chunk_masking {
            Some(ShakeSizeParser::new(&iv))
        } else {
            None
        };

        let len_cipher = if auth_length {
            let auth_len_key = vmess_kdf16(auth_len_base_key, &[b"auth_len"]);
            Some(ChunkCipher::new(security, &auth_len_key)?)
        } else {
            None
        };

        Ok(Self {
            cipher,
            len_cipher,
            iv,
            count: 0,
            len_count: 0,
            shake,
            global_padding,
        })
    }

    fn next_nonce(&mut self) -> [u8; 12] {
        let mut n = [0u8; 12];
        n[..2].copy_from_slice(&self.count.to_be_bytes());
        n[2..12].copy_from_slice(&self.iv[2..12]);
        self.count = self.count.wrapping_add(1);
        n
    }

    fn next_len_nonce(&mut self) -> [u8; 12] {
        let mut n = [0u8; 12];
        n[..2].copy_from_slice(&self.len_count.to_be_bytes());
        n[2..12].copy_from_slice(&self.iv[2..12]);
        self.len_count = self.len_count.wrapping_add(1);
        n
    }

    /// Reads one decrypted VMess chunk. Returns `Ok(None)` on EOF marker chunk.
    async fn read_chunk<R: AsyncRead + Unpin>(
        &mut self,
        reader: &mut R,
    ) -> io::Result<Option<Vec<u8>>> {
        let overhead = self.cipher.overhead();

        let (chunk_size, padding_len) = if self.len_cipher.is_some() {
            // AEADChunkSizeParser: 2 bytes length + 16 bytes tag = 18 bytes.
            let mut enc_len = [0u8; 18];
            if let Err(e) = reader.read_exact(&mut enc_len).await {
                if e.kind() == io::ErrorKind::UnexpectedEof {
                    return Ok(None);
                }
                return Err(e);
            }
            let padding_len = if self.global_padding {
                self.shake.as_mut().map(|s| s.next_padding_len()).unwrap_or(0)
            } else {
                0
            };
            let nonce = self.next_len_nonce();
            let plain_len = self.len_cipher.as_ref().unwrap().decrypt(&nonce, &enc_len)?;
            if plain_len.len() != 2 {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "invalid VMess auth_len",
                ));
            }
            // Xray AEADChunkSizeParser encodes payload_len - overhead; decode adds overhead back.
            let decoded = u16::from_be_bytes([plain_len[0], plain_len[1]]) as usize + overhead;
            (decoded, padding_len)
        } else {
            let mut size_raw = [0u8; 2];
            if let Err(e) = reader.read_exact(&mut size_raw).await {
                if e.kind() == io::ErrorKind::UnexpectedEof {
                    return Ok(None);
                }
                return Err(e);
            }
            let padding_len = if self.global_padding {
                self.shake.as_mut().map(|s| s.next_padding_len()).unwrap_or(0)
            } else {
                0
            };
            let chunk_size = match &mut self.shake {
                Some(s) => s.decode_size(size_raw),
                None => u16::from_be_bytes(size_raw) as usize,
            };
            (chunk_size, padding_len)
        };

        if chunk_size == overhead + padding_len {
            return Ok(None);
        }
        if chunk_size < overhead + padding_len {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "VMess chunk smaller than AEAD overhead",
            ));
        }

        let mut raw = vec![0u8; chunk_size];
        reader.read_exact(&mut raw).await?;

        let ct_len = chunk_size - padding_len;
        let nonce = self.next_nonce();
        let plain = self.cipher.decrypt(&nonce, &raw[..ct_len])?;
        Ok(Some(plain))
    }

    /// Encrypts and writes one VMess chunk (or EOF marker if `plaintext.is_empty()`).
    async fn write_chunk<W: AsyncWrite + Unpin>(
        &mut self,
        writer: &mut W,
        plaintext: &[u8],
    ) -> io::Result<()> {
        let overhead = self.cipher.overhead();
        let padding_len = if self.global_padding {
            self.shake.as_mut().map(|s| s.next_padding_len()).unwrap_or(0)
        } else {
            0
        };

        let encode_len = |this: &mut Self, total_len: usize| -> io::Result<Vec<u8>> {
            if this.len_cipher.is_some() {
                let raw_val = total_len.saturating_sub(overhead) as u16;
                let nonce = this.next_len_nonce();
                this.len_cipher
                    .as_ref()
                    .unwrap()
                    .encrypt(&nonce, &raw_val.to_be_bytes())
            } else {
                let b = match &mut this.shake {
                    Some(s) => s.encode_size(total_len as u16),
                    None => (total_len as u16).to_be_bytes(),
                };
                Ok(b.to_vec())
            }
        };

        if plaintext.is_empty() {
            let size_bytes = encode_len(self, overhead + padding_len)?;
            writer.write_all(&size_bytes).await?;
            return Ok(());
        }

        let nonce = self.next_nonce();
        let ct = self.cipher.encrypt(&nonce, plaintext)?;
        let total_len = ct.len() + padding_len;
        if total_len > u16::MAX as usize {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "VMess chunk exceeds u16 max",
            ));
        }

        let size_bytes = encode_len(self, total_len)?;

        let mut frame = Vec::with_capacity(size_bytes.len() + total_len);
        frame.extend_from_slice(&size_bytes);
        frame.extend_from_slice(&ct);
        if padding_len > 0 {
            let start = frame.len();
            frame.resize(start + padding_len, 0);
            rand::rngs::OsRng.fill_bytes(&mut frame[start..]);
        }
        writer.write_all(&frame).await
    }
}

struct DecodedVmessRequest {
    email: String,
    req_iv: [u8; 16],
    req_key: [u8; 16],
    resp_v: u8,
    option: u8,
    security: u8,
    cmd: u8,
    target: TargetAddr,
}

pub async fn handle_vmess(
    mut stream: BoxedStream,
    runtime: &InboundRuntime,
    peer_desc: &str,
) -> io::Result<()> {
    // 1. Read 16-byte AuthID + AEAD header under one strict 10s handshake timeout.
    let req = timeout(HANDSHAKE_TIMEOUT, async {
        let mut auth_id = [0u8; 16];
        stream.read_exact(&mut auth_id).await?;

        let now_unix = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs() as i64)
            .unwrap_or(0);

        let matched_user = {
            let users = runtime.users.read().unwrap_or_else(|e| e.into_inner());
            match_auth_id(&users.vmess_users, &auth_id, now_unix)
        };

        let Some(user) = matched_user else {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "VMess invalid AuthID or timestamp",
            ));
        };

        if !runtime.replay_cache.check_and_insert(auth_id) {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "VMess replayed AuthID",
            ));
        }

        open_vmess_aead_header(&mut stream, &user, &auth_id).await
    })
    .await
    .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "VMess handshake timeout"))??;

    log_debug!(
        "[{}] VMess user='{}' ({}) cmd={} sec={} -> {}",
        runtime.tag,
        req.email,
        peer_desc,
        req.cmd,
        req.security,
        req.target
    );

    // 2. Derive response key/IV = SHA256(req_key)[..16], SHA256(req_iv)[..16].
    let resp_key_full = Sha256::digest(req.req_key);
    let resp_iv_full = Sha256::digest(req.req_iv);
    let mut resp_key = [0u8; 16];
    let mut resp_iv = [0u8; 16];
    resp_key.copy_from_slice(&resp_key_full[..16]);
    resp_iv.copy_from_slice(&resp_iv_full[..16]);

    let resp_header_bytes = encode_vmess_aead_response_header(&resp_key, &resp_iv, req.resp_v)?;
    let mut req_codec = ChunkCodec::new(req.security, &req.req_key, &req.req_key, req.req_iv, req.option)?;
    // Note: Xray-core server.go uses s.requestBodyKey for auth_len key in EncodeResponseBody too.
    let mut resp_codec = ChunkCodec::new(req.security, &resp_key, &req.req_key, resp_iv, req.option)?;

    let counters = runtime.stats.counters_for(&req.email);
    let net_label = if req.cmd == CMD_UDP { "udp" } else { "tcp" };
    runtime.access_log.log_accepted(
        peer_desc,
        net_label,
        &req.target.to_string(),
        &runtime.tag,
        &req.email,
    );

    match req.cmd {
        CMD_TCP => {
            let outbound = dial_tcp(&req.target, runtime.block_private).await?;
            stream.write_all(&resp_header_bytes).await?;

            let (mut client_r, mut client_w) = tokio::io::split(stream);
            let (mut out_r, mut out_w) = outbound.into_split();

            let up_counters = counters.clone();
            let up = tokio::spawn(async move {
                while let Ok(Some(chunk)) = req_codec.read_chunk(&mut client_r).await {
                    if !chunk.is_empty() {
                        if out_w.write_all(&chunk).await.is_err() {
                            break;
                        }
                        if let Some(c) = &up_counters {
                            c.add_uplink(chunk.len() as u64);
                        }
                    }
                }
                let _ = out_w.shutdown().await;
            });

            let down_counters = counters;
            let down = tokio::spawn(async move {
                let mut buf = vec![0u8; MAX_CHUNK_PLAINTEXT];
                loop {
                    match out_r.read(&mut buf).await {
                        Ok(0) => {
                            let _ = resp_codec.write_chunk(&mut client_w, &[]).await;
                            break;
                        }
                        Ok(n) => {
                            if resp_codec.write_chunk(&mut client_w, &buf[..n]).await.is_err() {
                                break;
                            }
                            if let Some(c) = &down_counters {
                                c.add_downlink(n as u64);
                            }
                        }
                        Err(_) => break,
                    }
                }
                let _ = client_w.shutdown().await;
            });

            let _ = tokio::join!(up, down);
            Ok(())
        }
        CMD_UDP => {
            let remote_addr = resolve_udp_target(&req.target, runtime.block_private).await?;
            let udp = Arc::new(bind_udp_for(remote_addr).await?);
            let udp_recv = Arc::clone(&udp);

            stream.write_all(&resp_header_bytes).await?;

            let (mut client_r, mut client_w) = tokio::io::split(stream);

            let up_counters = counters.clone();
            let mut up = tokio::spawn(async move {
                loop {
                    match timeout(UDP_IDLE_TIMEOUT, req_codec.read_chunk(&mut client_r)).await {
                        Ok(Ok(Some(pkt))) => {
                            if !pkt.is_empty() {
                                if udp.send_to(&pkt, remote_addr).await.is_err() {
                                    break;
                                }
                                if let Some(c) = &up_counters {
                                    c.add_uplink(pkt.len() as u64);
                                }
                            }
                        }
                        _ => break,
                    }
                }
            });

            let down_counters = counters;
            let mut down = tokio::spawn(async move {
                let mut recv_buf = vec![0u8; 65507];
                loop {
                    let n =
                        match timeout(UDP_IDLE_TIMEOUT, udp_recv.recv_from(&mut recv_buf)).await {
                            Ok(Ok((n, _))) => n,
                            _ => break,
                        };
                    if n > 0 {
                        if resp_codec.write_chunk(&mut client_w, &recv_buf[..n]).await.is_err() {
                            break;
                        }
                        if let Some(c) = &down_counters {
                            c.add_downlink(n as u64);
                        }
                    }

                }
            });

            tokio::select! {
                _ = &mut up => { down.abort(); }
                _ = &mut down => { up.abort(); }
            }
            Ok(())
        }
        other => Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("unsupported VMess command 0x{other:02x}"),
        )),
    }
}

fn match_auth_id(users: &[VmessUser], auth_id: &[u8; 16], now_unix: i64) -> Option<VmessUser> {
    for u in users {
        let mut block = aes::Block::from(*auth_id);
        u.auth_id_cipher.decrypt_block(&mut block);
        let plain: [u8; 16] = block.into();

        let expected_crc = u32::from_be_bytes([plain[12], plain[13], plain[14], plain[15]]);
        if crc32fast::hash(&plain[..12]) != expected_crc {
            continue;
        }
        let ts = i64::from_be_bytes([
            plain[0], plain[1], plain[2], plain[3], plain[4], plain[5], plain[6], plain[7],
        ]);
        if ts < 0 || (ts - now_unix).abs() > 120 {
            continue;
        }
        return Some(u.clone());
    }
    None
}

async fn open_vmess_aead_header<R: AsyncRead + Unpin>(
    reader: &mut R,
    user: &VmessUser,
    auth_id: &[u8; 16],
) -> io::Result<DecodedVmessRequest> {
    let mut enc_len = [0u8; 18];
    let mut conn_nonce = [0u8; 8];
    reader.read_exact(&mut enc_len).await?;
    reader.read_exact(&mut conn_nonce).await?;

    let len_key = vmess_kdf16(&user.cmd_key, &[KDF_SALT_HEADER_LEN_KEY, auth_id, &conn_nonce]);
    let len_iv_full = vmess_kdf(&user.cmd_key, &[KDF_SALT_HEADER_LEN_IV, auth_id, &conn_nonce]);
    let len_cipher = Aes128Gcm::new((&len_key).into());
    let len_plain = len_cipher
        .decrypt(
            Nonce::from_slice(&len_iv_full[..12]),
            Payload {
                msg: &enc_len,
                aad: auth_id,
            },
        )
        .map_err(|_| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                "VMess AEAD header length decrypt failed",
            )
        })?;

    if len_plain.len() != 2 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "invalid VMess header len",
        ));
    }
    let header_len = u16::from_be_bytes([len_plain[0], len_plain[1]]) as usize;

    let mut enc_payload = vec![0u8; header_len + 16];
    reader.read_exact(&mut enc_payload).await?;

    let hdr_key = vmess_kdf16(
        &user.cmd_key,
        &[KDF_SALT_HEADER_PAYLOAD_KEY, auth_id, &conn_nonce],
    );
    let hdr_iv_full = vmess_kdf(
        &user.cmd_key,
        &[KDF_SALT_HEADER_PAYLOAD_IV, auth_id, &conn_nonce],
    );
    let hdr_cipher = Aes128Gcm::new((&hdr_key).into());
    let plain = hdr_cipher
        .decrypt(
            Nonce::from_slice(&hdr_iv_full[..12]),
            Payload {
                msg: &enc_payload,
                aad: auth_id,
            },
        )
        .map_err(|_| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                "VMess AEAD header payload decrypt failed",
            )
        })?;

    parse_vmess_request_header(&plain, user.email.clone())
}

fn parse_vmess_request_header(plain: &[u8], email: String) -> io::Result<DecodedVmessRequest> {
    if plain.len() < 42 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "VMess header too short",
        ));
    }
    let version = plain[0];
    if version != 1 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("unsupported VMess version {version}"),
        ));
    }

    let mut req_iv = [0u8; 16];
    let mut req_key = [0u8; 16];
    req_iv.copy_from_slice(&plain[1..17]);
    req_key.copy_from_slice(&plain[17..33]);

    let resp_v = plain[33];
    let option = plain[34];
    let padding_len = (plain[35] >> 4) as usize;
    let security = plain[35] & 0x0F;
    let cmd = plain[37];

    let (target, addr_consumed) = parse_vless_vmess_addr_slice(&plain[38..])?;
    let checksum_offset = 38 + addr_consumed + padding_len;
    if plain.len() < checksum_offset + 4 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "VMess missing FNV1a checksum",
        ));
    }

    let expected_hash = u32::from_be_bytes([
        plain[checksum_offset],
        plain[checksum_offset + 1],
        plain[checksum_offset + 2],
        plain[checksum_offset + 3],
    ]);
    let actual_hash = fnv1a_32(&plain[..checksum_offset]);
    if actual_hash != expected_hash {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "VMess header FNV1a mismatch",
        ));
    }

    Ok(DecodedVmessRequest {
        email,
        req_iv,
        req_key,
        resp_v,
        option,
        security,
        cmd,
        target,
    })
}

fn encode_vmess_aead_response_header(
    resp_key: &[u8; 16],
    resp_iv: &[u8; 16],
    resp_v: u8,
) -> io::Result<Vec<u8>> {
    let payload = [resp_v, 0x00, 0x00, 0x00];
    let len_bytes = (payload.len() as u16).to_be_bytes();

    let len_key = vmess_kdf16(resp_key, &[KDF_SALT_RESP_LEN_KEY]);
    let len_iv_full = vmess_kdf(resp_iv, &[KDF_SALT_RESP_LEN_IV]);
    let enc_len = Aes128Gcm::new((&len_key).into())
        .encrypt(Nonce::from_slice(&len_iv_full[..12]), len_bytes.as_slice())
        .map_err(|_| io::Error::new(io::ErrorKind::Other, "VMess resp len encrypt failed"))?;

    let hdr_key = vmess_kdf16(resp_key, &[KDF_SALT_RESP_PAYLOAD_KEY]);
    let hdr_iv_full = vmess_kdf(resp_iv, &[KDF_SALT_RESP_PAYLOAD_IV]);
    let enc_hdr = Aes128Gcm::new((&hdr_key).into())
        .encrypt(Nonce::from_slice(&hdr_iv_full[..12]), payload.as_slice())
        .map_err(|_| io::Error::new(io::ErrorKind::Other, "VMess resp hdr encrypt failed"))?;

    let mut out = Vec::with_capacity(enc_len.len() + enc_hdr.len());
    out.extend_from_slice(&enc_len);
    out.extend_from_slice(&enc_hdr);
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::parse_uuid;
    use aes::cipher::{BlockEncrypt, KeyInit as AesKeyInit};

    fn seal_test_vmess_aead_header(
        cmd_key: &[u8; 16],
        auth_id_key: &[u8; 16],
        timestamp: i64,
        header_plain: &[u8],
    ) -> Vec<u8> {
        let mut auth_plain = [0u8; 16];
        auth_plain[..8].copy_from_slice(&timestamp.to_be_bytes());
        auth_plain[8..12].copy_from_slice(&[0x11, 0x22, 0x33, 0x44]);
        let crc = crc32fast::hash(&auth_plain[..12]);
        auth_plain[12..16].copy_from_slice(&crc.to_be_bytes());

        let mut block = aes::Block::from(auth_plain);
        Aes128::new(auth_id_key.into()).encrypt_block(&mut block);
        let auth_id: [u8; 16] = block.into();

        let conn_nonce = [1u8, 2, 3, 4, 5, 6, 7, 8];
        let len_bytes = (header_plain.len() as u16).to_be_bytes();

        let len_key = vmess_kdf16(cmd_key, &[KDF_SALT_HEADER_LEN_KEY, &auth_id, &conn_nonce]);
        let len_iv = vmess_kdf(cmd_key, &[KDF_SALT_HEADER_LEN_IV, &auth_id, &conn_nonce]);
        let enc_len = Aes128Gcm::new((&len_key).into())
            .encrypt(
                Nonce::from_slice(&len_iv[..12]),
                Payload {
                    msg: &len_bytes,
                    aad: &auth_id,
                },
            )
            .unwrap();

        let hdr_key = vmess_kdf16(cmd_key, &[KDF_SALT_HEADER_PAYLOAD_KEY, &auth_id, &conn_nonce]);
        let hdr_iv = vmess_kdf(cmd_key, &[KDF_SALT_HEADER_PAYLOAD_IV, &auth_id, &conn_nonce]);
        let enc_hdr = Aes128Gcm::new((&hdr_key).into())
            .encrypt(
                Nonce::from_slice(&hdr_iv[..12]),
                Payload {
                    msg: header_plain,
                    aad: &auth_id,
                },
            )
            .unwrap();

        let mut out = Vec::new();
        out.extend_from_slice(&auth_id);
        out.extend_from_slice(&enc_len);
        out.extend_from_slice(&conn_nonce);
        out.extend_from_slice(&enc_hdr);
        out
    }

    #[tokio::test]
    async fn vmess_aead_header_and_chunk_roundtrip() {
        let uuid = parse_uuid("b831381d-6324-4d53-ad4f-8cda48b30811").unwrap();
        let cmd_key = derive_cmd_key(&uuid);
        let auth_id_key = derive_auth_id_key(&cmd_key);
        let user = VmessUser {
            uuid,
            cmd_key,
            auth_id_cipher: Aes128::new((&auth_id_key).into()),
            email: "test@example.com".to_string(),
        };

        let req_iv = [0xAAu8; 16];
        let req_key = [0xBBu8; 16];
        let mut hdr = Vec::new();
        hdr.push(1);
        hdr.extend_from_slice(&req_iv);
        hdr.extend_from_slice(&req_key);
        hdr.push(0x42);
        hdr.push(OPT_CHUNK_MASKING | OPT_GLOBAL_PADDING | 0x01);
        hdr.push(SEC_AES128_GCM);
        hdr.push(0);
        hdr.push(CMD_TCP);
        hdr.extend_from_slice(&443u16.to_be_bytes());
        hdr.push(0x01);
        hdr.extend_from_slice(&[1, 1, 1, 1]);
        let checksum = fnv1a_32(&hdr);
        hdr.extend_from_slice(&checksum.to_be_bytes());

        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64;
        let sealed = seal_test_vmess_aead_header(&cmd_key, &auth_id_key, now, &hdr);

        let mut auth_id = [0u8; 16];
        auth_id.copy_from_slice(&sealed[..16]);
        assert!(match_auth_id(&[user.clone()], &auth_id, now).is_some());

        let mut cursor = std::io::Cursor::new(&sealed[16..]);
        let decoded = open_vmess_aead_header(&mut cursor, &user, &auth_id)
            .await
            .unwrap();
        assert_eq!(decoded.resp_v, 0x42);
        assert_eq!(decoded.target.to_string(), "1.1.1.1:443");

        // Verify Shake128 + GlobalPadding chunk roundtrip
        let (mut w, mut r) = tokio::io::duplex(4096);
        let mut enc = ChunkCodec::new(SEC_AES128_GCM, &req_key, &req_key, req_iv, decoded.option).unwrap();
        let mut dec = ChunkCodec::new(SEC_AES128_GCM, &req_key, &req_key, req_iv, decoded.option).unwrap();

        enc.write_chunk(&mut w, b"hello-vmess-aead").await.unwrap();
        enc.write_chunk(&mut w, &[]).await.unwrap();
        drop(w);

        let plain = dec.read_chunk(&mut r).await.unwrap().unwrap();
        assert_eq!(plain, b"hello-vmess-aead");
        assert!(dec.read_chunk(&mut r).await.unwrap().is_none());

        // Verify AuthenticatedLength (0x10) chunk roundtrip
        let (mut w2, mut r2) = tokio::io::duplex(4096);
        let opt_auth = OPT_AUTHENTICATED_LENGTH | 0x01;
        let mut enc2 = ChunkCodec::new(SEC_AES128_GCM, &req_key, &req_key, req_iv, opt_auth).unwrap();
        let mut dec2 = ChunkCodec::new(SEC_AES128_GCM, &req_key, &req_key, req_iv, opt_auth).unwrap();

        enc2.write_chunk(&mut w2, b"auth-len-ok").await.unwrap();
        enc2.write_chunk(&mut w2, &[]).await.unwrap();
        drop(w2);

        let plain2 = dec2.read_chunk(&mut r2).await.unwrap().unwrap();
        assert_eq!(plain2, b"auth-len-ok");
        assert!(dec2.read_chunk(&mut r2).await.unwrap().is_none());
    }
}
