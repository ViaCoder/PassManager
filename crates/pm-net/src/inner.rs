//! Agent 通道的第二层（内层）加密：在外层 TLS 1.3（X25519MLKEM768 + AES-256-GCM）之内，
//! 再用服务端的两把静态后量子密钥建立一层独立的会话。
//!
//! ## 密钥
//! 服务端在 `init` 时生成 ML-KEM-1024（aws-lc-rs，格密码）与 Classic McEliece 6688128（liboqs，编码密码）
//! 两把静态密钥，私钥用设备密钥封存。公钥包 `bundle = "PMK1" ‖ len‖ek_mlkem ‖ len‖pk_mceliece`（约 1 MB），
//! 指纹 `fpr = SHA-384("pm/inner/v1/fpr\0" ‖ bundle)`。Agent 注册时从注册码里拿到指纹，
//! 下载公钥包并核对指纹后缓存；之后每次连接都重新核对缓存。
//!
//! ## 握手（全部在 TLS 之内）
//! ```text
//! C → S  "PMIN" ‖ 0x01(版本) ‖ op                    op = 0x01 取公钥包 | 0x02 建立会话
//! op=1:  S → C  u32 长度 ‖ bundle，然后关闭
//! op=2:  C → S  nonce_c(32) ‖ fpr(48) ‖ ct_K(1568) ‖ ct_M(208)      (ct_K, ss_K) = ML-KEM.Encaps(ek)，(ct_M, ss_M) = McEliece.Encaps(pk)
//!        S      fpr 不是自己的 → 静默断开；解封装得到 ss_K、ss_M
//!        S → C  nonce_s(32) ‖ tag_s(48)
//!        C → S  tag_c(48)
//! T    = 客户端第一条消息全部字节 ‖ nonce_s；  th = SHA-512("pm/inner/v1/transcript" ‖ T)
//! E    = TLS exporter("EXPORTER-PassManager-inner-v1", 64 字节)      把内层绑定到这一条 TLS 连接
//! okm  = HKDF-SHA512(salt = nonce_c ‖ nonce_s, ikm = ss_K ‖ ss_M ‖ E, info = "pm/inner/v1/keys" ‖ th)  → 128 字节
//! k_c2s = okm[0..32]，k_s2c = okm[32..64]，k_fin = okm[64..112]
//! tag_s = HMAC-SHA384(k_fin, "pm/inner/v1/server-finished" ‖ th)；tag_c 同理（"client-finished"）
//! ```
//! 服务端只有同时持有两把私钥才能算出 tag_s（证明身份）；中间人终止 TLS 再转发时 E 不同，双方密钥不一致，握手失败。
//! 版本、操作码都在 T 里，被改动会导致 tag 校验失败；服务端只接受版本 1。
//!
//! ## 帧
//! `u32 BE 密文长度 ‖ ChaCha20-Poly1305(k_dir, nonce = dir ‖ 0³ ‖ 计数器 u64 BE, aad = "pm/inner/v1/frame" ‖ 长度, 明文)`。
//! 两个方向各一把密钥、各一个从 0 开始的隐式计数器（不在线上传输）：重放、重排、删除、跨方向反射都会导致解密失败，
//! 连接立即关闭。外层 TLS 用 AES-GCM，内层用 ChaCha20-Poly1305：两层算法不同。

use std::io::{self, Read, Write};

use zeroize::Zeroizing;

use pm_crypto::aead::{self, Cipher};
use pm_crypto::kem::{self, McElieceKeys, MlKemKeys};
use pm_crypto::{CryptoError, ct_eq, hkdf, rng};

pub const MAGIC: &[u8; 4] = b"PMIN";
pub const VERSION: u8 = 1;
pub const OP_KEYS: u8 = 1;
pub const OP_SESSION: u8 = 2;
pub const HEADER_LEN: usize = 6;
pub const NONCE_LEN: usize = 32;
pub const FPR_LEN: usize = 48;
pub const TAG_LEN: usize = 48;
pub const MLKEM_CT_LEN: usize = 1568;
pub const MCELIECE_CT_LEN: usize = 208;
/// 会话请求中 header 之后的长度。
pub const SESSION_BODY_LEN: usize = NONCE_LEN + FPR_LEN + MLKEM_CT_LEN + MCELIECE_CT_LEN;
pub const SERVER_REPLY_LEN: usize = NONCE_LEN + TAG_LEN;
pub const EXPORTER_LABEL: &[u8] = b"EXPORTER-PassManager-inner-v1";
pub const EXPORTER_LEN: usize = 64;
/// 每帧明文上限。
pub const MAX_PLAINTEXT: usize = 64 * 1024;
const AEAD_TAG: usize = 16;
/// 公钥包大小上限（McEliece 公钥约 1 MB）。
pub const MAX_BUNDLE: usize = 2 * 1024 * 1024;

#[derive(Debug, thiserror::Error)]
pub enum InnerError {
    #[error("inner channel: malformed message ({0})")]
    Malformed(&'static str),
    #[error("inner channel: server key fingerprint mismatch")]
    Fingerprint,
    #[error("inner channel: handshake authentication failed")]
    Auth,
    #[error("inner channel: frame authentication failed (tampered, replayed or reordered)")]
    Frame,
    #[error("inner channel: frame counter exhausted")]
    CounterExhausted,
    #[error("inner channel: {0}")]
    Crypto(#[from] CryptoError),
    #[error("inner channel I/O: {0}")]
    Io(#[from] io::Error),
}

pub type Result<T> = std::result::Result<T, InnerError>;

fn header(op: u8) -> [u8; HEADER_LEN] {
    [MAGIC[0], MAGIC[1], MAGIC[2], MAGIC[3], VERSION, op]
}

/// 解析请求头，返回操作码。魔数、版本或操作码不对都返回错误（服务端据此静默断开）。
pub fn parse_header(h: &[u8; HEADER_LEN]) -> Result<u8> {
    if &h[..4] != MAGIC {
        return Err(InnerError::Malformed("magic"));
    }
    if h[4] != VERSION {
        return Err(InnerError::Malformed("unsupported version"));
    }
    match h[5] {
        OP_KEYS | OP_SESSION => Ok(h[5]),
        _ => Err(InnerError::Malformed("unknown operation")),
    }
}

/// 取公钥包的请求。
pub fn keys_request() -> [u8; HEADER_LEN] {
    header(OP_KEYS)
}

// ---------------- 服务端静态密钥 ----------------

/// 服务端的两把静态密钥。
pub struct ServerKeys {
    mlkem: MlKemKeys,
    mce: McElieceKeys,
    bundle: Vec<u8>,
    fpr: [u8; FPR_LEN],
}

/// 公钥包与指纹（客户端缓存）。
#[derive(Clone)]
pub struct ServerPublic {
    pub ek_mlkem: Vec<u8>,
    pub pk_mce: Vec<u8>,
    pub bundle: Vec<u8>,
    pub fpr: [u8; FPR_LEN],
}

pub fn fingerprint(bundle: &[u8]) -> [u8; FPR_LEN] {
    let mut d = b"pm/inner/v1/fpr\0".to_vec();
    d.extend_from_slice(bundle);
    pm_crypto::sha384(&d)
}

fn encode_bundle(ek: &[u8], pk: &[u8]) -> Vec<u8> {
    let mut b = Vec::with_capacity(12 + ek.len() + pk.len());
    b.extend_from_slice(b"PMK1");
    b.extend_from_slice(&(ek.len() as u32).to_be_bytes());
    b.extend_from_slice(ek);
    b.extend_from_slice(&(pk.len() as u32).to_be_bytes());
    b.extend_from_slice(pk);
    b
}

fn take<'a>(b: &mut &'a [u8]) -> Result<&'a [u8]> {
    if b.len() < 4 {
        return Err(InnerError::Malformed("truncated"));
    }
    let n = u32::from_be_bytes([b[0], b[1], b[2], b[3]]) as usize;
    if b.len() < 4 + n {
        return Err(InnerError::Malformed("truncated"));
    }
    let v = &b[4..4 + n];
    *b = &b[4 + n..];
    Ok(v)
}

impl ServerPublic {
    /// 解析公钥包并核对指纹（`expected` 来自注册码，或 remote.toml 中固定的值）。
    pub fn from_bundle(bundle: &[u8], expected: &[u8; FPR_LEN]) -> Result<Self> {
        if !ct_eq(&fingerprint(bundle), expected) {
            return Err(InnerError::Fingerprint);
        }
        let mut b = bundle.strip_prefix(b"PMK1".as_slice()).ok_or(InnerError::Malformed("bundle magic"))?;
        let ek = take(&mut b)?.to_vec();
        let pk = take(&mut b)?.to_vec();
        if !b.is_empty() {
            return Err(InnerError::Malformed("bundle trailing data"));
        }
        Ok(Self { ek_mlkem: ek, pk_mce: pk, bundle: bundle.to_vec(), fpr: *expected })
    }
}

impl ServerKeys {
    /// 生成新密钥（McEliece 约需数百毫秒）。
    pub fn generate() -> Result<Self> {
        let mlkem = kem::mlkem_generate()?;
        let mce = kem::mceliece_generate()?;
        Ok(Self::assemble(mlkem, mce))
    }

    fn assemble(mlkem: MlKemKeys, mce: McElieceKeys) -> Self {
        let bundle = encode_bundle(&mlkem.ek, &mce.pk);
        let fpr = fingerprint(&bundle);
        Self { mlkem, mce, bundle, fpr }
    }

    pub fn bundle(&self) -> &[u8] {
        &self.bundle
    }

    pub fn fingerprint(&self) -> [u8; FPR_LEN] {
        self.fpr
    }

    /// 私钥部分（由调用方用设备密钥封存）：`len‖dk_mlkem ‖ len‖sk_mceliece`。
    pub fn secret_bytes(&self) -> Zeroizing<Vec<u8>> {
        Zeroizing::new(encode_bundle(&self.mlkem.dk, &self.mce.sk)[4..].to_vec())
    }

    /// 由公钥包与私钥部分重建，并做成对一致性检查（防止两个文件不配套）。
    pub fn from_parts(bundle: &[u8], secret: &[u8]) -> Result<Self> {
        let public = ServerPublic::from_bundle(bundle, &fingerprint(bundle))?;
        let mut s = secret;
        let dk = Zeroizing::new(take(&mut s)?.to_vec());
        let sk = Zeroizing::new(take(&mut s)?.to_vec());
        if !s.is_empty() {
            return Err(InnerError::Malformed("secret trailing data"));
        }
        let (ct, ss) = kem::mlkem_encaps(&public.ek_mlkem)?;
        if !ct_eq(&ss, &kem::mlkem_decaps(&dk, &ct)?) {
            return Err(InnerError::Malformed("ML-KEM key pair mismatch"));
        }
        let (ct, ss) = kem::mceliece_encaps(&public.pk_mce)?;
        if !ct_eq(&ss, &kem::mceliece_decaps(&sk, &ct)?) {
            return Err(InnerError::Malformed("McEliece key pair mismatch"));
        }
        Ok(Self::assemble(MlKemKeys { dk, ek: public.ek_mlkem }, McElieceKeys { sk, pk: public.pk_mce }))
    }
}

// ---------------- 密钥派生 ----------------

struct Derived {
    c2s: Zeroizing<[u8; 32]>,
    s2c: Zeroizing<[u8; 32]>,
    fin: Zeroizing<[u8; 48]>,
    th: [u8; 64],
}

fn derive(client_msg: &[u8], nonce_c: &[u8], nonce_s: &[u8], ss_k: &[u8], ss_m: &[u8], exporter: &[u8; EXPORTER_LEN]) -> Result<Derived> {
    let mut t = b"pm/inner/v1/transcript".to_vec();
    t.extend_from_slice(client_msg);
    t.extend_from_slice(nonce_s);
    let th = pm_crypto::sha512(&t);
    let mut salt = nonce_c.to_vec();
    salt.extend_from_slice(nonce_s);
    let mut ikm = Zeroizing::new(Vec::with_capacity(ss_k.len() + ss_m.len() + EXPORTER_LEN));
    ikm.extend_from_slice(ss_k);
    ikm.extend_from_slice(ss_m);
    ikm.extend_from_slice(exporter);
    let mut okm = Zeroizing::new([0u8; 128]);
    hkdf::hkdf_sha512(&salt, &ikm, &[b"pm/inner/v1/keys", &th], okm.as_mut())?;
    let mut d = Derived { c2s: Zeroizing::new([0; 32]), s2c: Zeroizing::new([0; 32]), fin: Zeroizing::new([0; 48]), th };
    d.c2s.copy_from_slice(&okm[..32]);
    d.s2c.copy_from_slice(&okm[32..64]);
    d.fin.copy_from_slice(&okm[64..112]);
    Ok(d)
}

fn finished(fin: &[u8; 48], label: &[u8], th: &[u8; 64]) -> [u8; TAG_LEN] {
    pm_crypto::hmac_sha384(fin, &[label, th])
}

const SERVER_FIN: &[u8] = b"pm/inner/v1/server-finished";
const CLIENT_FIN: &[u8] = b"pm/inner/v1/client-finished";

// ---------------- 客户端握手 ----------------

pub struct ClientHandshake {
    msg: Vec<u8>,
    ss_k: Zeroizing<Vec<u8>>,
    ss_m: Zeroizing<Vec<u8>>,
}

impl ClientHandshake {
    /// 生成第一条消息（header ‖ nonce_c ‖ fpr ‖ ct_K ‖ ct_M）。
    pub fn start(server: &ServerPublic) -> Result<(Self, Vec<u8>)> {
        let nonce_c: [u8; NONCE_LEN] = rng::random_array()?;
        let (ct_k, ss_k) = kem::mlkem_encaps(&server.ek_mlkem)?;
        let (ct_m, ss_m) = kem::mceliece_encaps(&server.pk_mce)?;
        if ct_k.len() != MLKEM_CT_LEN || ct_m.len() != MCELIECE_CT_LEN {
            return Err(InnerError::Malformed("unexpected KEM ciphertext length"));
        }
        let mut msg = Vec::with_capacity(HEADER_LEN + SESSION_BODY_LEN);
        msg.extend_from_slice(&header(OP_SESSION));
        msg.extend_from_slice(&nonce_c);
        msg.extend_from_slice(&server.fpr);
        msg.extend_from_slice(&ct_k);
        msg.extend_from_slice(&ct_m);
        Ok((Self { msg: msg.clone(), ss_k, ss_m }, msg))
    }

    /// 处理服务端回复（nonce_s ‖ tag_s），校验服务端身份，返回会话与要发送的 tag_c。
    pub fn finish(self, reply: &[u8; SERVER_REPLY_LEN], exporter: &[u8; EXPORTER_LEN]) -> Result<(Session, [u8; TAG_LEN])> {
        let nonce_c = &self.msg[HEADER_LEN..HEADER_LEN + NONCE_LEN];
        let (nonce_s, tag_s) = reply.split_at(NONCE_LEN);
        let d = derive(&self.msg, nonce_c, nonce_s, &self.ss_k, &self.ss_m, exporter)?;
        if !ct_eq(&finished(&d.fin, SERVER_FIN, &d.th), tag_s) {
            return Err(InnerError::Auth);
        }
        let tag_c = finished(&d.fin, CLIENT_FIN, &d.th);
        Ok((Session { send: FrameCipher::new(&d.c2s, DIR_C2S), recv: FrameCipher::new(&d.s2c, DIR_S2C) }, tag_c))
    }
}

// ---------------- 服务端握手 ----------------

pub struct ServerPending {
    session: Session,
    expect: [u8; TAG_LEN],
}

/// 处理会话请求（`body` = header 之后的 [`SESSION_BODY_LEN`] 字节），返回待确认的会话与回复。
pub fn server_respond(keys: &ServerKeys, body: &[u8], exporter: &[u8; EXPORTER_LEN]) -> Result<(ServerPending, [u8; SERVER_REPLY_LEN])> {
    if body.len() != SESSION_BODY_LEN {
        return Err(InnerError::Malformed("session request length"));
    }
    let nonce_c = &body[..NONCE_LEN];
    let fpr = &body[NONCE_LEN..NONCE_LEN + FPR_LEN];
    if !ct_eq(fpr, &keys.fpr) {
        return Err(InnerError::Fingerprint);
    }
    let ct_k = &body[NONCE_LEN + FPR_LEN..NONCE_LEN + FPR_LEN + MLKEM_CT_LEN];
    let ct_m = &body[NONCE_LEN + FPR_LEN + MLKEM_CT_LEN..];
    // ML-KEM 隐式拒绝：被篡改的密文得到随机的共享密钥，随后 tag 校验失败。
    let ss_k = kem::mlkem_decaps(&keys.mlkem.dk, ct_k)?;
    let ss_m = kem::mceliece_decaps(&keys.mce.sk, ct_m)?;
    let nonce_s: [u8; NONCE_LEN] = rng::random_array()?;
    let mut msg = header(OP_SESSION).to_vec();
    msg.extend_from_slice(body);
    let d = derive(&msg, nonce_c, &nonce_s, &ss_k, &ss_m, exporter)?;
    let mut reply = [0u8; SERVER_REPLY_LEN];
    reply[..NONCE_LEN].copy_from_slice(&nonce_s);
    reply[NONCE_LEN..].copy_from_slice(&finished(&d.fin, SERVER_FIN, &d.th));
    let expect = finished(&d.fin, CLIENT_FIN, &d.th);
    Ok((
        ServerPending { session: Session { send: FrameCipher::new(&d.s2c, DIR_S2C), recv: FrameCipher::new(&d.c2s, DIR_C2S) }, expect },
        reply,
    ))
}

impl ServerPending {
    /// 校验客户端的 tag_c（证明客户端与服务端得到了相同的密钥，即同一条 TLS 连接、同一组 KEM 共享密钥）。
    pub fn confirm(self, tag_c: &[u8; TAG_LEN]) -> Result<Session> {
        if ct_eq(&self.expect, tag_c) { Ok(self.session) } else { Err(InnerError::Auth) }
    }
}

// ---------------- 帧加密 ----------------

const DIR_C2S: u8 = 0x01;
const DIR_S2C: u8 = 0x02;
const FRAME_AAD: &[u8] = b"pm/inner/v1/frame";

/// 单方向的帧加密器：每帧计数器加一（隐式，不传输）。
pub struct FrameCipher {
    key: Zeroizing<[u8; 32]>,
    dir: u8,
    counter: u64,
}

impl FrameCipher {
    fn new(key: &[u8; 32], dir: u8) -> Self {
        Self { key: Zeroizing::new(*key), dir, counter: 0 }
    }

    fn nonce(&self) -> [u8; 12] {
        let mut n = [0u8; 12];
        n[0] = self.dir;
        n[4..].copy_from_slice(&self.counter.to_be_bytes());
        n
    }

    fn advance(&mut self) -> Result<()> {
        self.counter = self.counter.checked_add(1).ok_or(InnerError::CounterExhausted)?;
        Ok(())
    }

    /// 加密一帧，返回 `u32 长度 ‖ 密文`。
    pub fn seal(&mut self, plaintext: &[u8]) -> Result<Vec<u8>> {
        if plaintext.is_empty() || plaintext.len() > MAX_PLAINTEXT {
            return Err(InnerError::Malformed("frame size"));
        }
        if self.counter == u64::MAX {
            return Err(InnerError::CounterExhausted);
        }
        let len = ((plaintext.len() + AEAD_TAG) as u32).to_be_bytes();
        let mut aad = FRAME_AAD.to_vec();
        aad.extend_from_slice(&len);
        let ct = aead::seal_with_nonce(Cipher::ChaCha20Poly1305, &self.key, self.nonce(), &aad, plaintext)?;
        self.advance()?;
        let mut out = Vec::with_capacity(4 + ct.len());
        out.extend_from_slice(&len);
        out.extend_from_slice(&ct);
        Ok(out)
    }

    /// 校验帧长度字段（读取密文前调用，避免按攻击者给的长度分配内存）。
    pub fn check_len(len: u32) -> Result<usize> {
        let len = len as usize;
        if len <= AEAD_TAG || len > MAX_PLAINTEXT + AEAD_TAG {
            return Err(InnerError::Malformed("frame length"));
        }
        Ok(len)
    }

    /// 解密一帧（`ct` 为长度字段之后的密文）。失败后连接必须关闭。
    pub fn open(&mut self, ct: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
        Self::check_len(ct.len() as u32)?;
        if self.counter == u64::MAX {
            return Err(InnerError::CounterExhausted);
        }
        let mut aad = FRAME_AAD.to_vec();
        aad.extend_from_slice(&(ct.len() as u32).to_be_bytes());
        let pt = aead::open_with_nonce(Cipher::ChaCha20Poly1305, &self.key, self.nonce(), &aad, ct).map_err(|_| InnerError::Frame)?;
        self.advance()?;
        Ok(pt)
    }

    #[cfg(any(test, feature = "test-hooks"))]
    pub fn set_counter_for_test(&mut self, c: u64) {
        self.counter = c;
    }
}

/// 已建立的会话：发送与接收各一个方向。
pub struct Session {
    pub send: FrameCipher,
    pub recv: FrameCipher,
}

// ---------------- 阻塞式客户端流（Agent 端：MCP / CLI） ----------------

/// 内层通道包装成 `Read + Write`：写入先缓存，`flush` 时（或满一帧时）加密发出；读取按帧解密。
pub struct InnerStream<S: Read + Write> {
    io: S,
    session: Session,
    wbuf: Vec<u8>,
    rbuf: Zeroizing<Vec<u8>>,
    rpos: usize,
    broken: bool,
}

/// 读满 `buf`；对端在中途关闭视为错误。
fn read_exact<S: Read>(io: &mut S, buf: &mut [u8]) -> io::Result<()> {
    io.read_exact(buf)
}

/// 阻塞式：从流中取公钥包（调用方再用 [`ServerPublic::from_bundle`] 核对指纹）。
pub fn fetch_bundle<S: Read + Write>(io: &mut S) -> Result<Vec<u8>> {
    io.write_all(&keys_request())?;
    io.flush()?;
    let mut len = [0u8; 4];
    read_exact(io, &mut len)?;
    let n = u32::from_be_bytes(len) as usize;
    if n == 0 || n > MAX_BUNDLE {
        return Err(InnerError::Malformed("bundle length"));
    }
    let mut b = vec![0u8; n];
    read_exact(io, &mut b)?;
    Ok(b)
}

impl<S: Read + Write> InnerStream<S> {
    /// 在已建立的 TLS 流上完成内层握手。`exporter` 取自同一条 TLS 连接。
    pub fn connect(mut io: S, server: &ServerPublic, exporter: &[u8; EXPORTER_LEN]) -> Result<Self> {
        let (hs, msg) = ClientHandshake::start(server)?;
        io.write_all(&msg)?;
        io.flush()?;
        let mut reply = [0u8; SERVER_REPLY_LEN];
        read_exact(&mut io, &mut reply)?;
        let (session, tag_c) = hs.finish(&reply, exporter)?;
        io.write_all(&tag_c)?;
        io.flush()?;
        Ok(Self { io, session, wbuf: Vec::new(), rbuf: Zeroizing::new(Vec::new()), rpos: 0, broken: false })
    }

    pub fn get_ref(&self) -> &S {
        &self.io
    }

    fn send_pending(&mut self) -> io::Result<()> {
        while !self.wbuf.is_empty() {
            let n = self.wbuf.len().min(MAX_PLAINTEXT);
            let frame = self.session.send.seal(&self.wbuf[..n]).map_err(io::Error::other)?;
            self.io.write_all(&frame)?;
            self.wbuf.drain(..n);
        }
        Ok(())
    }
}

impl<S: Read + Write> Write for InnerStream<S> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        if self.broken {
            return Err(io::Error::new(io::ErrorKind::BrokenPipe, "inner channel closed"));
        }
        self.wbuf.extend_from_slice(buf);
        if self.wbuf.len() >= MAX_PLAINTEXT {
            let full = self.wbuf.len() / MAX_PLAINTEXT * MAX_PLAINTEXT;
            let rest = self.wbuf.split_off(full);
            self.send_pending()?;
            self.wbuf = rest;
        }
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        self.send_pending()?;
        self.io.flush()
    }
}

impl<S: Read + Write> Read for InnerStream<S> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if buf.is_empty() {
            return Ok(0);
        }
        if self.rpos >= self.rbuf.len() {
            if self.broken {
                return Err(io::Error::new(io::ErrorKind::BrokenPipe, "inner channel closed"));
            }
            let mut len = [0u8; 4];
            match self.io.read(&mut len[..1]) {
                Ok(0) => return Ok(0),
                Ok(_) => {}
                Err(e) => return Err(e),
            }
            read_exact(&mut self.io, &mut len[1..])?;
            let n = FrameCipher::check_len(u32::from_be_bytes(len)).map_err(|e| {
                self.broken = true;
                io::Error::new(io::ErrorKind::InvalidData, e)
            })?;
            let mut ct = vec![0u8; n];
            read_exact(&mut self.io, &mut ct)?;
            self.rbuf = self.session.recv.open(&ct).map_err(|e| {
                self.broken = true;
                io::Error::new(io::ErrorKind::InvalidData, e)
            })?;
            self.rpos = 0;
        }
        let n = buf.len().min(self.rbuf.len() - self.rpos);
        buf[..n].copy_from_slice(&self.rbuf[self.rpos..self.rpos + n]);
        self.rpos += n;
        Ok(n)
    }
}

// ---------------- 异步服务端 ----------------

pub mod server {
    //! 服务端：在 TLS 流上完成握手，然后把内层通道包装成 `AsyncRead + AsyncWrite`
    //! （tokio duplex 管道 + 两个加解密泵），直接交给现有的 `handle_conn`。

    use std::time::Duration;

    use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, DuplexStream};

    use super::*;

    pub const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(15);

    /// 握手结果。
    pub enum Accepted {
        /// 客户端只取了公钥包（已发送），连接应关闭。
        KeysSent,
        Session(Session),
    }

    /// 读取请求头并完成握手。任何错误都应导致静默断开（不回任何内容）。
    pub async fn accept<S: AsyncRead + AsyncWrite + Unpin>(
        io: &mut S,
        keys: &ServerKeys,
        exporter: &[u8; EXPORTER_LEN],
    ) -> Result<Accepted> {
        tokio::time::timeout(HANDSHAKE_TIMEOUT, accept_inner(io, keys, exporter))
            .await
            .map_err(|_| InnerError::Io(io::Error::new(io::ErrorKind::TimedOut, "inner handshake timeout")))?
    }

    async fn accept_inner<S: AsyncRead + AsyncWrite + Unpin>(
        io: &mut S,
        keys: &ServerKeys,
        exporter: &[u8; EXPORTER_LEN],
    ) -> Result<Accepted> {
        let mut h = [0u8; HEADER_LEN];
        io.read_exact(&mut h).await?;
        match parse_header(&h)? {
            OP_KEYS => {
                let b = keys.bundle();
                io.write_all(&(b.len() as u32).to_be_bytes()).await?;
                io.write_all(b).await?;
                io.flush().await?;
                Ok(Accepted::KeysSent)
            }
            _ => {
                let mut body = vec![0u8; SESSION_BODY_LEN];
                io.read_exact(&mut body).await?;
                let (pending, reply) = server_respond(keys, &body, exporter)?;
                io.write_all(&reply).await?;
                io.flush().await?;
                let mut tag = [0u8; TAG_LEN];
                io.read_exact(&mut tag).await?;
                Ok(Accepted::Session(pending.confirm(&tag)?))
            }
        }
    }

    /// 在服务端 TLS 流上完成内层握手并包装。返回 None 表示只发送了公钥包（连接应关闭）。
    /// 外层协商结果不符合策略（理论上服务端配置已保证）时直接拒绝。
    pub async fn accept_tls<IO: AsyncRead + AsyncWrite + Unpin + Send + 'static>(
        mut tls: tokio_rustls::server::TlsStream<IO>,
        keys: &ServerKeys,
    ) -> Result<Option<DuplexStream>> {
        let conn = tls.get_ref().1;
        let group = conn.negotiated_key_exchange_group().map(|g| g.name());
        let suite = conn.negotiated_cipher_suite().map(|c| c.suite());
        if !crate::tls::negotiated_ok(group, suite) {
            return Err(InnerError::Malformed("TLS policy"));
        }
        let exporter = conn
            .export_keying_material([0u8; EXPORTER_LEN], EXPORTER_LABEL, None)
            .map_err(|e| InnerError::Io(io::Error::other(e.to_string())))?;
        match accept(&mut tls, keys, &exporter).await? {
            Accepted::KeysSent => Ok(None),
            Accepted::Session(s) => Ok(Some(wrap(tls, s))),
        }
    }

    /// 把已建立的会话包装成 `AsyncRead + AsyncWrite`。任一方向出错（帧被篡改、重放、重排）都会关闭整条连接。
    pub fn wrap<S: AsyncRead + AsyncWrite + Send + 'static>(io: S, session: Session) -> DuplexStream {
        let (app, internal) = tokio::io::duplex(4 * MAX_PLAINTEXT);
        let Session { send, recv } = session;
        tokio::spawn(async move {
            let (mut net_r, mut net_w) = tokio::io::split(io);
            let (mut int_r, mut int_w) = tokio::io::split(internal);
            let inbound = async move {
                let mut recv = recv;
                loop {
                    let mut len = [0u8; 4];
                    net_r.read_exact(&mut len).await?;
                    let n = FrameCipher::check_len(u32::from_be_bytes(len))?;
                    let mut ct = vec![0u8; n];
                    net_r.read_exact(&mut ct).await?;
                    let pt = recv.open(&ct)?;
                    int_w.write_all(&pt).await?;
                }
                #[allow(unreachable_code)]
                Ok::<(), InnerError>(())
            };
            let outbound = async move {
                let mut send = send;
                let mut buf = Zeroizing::new(vec![0u8; MAX_PLAINTEXT]);
                loop {
                    let n = int_r.read(&mut buf).await?;
                    if n == 0 {
                        break;
                    }
                    let frame = send.seal(&buf[..n])?;
                    net_w.write_all(&frame).await?;
                    net_w.flush().await?;
                }
                let _ = net_w.shutdown().await;
                Ok::<(), InnerError>(())
            };
            // 任一方向结束（含出错）即整体关闭：另一个方向随之被丢弃，TLS 流关闭，应用端读到 EOF。
            tokio::select! {
                _ = inbound => {}
                _ = outbound => {}
            }
        });
        app
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::OnceLock;

    pub(crate) fn keys() -> &'static ServerKeys {
        static K: OnceLock<ServerKeys> = OnceLock::new();
        K.get_or_init(|| ServerKeys::generate().unwrap())
    }

    fn public() -> ServerPublic {
        let k = keys();
        ServerPublic::from_bundle(k.bundle(), &k.fingerprint()).unwrap()
    }

    fn handshake(exp_c: &[u8; 64], exp_s: &[u8; 64]) -> Result<(Session, Session)> {
        let (hs, msg) = ClientHandshake::start(&public())?;
        let (pending, reply) = server_respond(keys(), &msg[HEADER_LEN..], exp_s)?;
        let (client, tag_c) = hs.finish(&reply, exp_c)?;
        let server = pending.confirm(&tag_c)?;
        Ok((client, server))
    }

    #[test]
    fn handshake_and_frames_roundtrip() {
        let e = [9u8; 64];
        let (mut c, mut s) = handshake(&e, &e).unwrap();
        let f1 = c.send.seal(b"hello").unwrap();
        let f2 = c.send.seal(b"world").unwrap();
        assert_ne!(f1[4..], f2[4..]);
        assert_eq!(s.recv.open(&f1[4..]).unwrap().as_slice(), b"hello");
        assert_eq!(s.recv.open(&f2[4..]).unwrap().as_slice(), b"world");
        let r = s.send.seal(b"reply").unwrap();
        assert_eq!(c.recv.open(&r[4..]).unwrap().as_slice(), b"reply");
        // 最大帧与超限。
        let big = vec![7u8; MAX_PLAINTEXT];
        let fb = c.send.seal(&big).unwrap();
        assert_eq!(s.recv.open(&fb[4..]).unwrap().len(), MAX_PLAINTEXT);
        assert!(c.send.seal(&vec![0u8; MAX_PLAINTEXT + 1]).is_err());
        assert!(c.send.seal(b"").is_err());
        assert!(FrameCipher::check_len(16).is_err());
        assert!(FrameCipher::check_len(17).is_ok());
        assert!(FrameCipher::check_len((MAX_PLAINTEXT + 17) as u32).is_err());
    }

    #[test]
    fn replay_reorder_reflection_and_tamper_are_rejected() {
        let e = [1u8; 64];
        let (mut c, mut s) = handshake(&e, &e).unwrap();
        let a = c.send.seal(b"first").unwrap();
        let b = c.send.seal(b"second").unwrap();
        // 重排：先收到第二帧。
        assert!(matches!(s.recv.open(&b[4..]), Err(InnerError::Frame)));
        let (mut c, mut s) = handshake(&e, &e).unwrap();
        let a2 = c.send.seal(b"first").unwrap();
        assert_eq!(s.recv.open(&a2[4..]).unwrap().as_slice(), b"first");
        // 重放：同一帧再来一次。
        assert!(s.recv.open(&a2[4..]).is_err());
        // 上一个会话的帧不能用于新会话。
        let (mut c, mut s) = handshake(&e, &e).unwrap();
        assert!(s.recv.open(&a[4..]).is_err());
        // 反射：把服务端发出的帧送回服务端。
        let out = s.send.seal(b"to client").unwrap();
        assert!(s.recv.open(&out[4..]).is_err());
        // 篡改任意字节或截断：失败且不推进计数器，之后原帧仍能正常解密。
        let (mut c2, mut s2) = handshake(&e, &e).unwrap();
        let f = c2.send.seal(b"payload-data").unwrap();
        for i in 4..f.len() {
            let mut t = f.clone();
            t[i] ^= 0x01;
            assert!(s2.recv.open(&t[4..]).is_err(), "byte {i}");
        }
        assert!(s2.recv.open(&f[4..f.len() - 1]).is_err());
        assert_eq!(s2.recv.open(&f[4..]).unwrap().as_slice(), b"payload-data");
        let _ = (&mut c, &mut c2);
    }

    #[test]
    fn counter_exhaustion_is_an_error() {
        let e = [2u8; 64];
        let (mut c, mut s) = handshake(&e, &e).unwrap();
        c.send.set_counter_for_test(u64::MAX - 1);
        s.recv.set_counter_for_test(u64::MAX - 1);
        let f = c.send.seal(b"last").unwrap();
        assert_eq!(s.recv.open(&f[4..]).unwrap().as_slice(), b"last");
        assert!(matches!(c.send.seal(b"one more"), Err(InnerError::CounterExhausted)));
        assert!(matches!(s.recv.open(&f[4..]), Err(InnerError::CounterExhausted)));
    }

    /// 中间人终止 TLS 再转发：双方的 exporter 不同 → 握手失败（客户端发现 tag_s 不对）。
    #[test]
    fn different_tls_exporter_fails() {
        assert!(matches!(handshake(&[1u8; 64], &[2u8; 64]), Err(InnerError::Auth)));
    }

    #[test]
    fn tampered_handshake_messages_fail() {
        let e = [3u8; 64];
        let pubk = public();
        // 篡改客户端消息的各个部分：fpr → 服务端拒绝；nonce / ct_K / ct_M → tag 不符。
        for (pos, fpr_err) in [
            (HEADER_LEN, false),
            (HEADER_LEN + NONCE_LEN, true),
            (HEADER_LEN + NONCE_LEN + FPR_LEN + 5, false),
            (HEADER_LEN + SESSION_BODY_LEN - 3, false),
        ] {
            let (hs, mut msg) = ClientHandshake::start(&pubk).unwrap();
            msg[pos] ^= 1;
            match server_respond(keys(), &msg[HEADER_LEN..], &e) {
                Err(InnerError::Fingerprint) => assert!(fpr_err, "{pos}"),
                Err(err) => panic!("{pos}: {err}"),
                Ok((_, reply)) => {
                    assert!(!fpr_err);
                    assert!(matches!(hs.finish(&reply, &e), Err(InnerError::Auth)), "{pos}");
                }
            }
        }
        // 篡改服务端回复（nonce_s 或 tag_s）。
        for pos in [0, NONCE_LEN + 1] {
            let (hs, msg) = ClientHandshake::start(&pubk).unwrap();
            let (_, mut reply) = server_respond(keys(), &msg[HEADER_LEN..], &e).unwrap();
            reply[pos] ^= 1;
            assert!(matches!(hs.finish(&reply, &e), Err(InnerError::Auth)), "{pos}");
        }
        // 篡改客户端的 tag_c。
        let (hs, msg) = ClientHandshake::start(&pubk).unwrap();
        let (pending, reply) = server_respond(keys(), &msg[HEADER_LEN..], &e).unwrap();
        let (_, mut tag) = hs.finish(&reply, &e).unwrap();
        tag[0] ^= 1;
        assert!(matches!(pending.confirm(&tag), Err(InnerError::Auth)));
        // 长度不对。
        assert!(server_respond(keys(), &msg[HEADER_LEN..msg.len() - 1], &e).is_err());
    }

    /// 降级：不同版本、未知操作码、错误魔数都被拒绝；改了版本的握手即使送到服务端也验证不过。
    #[test]
    fn downgrade_and_unknown_versions_are_rejected() {
        assert_eq!(parse_header(b"PMIN\x01\x02").unwrap(), OP_SESSION);
        assert_eq!(parse_header(&keys_request()).unwrap(), OP_KEYS);
        for bad in [b"PMIN\x00\x02", b"PMIN\x02\x02", b"PMIN\x01\x03", b"PMIN\x01\x00", b"XMIN\x01\x02", b"GET / "] {
            assert!(parse_header(bad).is_err(), "{bad:?}");
        }
        // 客户端声明的版本是 transcript 的一部分：服务端按 v1 计算，客户端若被改成别的版本，tag 不符。
        let e = [4u8; 64];
        let (hs, mut msg) = ClientHandshake::start(&public()).unwrap();
        let (_, reply) = server_respond(keys(), &msg[HEADER_LEN..], &e).unwrap();
        msg[4] = 0;
        let forged = ClientHandshake { msg, ss_k: hs.ss_k.clone(), ss_m: hs.ss_m.clone() };
        assert!(matches!(forged.finish(&reply, &e), Err(InnerError::Auth)));
    }

    #[test]
    fn fingerprint_pinning_and_bundle_parsing() {
        let k = keys();
        let mut wrong = k.fingerprint();
        wrong[0] ^= 1;
        assert!(matches!(ServerPublic::from_bundle(k.bundle(), &wrong), Err(InnerError::Fingerprint)));
        let mut b = k.bundle().to_vec();
        b[100] ^= 1;
        assert!(matches!(ServerPublic::from_bundle(&b, &k.fingerprint()), Err(InnerError::Fingerprint)));
        // 指纹正确但结构坏（攻击者无法做到，但解析必须健壮）。
        let junk = b"PMK1\x00\x00\x00\x09abc".to_vec();
        assert!(ServerPublic::from_bundle(&junk, &fingerprint(&junk)).is_err());
        let mut trailing = k.bundle().to_vec();
        trailing.push(0);
        assert!(ServerPublic::from_bundle(&trailing, &fingerprint(&trailing)).is_err());
        // 另一台服务器的密钥：客户端指纹不符，服务端拒绝。
        let other = ServerKeys::generate().unwrap();
        let p_other = ServerPublic::from_bundle(other.bundle(), &other.fingerprint()).unwrap();
        let (_, msg) = ClientHandshake::start(&p_other).unwrap();
        assert!(matches!(server_respond(keys(), &msg[HEADER_LEN..], &[0u8; 64]), Err(InnerError::Fingerprint)));
        // 私钥部分可重建，且与别的公钥包不配套时被发现。
        let re = ServerKeys::from_parts(k.bundle(), &k.secret_bytes()).unwrap();
        assert_eq!(re.fingerprint(), k.fingerprint());
        assert!(ServerKeys::from_parts(other.bundle(), &k.secret_bytes()).is_err());
        assert!(ServerKeys::from_parts(k.bundle(), &k.secret_bytes()[..100]).is_err());
        assert_eq!(fingerprint(k.bundle()).len(), 48);
    }

    /// 阻塞式客户端流：大于一帧的数据被拆成多帧，读取端按帧解密并拼回。
    #[test]
    #[cfg(unix)]
    fn blocking_stream_chunks_large_writes() {
        use std::os::unix::net::UnixStream;
        let (a, b) = UnixStream::pair().unwrap();
        let e = [5u8; 64];
        let server = std::thread::spawn(move || {
            let mut b = b;
            let mut h = [0u8; HEADER_LEN];
            b.read_exact(&mut h).unwrap();
            assert_eq!(parse_header(&h).unwrap(), OP_SESSION);
            let mut body = vec![0u8; SESSION_BODY_LEN];
            b.read_exact(&mut body).unwrap();
            let (p, reply) = server_respond(keys(), &body, &e).unwrap();
            b.write_all(&reply).unwrap();
            let mut tag = [0u8; TAG_LEN];
            b.read_exact(&mut tag).unwrap();
            let mut s = p.confirm(&tag).unwrap();
            let mut got = Vec::new();
            let mut frames = 0;
            while got.len() < 200_000 {
                let mut len = [0u8; 4];
                b.read_exact(&mut len).unwrap();
                let mut ct = vec![0u8; FrameCipher::check_len(u32::from_be_bytes(len)).unwrap()];
                b.read_exact(&mut ct).unwrap();
                got.extend_from_slice(&s.recv.open(&ct).unwrap());
                frames += 1;
            }
            assert!(frames >= 4);
            let f = s.send.seal(&got[..100_000.min(MAX_PLAINTEXT)]).unwrap();
            b.write_all(&f).unwrap();
            got
        });
        let mut c = InnerStream::connect(a, &public(), &e).unwrap();
        let data: Vec<u8> = (0..200_000u32).map(|i| (i % 251) as u8).collect();
        c.write_all(&data).unwrap();
        c.flush().unwrap();
        let mut back = vec![0u8; MAX_PLAINTEXT];
        c.read_exact(&mut back).unwrap();
        assert_eq!(back, data[..MAX_PLAINTEXT]);
        assert_eq!(server.join().unwrap(), data);
    }
}
