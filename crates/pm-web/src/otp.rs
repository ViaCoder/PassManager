//! 网页上的两步验证：账户列表 → 点进详情看当前验证码 → 需要时点"显示密钥"看种子（Base32、otpauth 链接与二维码）；
//! 导入（二维码图片可点选、拖入或粘贴截图，也可粘贴链接、上传 2FAS 备份）；改名、删除。
//!
//! 导入时只把二维码里读出的文本、粘贴的链接和 2FAS 文件原样交给服务端解析。种子平时不出现在任何页面里，
//! 只有在详情页点"显示密钥"（带 CSRF 的 POST）时由服务端返回一次，服务端每次都记日志。上传内容只在内存里，用完清零。

use std::collections::HashMap;

use axum::extract::{Extension, Form, Multipart, Path, Query, State};
use axum::http::{HeaderMap, StatusCode, header};
use axum::response::{IntoResponse, Response};
use minijinja::{Value, context};
use pm_proto::{OtpDetailView, OtpImportReport, OtpView, Request as Req, Sensitive};
use zeroize::Zeroizing;

use super::{ConnInfo, DoneQ, St, call, done, err_flash, err_text, flash_ctx, message, page, require, require_post, script_csp, sv};

/// 导入页的请求体上限（全部图片与文件加起来）。
pub const IMPORT_LIMIT: usize = 4 << 20;
/// 一次最多几张图片。
pub const MAX_IMAGES: usize = 10;
/// 粘贴的链接最多 256 KiB。
const MAX_LINKS: usize = 256 << 10;
/// 2FAS 备份文件最多 1 MiB。
const MAX_TWOFAS: usize = 1 << 20;
/// 备份口令最多 1 KiB。
const MAX_PASSWORD: usize = 1 << 10;
/// 详情页最多自动刷新几次（约 5 分钟），之后遮住验证码。
pub const MAX_ROUNDS: u32 = 10;
/// 头像的配色数（样式表里的 .av-0 … .av-7）。
const HUES: u32 = 8;

/// 详情页的脚本（按 SHA-256 放行，见 `script_csp`）：倒计时；到期时页面在前台且还没刷新满 MAX_ROUNDS 次就打开
/// 下一轮（GET，已显示的密钥随之遮住），否则遮住验证码与密钥；带 data-copy 的按钮点击复制（浏览器拒绝时提示手动输入）；
/// 服务器与浏览器时钟相差超过 5 秒时提示。只用 textContent / value / hidden 等属性，不拼 HTML。
pub const OTP_JS: &str = "(function(){var r=document.getElementById('otp');if(!r)return;\
var t0=performance.now(),left=+r.dataset.left,round=+r.dataset.round,max=+r.dataset.max,done=false;\
var off=Date.now()/1000-(+r.dataset.now);if(Math.abs(off)>5){document.getElementById('otp-off').textContent=String(Math.round(off));document.getElementById('otp-clock').hidden=false;}\
var bar=document.getElementById('otp-bar'),sec=document.getElementById('otp-sec'),code=document.getElementById('otp-code');\
function hide(){done=true;code.textContent='••••••';code.disabled=true;code.removeAttribute('data-copy');var s=document.getElementById('otp-secret');if(s)s.hidden=true;document.getElementById('otp-hidden').hidden=false;}\
function tick(){if(done)return;var l=Math.max(0,Math.ceil(left-(performance.now()-t0)/1000));bar.value=l;sec.textContent=String(l);\
if(l<=0){if(round<max&&document.visibilityState==='visible'){done=true;location.replace(r.dataset.next);}else{hide();}}}\
document.addEventListener('click',function(ev){var b=ev.target.closest&&ev.target.closest('[data-copy]');if(!b||!b.dataset.copy)return;\
var s=b.parentNode.querySelector('.copied');function say(t){if(!s)return;s.textContent=t;s.hidden=false;setTimeout(function(){s.hidden=true;},2000);}\
if(!navigator.clipboard){say('无法自动复制，请手动输入');return;}navigator.clipboard.writeText(b.dataset.copy).then(function(){say('已复制');},function(){say('无法自动复制，请手动输入');});});\
tick();setInterval(tick,250);})();";

/// 导入页的脚本（按 SHA-256 放行）：二维码图片可以拖进虚线框，或在页面上直接粘贴截图（Ctrl+V），都加进文件输入框；
/// 列出已选的文件名。只接受 PNG / JPEG；只用 textContent 与 createElement，不拼 HTML。
pub const IMPORT_JS: &str = "(function(){var inp=document.getElementById('f-images'),zone=document.getElementById('drop'),list=document.getElementById('picked');\
if(!inp||inp.disabled||!zone||!list)return;\
function show(){list.textContent='';[].forEach.call(inp.files,function(f){var li=document.createElement('li');li.textContent=f.name||'粘贴的图片';list.appendChild(li);});list.hidden=inp.files.length===0;}\
function add(files){var dt=new DataTransfer();[].forEach.call(inp.files,function(f){dt.items.add(f);});\
[].forEach.call(files,function(f){if(/^image\\/(png|jpeg)$/.test(f.type))dt.items.add(f);});inp.files=dt.files;show();}\
inp.addEventListener('change',show);\
zone.addEventListener('dragover',function(e){e.preventDefault();zone.classList.add('over');});\
zone.addEventListener('dragleave',function(){zone.classList.remove('over');});\
zone.addEventListener('drop',function(e){e.preventDefault();zone.classList.remove('over');add(e.dataTransfer.files);});\
document.addEventListener('paste',function(e){var fs=e.clipboardData&&e.clipboardData.files;if(fs&&fs.length){e.preventDefault();add(fs);}});})();";

/// 验证码分组显示：6 位显示成"123 456"，8 位"1234 5678"；Steam 码与奇数位不分组。
pub fn group(code: &str) -> String {
    let n = code.chars().count();
    if n >= 6 && n.is_multiple_of(2) && code.chars().all(|c| c.is_ascii_digit()) {
        let (a, b) = code.split_at(n / 2);
        format!("{a} {b}")
    } else {
        code.to_string()
    }
}

/// Base32 密钥每 4 个字符一组，方便对照抄写。
pub fn group4(s: &str) -> String {
    s.as_bytes().chunks(4).map(|c| String::from_utf8_lossy(c).into_owned()).collect::<Vec<_>>().join(" ")
}

/// 头像：发行方（没有时用名称）的第一个字母或数字（大写），与按名称算出的配色序号。
pub fn avatar(v: &OtpView) -> (String, u32) {
    let src = if v.issuer.is_empty() { &v.name } else { &v.issuer };
    let initial = src.chars().find(|c| c.is_alphanumeric()).map(|c| c.to_uppercase().to_string()).unwrap_or_else(|| "#".into());
    let hue = v.name.chars().fold(0u32, |h, c| h.wrapping_mul(31).wrapping_add(c as u32)) % HUES;
    (initial, hue)
}

/// 把文本画成二维码 SVG：一个白底 `<rect>` 加一个 `<path>`（每个深色模块一个 1×1 方块，四周留 4 个模块白边）。
/// 输出只有数字与固定的标记，不含输入文本本身。
pub fn qr_svg(text: &str) -> Option<String> {
    let code = qrcode::QrCode::new(text.as_bytes()).ok()?;
    let (n, colors) = (code.width(), code.to_colors());
    let mut d = String::new();
    for y in 0..n {
        for x in 0..n {
            if colors[y * n + x] == qrcode::Color::Dark {
                d.push_str(&format!("M{} {}h1v1h-1z", x + 4, y + 4));
            }
        }
    }
    let s = n + 8;
    Some(format!(
        r##"<svg class="qr" viewBox="0 0 {s} {s}" role="img" aria-label="密钥二维码" shape-rendering="crispEdges"><rect width="{s}" height="{s}" fill="#fff"/><path d="{d}" fill="#000"/></svg>"##
    ))
}

/// 列表里的一行：账户信息与头像。
#[derive(serde::Serialize)]
struct Row {
    #[serde(flatten)]
    view: OtpView,
    initial: String,
    hue: u32,
}

/// `GET /otp`：账户列表（不显示验证码）。
pub async fn list(State(st): State<St>, h: HeaderMap, conn: Option<Extension<ConnInfo>>, Query(q): Query<DoneQ>) -> Response {
    let c = match require(&st, &h, &conn) {
        Ok(c) => c,
        Err(r) => return r,
    };
    match call::<Vec<OtpView>>(&st, Req::OtpList).await {
        Ok(l) => {
            let rows: Vec<Row> = l
                .into_iter()
                .map(|view| {
                    let (initial, hue) = avatar(&view);
                    Row { view, initial, hue }
                })
                .collect();
            page(&st, &c, "otp.html", context! { accounts => sv(&rows), ..flash_ctx(&q) })
        }
        Err(e) => page(&st, &c, "otp.html", context! { accounts => sv(Vec::<Row>::new()), ..err_flash(&e) }),
    }
}

/// 详情页的查询参数：`r` 是自动刷新的轮次。
#[derive(serde::Deserialize, Default)]
pub struct RoundQ {
    r: Option<u32>,
}

/// 渲染详情页（`reveal` 时带上密钥、链接与二维码）。
async fn detail_page(st: &St, c: &super::Ctx, name: String, round: u32, reveal: bool) -> Response {
    let d = match call::<OtpDetailView>(st, Req::OtpDetail { name, reveal }).await {
        Ok(d) => d,
        Err(e) if e.0 == "UNKNOWN_CREDENTIAL" => {
            return message(st, Some(c), StatusCode::NOT_FOUND, "账户不存在", "账户不存在或已被删除。");
        }
        Err(e) => return message(st, Some(c), StatusCode::BAD_REQUEST, "无法显示", &err_text(&e)),
    };
    let (initial, hue) = avatar(&d.view);
    let round = round.min(MAX_ROUNDS);
    let qr = d.uri.as_deref().and_then(qr_svg).map(Value::from_safe_string);
    let ctx = context! {
        a => sv(&d.view),
        initial,
        hue,
        code => d.code.clone(),
        shown => group(&d.code),
        remaining => d.remaining,
        now => d.now,
        round,
        next_round => round + 1,
        max_rounds => MAX_ROUNDS,
        secret => d.secret.clone(),
        secret_shown => d.secret.as_deref().map(group4),
        uri => d.uri.clone(),
        qr,
        otp_js => Value::from_safe_string(OTP_JS.into()),
    };
    let mut r = page(st, c, "otp_item.html", ctx);
    r.headers_mut().insert(header::CONTENT_SECURITY_POLICY, script_csp(OTP_JS));
    r
}

/// `GET /otp/a/{name}`：详情与当前验证码（不含密钥）。
pub async fn detail(
    State(st): State<St>,
    h: HeaderMap,
    conn: Option<Extension<ConnInfo>>,
    Path(name): Path<String>,
    Query(q): Query<RoundQ>,
) -> Response {
    let c = match require(&st, &h, &conn) {
        Ok(c) => c,
        Err(r) => return r,
    };
    detail_page(&st, &c, name, q.r.unwrap_or(0), false).await
}

/// `POST /otp/a/{name}/secret`：显示密钥（带 CSRF）。
pub async fn reveal(
    State(st): State<St>,
    h: HeaderMap,
    conn: Option<Extension<ConnInfo>>,
    Path(name): Path<String>,
    Form(f): Form<HashMap<String, String>>,
) -> Response {
    let c = match require_post(&st, &h, &conn, &f) {
        Ok(c) => c,
        Err(r) => return r,
    };
    detail_page(&st, &c, name, 0, true).await
}

/// 导入页的上下文（GET 与 POST 结果共用）。
fn import_ctx(st: &St, report: Option<&OtpImportReport>) -> Value {
    context! {
        report => report.map(sv),
        limit_mib => IMPORT_LIMIT >> 20,
        max_images => MAX_IMAGES,
        has_qr => st.cfg.qr.is_some(),
        import_js => Value::from_safe_string(IMPORT_JS.into()),
    }
}

/// 渲染导入页（带导入页脚本的 CSP）。
fn import_render(st: &St, c: &super::Ctx, report: Option<&OtpImportReport>) -> Response {
    let mut r = page(st, c, "otp_import.html", import_ctx(st, report));
    r.headers_mut().insert(header::CONTENT_SECURITY_POLICY, script_csp(IMPORT_JS));
    r
}

/// `GET /otp/import`：导入页。
pub async fn import_page(State(st): State<St>, h: HeaderMap, conn: Option<Extension<ConnInfo>>) -> Response {
    let c = match require(&st, &h, &conn) {
        Ok(c) => c,
        Err(r) => return r,
    };
    import_render(&st, &c, None)
}

/// 导入表单里读到的内容。
#[derive(Default)]
struct Upload {
    csrf: String,
    images: Vec<Zeroizing<Vec<u8>>>,
    links: Zeroizing<Vec<u8>>,
    twofas: Zeroizing<Vec<u8>>,
    password: Zeroizing<Vec<u8>>,
    too_many_images: bool,
}

/// 读表单失败：状态码与原因（请求体超过上限时是 413）。
type UploadErr = (StatusCode, &'static str);

/// multipart 错误换成状态码与原因。
fn upload_err(e: axum::extract::multipart::MultipartError) -> UploadErr {
    if e.status() == StatusCode::PAYLOAD_TOO_LARGE {
        (StatusCode::PAYLOAD_TOO_LARGE, "上传的内容太大（总共不超过 4 MiB）")
    } else {
        (StatusCode::BAD_REQUEST, "上传中断或格式不对")
    }
}

/// 读一个字段的全部内容（逐块放进 Zeroizing，超过 `max` 字节时报错）。
async fn read_field(field: &mut axum::extract::multipart::Field<'_>, max: usize) -> Result<Zeroizing<Vec<u8>>, UploadErr> {
    let mut buf = Zeroizing::new(Vec::new());
    while let Some(chunk) = field.chunk().await.map_err(upload_err)? {
        if buf.len() + chunk.len() > max {
            return Err((StatusCode::PAYLOAD_TOO_LARGE, "上传的内容太大"));
        }
        buf.extend_from_slice(&chunk);
    }
    Ok(buf)
}

/// 读整个 multipart 表单。不认识的字段丢弃。
async fn read_upload(mut mp: Multipart) -> Result<Upload, UploadErr> {
    let mut u = Upload::default();
    while let Some(mut field) = mp.next_field().await.map_err(upload_err)? {
        let name = field.name().unwrap_or_default().to_string();
        match name.as_str() {
            "csrf" => u.csrf = String::from_utf8_lossy(&read_field(&mut field, 256).await?).into_owned(),
            "images" => {
                let data = read_field(&mut field, IMPORT_LIMIT).await?;
                // 没选文件时浏览器也会送一个空字段
                if data.is_empty() {
                    continue;
                }
                if u.images.len() >= MAX_IMAGES {
                    u.too_many_images = true;
                } else {
                    u.images.push(data);
                }
            }
            "links" => u.links = read_field(&mut field, MAX_LINKS).await?,
            "twofas" => u.twofas = read_field(&mut field, MAX_TWOFAS).await?,
            "password" => u.password = read_field(&mut field, MAX_PASSWORD).await?,
            _ => {
                read_field(&mut field, IMPORT_LIMIT).await?;
            }
        }
    }
    Ok(u)
}

/// 字节转成字符串（不是 UTF-8 时返回 None）；结果放进 Sensitive。
fn utf8(b: &[u8]) -> Option<Sensitive> {
    std::str::from_utf8(b).ok().map(Sensitive::new)
}

/// `POST /otp/import`：导入。先读完整个表单并检查 CSRF，然后逐张解码图片，再交给服务端。
pub async fn import(State(st): State<St>, h: HeaderMap, conn: Option<Extension<ConnInfo>>, mp: Multipart) -> Response {
    // 先检查会话（未登录的请求不读表单）
    let c = match require(&st, &h, &conn) {
        Ok(c) => c,
        Err(r) => return r,
    };
    let u = match read_upload(mp).await {
        Ok(u) => u,
        Err((code, why)) => return message(&st, Some(&c), code, "导入失败", why),
    };
    // CSRF（常数时间比较）
    if !pm_crypto::ct_eq(u.csrf.as_bytes(), c.csrf.as_bytes()) {
        return (StatusCode::FORBIDDEN, "CSRF token mismatch").into_response();
    }
    let mut texts = Vec::new();
    let mut skipped: Vec<(String, String)> = Vec::new();
    // 二维码图片：逐张交给解码器（服务器上是子进程）
    for (i, img) in u.images.into_iter().enumerate() {
        let label = format!("第 {} 张图片", i + 1);
        match &st.cfg.qr {
            Some(decode) => match decode(img).await {
                Ok(found) => texts.extend(found.iter().map(|t| Sensitive::new(t.as_str()))),
                Err(why) => skipped.push((label, why)),
            },
            None => skipped.push((label, "这台服务器不支持图片导入".into())),
        }
    }
    if u.too_many_images {
        skipped.push(("图片".into(), format!("一次最多 {MAX_IMAGES} 张，多出的没有处理")));
    }
    // 粘贴的链接
    if !u.links.is_empty() {
        match utf8(&u.links) {
            Some(t) => texts.push(t),
            None => skipped.push(("粘贴的链接".into(), "不是 UTF-8 文本".into())),
        }
    }
    // 2FAS 备份
    let twofas = if u.twofas.is_empty() {
        None
    } else {
        match utf8(&u.twofas) {
            Some(t) => Some(t),
            None => {
                skipped.push(("2FAS 备份".into(), "不是 2FAS 备份文件".into()));
                None
            }
        }
    };
    let password = if u.password.is_empty() { None } else { utf8(&u.password) };
    // 什么都没有：直接说明
    if texts.is_empty() && twofas.is_none() && skipped.is_empty() {
        return message(&st, Some(&c), StatusCode::BAD_REQUEST, "导入失败", "没有选择图片、粘贴链接或 2FAS 备份文件。");
    }
    let mut report = if texts.is_empty() && twofas.is_none() {
        OtpImportReport::default()
    } else {
        match call::<OtpImportReport>(&st, Req::OtpImport { texts, twofas, password }).await {
            Ok(r) => r,
            Err(e) => return message(&st, Some(&c), StatusCode::BAD_REQUEST, "导入失败", &err_text(&e)),
        }
    };
    // 网页这一侧的问题（图片读不出等）排在前面
    skipped.append(&mut report.skipped);
    report.skipped = skipped;
    import_render(&st, &c, Some(&report))
}

/// `POST /otp/a/{name}/rename`。
pub async fn rename(
    State(st): State<St>,
    h: HeaderMap,
    conn: Option<Extension<ConnInfo>>,
    Path(name): Path<String>,
    Form(f): Form<HashMap<String, String>>,
) -> Response {
    let c = match require_post(&st, &h, &conn, &f) {
        Ok(c) => c,
        Err(r) => return r,
    };
    let new_name = f.get("new_name").cloned().unwrap_or_default();
    match call::<serde_json::Value>(&st, Req::OtpRename { name, new_name }).await {
        Ok(_) => done("/otp", "renamed"),
        Err(e) => message(&st, Some(&c), StatusCode::BAD_REQUEST, "改名失败", &err_text(&e)),
    }
}

/// `POST /otp/a/{name}/delete`。
pub async fn delete(
    State(st): State<St>,
    h: HeaderMap,
    conn: Option<Extension<ConnInfo>>,
    Path(name): Path<String>,
    Form(f): Form<HashMap<String, String>>,
) -> Response {
    let c = match require_post(&st, &h, &conn, &f) {
        Ok(c) => c,
        Err(r) => return r,
    };
    match call::<serde_json::Value>(&st, Req::OtpDelete { name }).await {
        Ok(_) => done("/otp", "deleted"),
        Err(e) => message(&st, Some(&c), StatusCode::BAD_REQUEST, "删除失败", &err_text(&e)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn group_splits_even_numeric_codes() {
        assert_eq!(group("123456"), "123 456");
        assert_eq!(group("12345678"), "1234 5678");
        assert_eq!(group("1234567"), "1234567");
        assert_eq!(group("12345"), "12345");
        assert_eq!(group("GG5F5"), "GG5F5");
        assert_eq!(group(""), "");
    }

    #[test]
    fn group4_splits_secret() {
        assert_eq!(group4("GEZDGNBVGY3TQOJQ"), "GEZD GNBV GY3T QOJQ");
        assert_eq!(group4("JBSWY3DPEE"), "JBSW Y3DP EE");
        assert_eq!(group4(""), "");
    }

    #[test]
    fn avatar_initial_and_stable_hue() {
        let v = |name: &str, issuer: &str| OtpView { name: name.into(), issuer: issuer.into(), ..Default::default() };
        assert_eq!(avatar(&v("GitHub:alice", "GitHub")).0, "G");
        assert_eq!(avatar(&v("alice", "")).0, "A");
        assert_eq!(avatar(&v("  ·:x", "")).0, "X");
        assert_eq!(avatar(&v("工作邮箱", "")).0, "工");
        assert_eq!(avatar(&v("--", "")).0, "#");
        // 配色只由名称决定，范围 0..8
        assert_eq!(avatar(&v("GitHub:alice", "GitHub")).1, avatar(&v("GitHub:alice", "Other")).1);
        assert!((0..50).all(|i| avatar(&v(&format!("n{i}"), "")).1 < HUES));
    }

    /// SVG 只含数字与固定标记；把 path 画回像素，用 pm-otp 解码，得到原来的文本。
    #[test]
    fn qr_svg_round_trips_through_decoder() {
        let text = "otpauth://totp/Example:alice?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ&issuer=Example";
        let svg = qr_svg(text).unwrap();
        assert!(svg.starts_with("<svg class=\"qr\"") && !svg.contains("otpauth") && !svg.contains("GEZD"));
        // viewBox 边长与 path 里的方块
        let side: usize = svg.split("viewBox=\"0 0 ").nth(1).unwrap().split(' ').next().unwrap().parse().unwrap();
        let d = svg.split("<path d=\"").nth(1).unwrap().split('"').next().unwrap();
        let (scale, w) = (4, side * 4);
        let mut px = vec![255u8; w * w];
        for m in d.split('M').filter(|s| !s.is_empty()) {
            let xy = m.trim_end_matches("h1v1h-1z");
            let (x, y) = xy.split_once(' ').unwrap();
            let (x, y): (usize, usize) = (x.parse().unwrap(), y.parse().unwrap());
            for dy in 0..scale {
                for dx in 0..scale {
                    px[(y * scale + dy) * w + x * scale + dx] = 0;
                }
            }
        }
        let mut png_bytes = Vec::new();
        {
            let mut enc = png::Encoder::new(&mut png_bytes, w as u32, w as u32);
            enc.set_color(png::ColorType::Grayscale);
            enc.write_header().unwrap().write_image_data(&px).unwrap();
        }
        let found = pm_otp::qr::decode_image(&png_bytes).unwrap();
        assert_eq!(found[0].as_str(), text);
    }
}
