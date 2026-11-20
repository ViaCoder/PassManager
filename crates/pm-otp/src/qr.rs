//! 从 PNG / JPEG 图片里找二维码，读出里面的文本（`otpauth://…` 链接）。
//!
//! 图片来自网页上传，是不可信的输入。服务器以 `panic = abort` 编译，解码库里任何一处 panic 都会让整个服务退出，
//! 所以服务进程不在自己身上解码：它启动自己的一个子进程（`PassManager qr-decode`，限制内存与 CPU 时间、禁止 core dump），
//! 通过标准输入交给它图片，从标准输出读回 JSON。[`child_main`] 是子进程一端，[`parse_child_output`] 是父进程一端。
//!
//! 格式按文件头判断（不看扩展名）；宽高、像素数与解码内存都有上限，防止解压炸弹。

use std::io::{Read, Write};

use zeroize::Zeroizing;

/// 一张图片最大 4 MiB（与网页导入页的上传上限一致）。
pub const MAX_IMAGE_BYTES: usize = 4 << 20;
/// 宽、高各最多 4096 像素。
pub const MAX_SIDE: usize = 4096;
/// 像素总数上限。
pub const MAX_PIXELS: usize = MAX_SIDE * MAX_SIDE;
/// PNG 解码器最多分配的内存（4096×4096 的 16 位 RGBA 解成 8 位是 64 MiB，再留余量）。
const PNG_MEMORY: usize = 96 << 20;
/// 子进程输出最大 1 MiB（一张图里的二维码文本远小于此）。
pub const MAX_CHILD_OUTPUT: usize = 1 << 20;

/// PNG 文件头。
const PNG_MAGIC: &[u8] = b"\x89PNG\r\n\x1a\n";
/// JPEG 文件头（SOI 标记 + 下一个标记的 0xFF）。
const JPEG_MAGIC: &[u8] = &[0xff, 0xd8, 0xff];

/// 把图片解成灰度：返回 (宽, 高, 每像素一个字节)。
pub fn luma(bytes: &[u8]) -> Result<(usize, usize, Zeroizing<Vec<u8>>), &'static str> {
    if bytes.len() > MAX_IMAGE_BYTES {
        return Err("图片太大（最大 4 MiB）");
    }
    if bytes.starts_with(PNG_MAGIC) {
        png_luma(bytes)
    } else if bytes.starts_with(JPEG_MAGIC) {
        jpeg_luma(bytes)
    } else {
        Err("只支持 PNG 和 JPEG 图片")
    }
}

/// 宽高检查。
fn check_dims(w: usize, h: usize) -> Result<(), &'static str> {
    if w == 0 || h == 0 {
        return Err("图片尺寸为 0");
    }
    if w > MAX_SIDE || h > MAX_SIDE || w * h > MAX_PIXELS {
        return Err("图片尺寸太大（宽高最多 4096 像素）");
    }
    Ok(())
}

/// PNG → 灰度。透明像素按白色背景合成（截图常有透明边）。
fn png_luma(bytes: &[u8]) -> Result<(usize, usize, Zeroizing<Vec<u8>>), &'static str> {
    const BAD: &str = "PNG 图片已损坏";
    let mut dec = png::Decoder::new_with_limits(std::io::Cursor::new(bytes), png::Limits { bytes: PNG_MEMORY });
    // 调色板、低位深与 16 位都统一成每通道 8 位
    dec.set_transformations(png::Transformations::normalize_to_color8());
    let mut reader = dec.read_info().map_err(|_| BAD)?;
    // 先看头里的宽高，超限的不解码
    let (w, h) = {
        let i = reader.info();
        (i.width as usize, i.height as usize)
    };
    check_dims(w, h)?;
    let size = reader.output_buffer_size().ok_or("图片尺寸太大")?;
    let mut buf = Zeroizing::new(vec![0u8; size]);
    let info = reader.next_frame(&mut buf).map_err(|_| BAD)?;
    // 每像素的通道数
    let ch = match info.color_type {
        png::ColorType::Grayscale => 1,
        png::ColorType::GrayscaleAlpha => 2,
        png::ColorType::Rgb => 3,
        png::ColorType::Rgba => 4,
        // normalize_to_color8 已经展开了调色板，不会走到这里
        png::ColorType::Indexed => return Err(BAD),
    };
    let (fw, fh) = (info.width as usize, info.height as usize);
    check_dims(fw, fh)?;
    // 每行至少要有 宽 × 通道数 字节
    if info.line_size < fw * ch || buf.len() < info.line_size * fh {
        return Err(BAD);
    }
    let mut out = Zeroizing::new(Vec::with_capacity(fw * fh));
    for row in buf.chunks(info.line_size).take(fh) {
        for px in row[..fw * ch].chunks_exact(ch) {
            // 灰度：ITU-R BT.601 的整数近似（0.299 R + 0.587 G + 0.114 B）
            let (l, a) = match ch {
                1 => (px[0] as u32, 255),
                2 => (px[0] as u32, px[1] as u32),
                3 => (rgb(px[0], px[1], px[2]), 255),
                _ => (rgb(px[0], px[1], px[2]), px[3] as u32),
            };
            // 按白色背景合成透明度
            out.push(((l * a + 255 * (255 - a)) / 255) as u8);
        }
    }
    Ok((fw, fh, out))
}

/// RGB → 灰度。
fn rgb(r: u8, g: u8, b: u8) -> u32 {
    (299 * r as u32 + 587 * g as u32 + 114 * b as u32) / 1000
}

/// JPEG → 灰度（解码器直接输出灰度）。
fn jpeg_luma(bytes: &[u8]) -> Result<(usize, usize, Zeroizing<Vec<u8>>), &'static str> {
    use zune_jpeg::zune_core::{colorspace::ColorSpace, options::DecoderOptions};
    const BAD: &str = "JPEG 图片已损坏";
    // 解码器自己也按宽高上限拒绝；输出灰度
    let opts = DecoderOptions::default().set_max_width(MAX_SIDE).set_max_height(MAX_SIDE).jpeg_set_out_colorspace(ColorSpace::Luma);
    let mut d = zune_jpeg::JpegDecoder::new_with_options(std::io::Cursor::new(bytes), opts);
    d.decode_headers().map_err(|_| BAD)?;
    let info = d.info().ok_or(BAD)?;
    let (w, h) = (info.width as usize, info.height as usize);
    check_dims(w, h)?;
    let px = Zeroizing::new(d.decode().map_err(|_| BAD)?);
    // 输出必须正好是 宽 × 高 个灰度字节
    if px.len() != w * h {
        return Err(BAD);
    }
    Ok((w, h, px))
}

/// 找出图片里的所有二维码并读出文本。一个都读不出时返回原因。
pub fn decode_image(bytes: &[u8]) -> Result<Vec<Zeroizing<String>>, &'static str> {
    let (w, h, px) = luma(bytes)?;
    // rqrr：二值化、找定位图案、读码
    let mut img = rqrr::PreparedImage::prepare_from_greyscale(w, h, |x, y| px[y * w + x]);
    let mut out = Vec::new();
    let mut unreadable = 0;
    for g in img.detect_grids() {
        match g.decode() {
            Ok((_, text)) => out.push(Zeroizing::new(text)),
            Err(_) => unreadable += 1,
        }
    }
    if out.is_empty() {
        return Err(if unreadable > 0 {
            "找到了二维码，但读不出来（可能太模糊或被遮挡）"
        } else {
            "图片里没有找到二维码"
        });
    }
    Ok(out)
}

/// 子进程一端：从 `input` 读一张图片，向 `output` 写 `{"texts":[…]}` 或 `{"error":"…"}`。返回退出码。
pub fn child_main(input: &mut dyn Read, output: &mut dyn Write) -> i32 {
    // 最多读上限 + 1 字节，用来判断是否超限
    let mut buf = Zeroizing::new(Vec::new());
    if input.take(MAX_IMAGE_BYTES as u64 + 1).read_to_end(&mut buf).is_err() {
        return write_json(output, &serde_json::json!({ "error": "读取图片失败" }));
    }
    let v = match decode_image(&buf) {
        Ok(texts) => serde_json::json!({ "texts": texts.iter().map(|t| t.as_str()).collect::<Vec<_>>() }),
        Err(e) => serde_json::json!({ "error": e }),
    };
    write_json(output, &v)
}

/// 写出 JSON（序列化结果里有种子，放进 Zeroizing）。
fn write_json(output: &mut dyn Write, v: &serde_json::Value) -> i32 {
    let Ok(bytes) = serde_json::to_vec(v).map(Zeroizing::new) else { return 1 };
    if output.write_all(&bytes).and_then(|_| output.flush()).is_err() { 1 } else { 0 }
}

/// 父进程一端：解析子进程的输出。子进程崩溃、超时或输出不对时，调用方传入空输出，这里统一报"无法解码"。
pub fn parse_child_output(stdout: &[u8]) -> Result<Vec<Zeroizing<String>>, String> {
    #[derive(serde::Deserialize)]
    struct Out {
        #[serde(default)]
        texts: Option<Vec<Zeroizing<String>>>,
        #[serde(default)]
        error: Option<String>,
    }
    if stdout.len() > MAX_CHILD_OUTPUT {
        return Err("图片无法解码".into());
    }
    match serde_json::from_slice::<Out>(stdout) {
        Ok(Out { texts: Some(t), .. }) => Ok(t),
        Ok(Out { error: Some(e), .. }) => Err(e),
        _ => Err("图片无法解码".into()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 生成一张二维码 PNG：每个模块 `scale` 像素，四周留 4 个模块的白边；`mode` 选颜色类型。
    pub fn qr_png(text: &str, scale: usize, mode: png::ColorType) -> Vec<u8> {
        let code = qrcode::QrCode::new(text.as_bytes()).unwrap();
        let n = code.width();
        let colors = code.to_colors();
        let side = (n + 8) * scale;
        let ch = match mode {
            png::ColorType::Grayscale => 1,
            png::ColorType::GrayscaleAlpha => 2,
            png::ColorType::Rgb => 3,
            _ => 4,
        };
        let mut px = vec![255u8; side * side * ch];
        for y in 0..side {
            for x in 0..side {
                let (mx, my) = ((x / scale).wrapping_sub(4), (y / scale).wrapping_sub(4));
                let dark = mx < n && my < n && colors[my * n + mx] == qrcode::Color::Dark;
                let o = (y * side + x) * ch;
                match ch {
                    // 灰度：深色模块为 0
                    1 => px[o] = if dark { 0 } else { 255 },
                    // 灰度 + 透明：浅色部分全透明（合成到白底后是白色）
                    2 => {
                        px[o] = 0;
                        px[o + 1] = if dark { 255 } else { 0 };
                    }
                    // 彩色：深色模块用深蓝
                    _ => {
                        if dark {
                            px[o..o + 3].copy_from_slice(&[10, 20, 80]);
                        }
                        if ch == 4 {
                            px[o + 3] = 255;
                        }
                    }
                }
            }
        }
        let mut out = Vec::new();
        {
            let mut enc = png::Encoder::new(&mut out, side as u32, side as u32);
            enc.set_color(mode);
            enc.set_depth(png::BitDepth::Eight);
            let mut w = enc.write_header().unwrap();
            w.write_image_data(&px).unwrap();
        }
        out
    }

    const LINK: &str = "otpauth://totp/Example:alice@example.com?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ&issuer=Example";

    #[test]
    fn decodes_png_in_every_color_type() {
        for mode in [png::ColorType::Grayscale, png::ColorType::GrayscaleAlpha, png::ColorType::Rgb, png::ColorType::Rgba] {
            let texts = decode_image(&qr_png(LINK, 4, mode)).unwrap_or_else(|e| panic!("{mode:?}: {e}"));
            assert_eq!(texts.len(), 1);
            assert_eq!(texts[0].as_str(), LINK);
        }
    }

    #[test]
    fn rejects_non_images_oversize_and_empty() {
        assert_eq!(luma(b"GIF89a....").unwrap_err(), "只支持 PNG 和 JPEG 图片");
        assert!(luma(&vec![0u8; MAX_IMAGE_BYTES + 1]).unwrap_err().contains("太大"));
        // 只有文件头的 PNG / JPEG
        assert_eq!(luma(PNG_MAGIC).unwrap_err(), "PNG 图片已损坏");
        assert_eq!(luma(&[0xff, 0xd8, 0xff, 0xd9]).unwrap_err(), "JPEG 图片已损坏");
        // 一张全白的 PNG：没有二维码
        let mut white = Vec::new();
        {
            let mut enc = png::Encoder::new(&mut white, 64, 64);
            enc.set_color(png::ColorType::Grayscale);
            enc.write_header().unwrap().write_image_data(&[255u8; 64 * 64]).unwrap();
        }
        assert_eq!(decode_image(&white).unwrap_err(), "图片里没有找到二维码");
    }

    #[test]
    fn rejects_huge_dimensions_before_decoding() {
        // 头里声称 5000×5000 的 PNG（数据很少）：不分配大块内存，直接按尺寸拒绝
        let mut out = Vec::new();
        {
            let mut enc = png::Encoder::new(&mut out, 5000, 1);
            enc.set_color(png::ColorType::Grayscale);
            enc.write_header().unwrap().write_image_data(&[255u8; 5000]).unwrap();
        }
        assert!(luma(&out).unwrap_err().contains("尺寸"));
        // 手工拼的 JPEG 头：SOI + SOF0 声称 8000×8000（低熵字节，不含图像数据）
        let mut j = vec![0xff, 0xd8];
        j.extend_from_slice(&[0xff, 0xc0, 0x00, 0x0b, 0x08, 0x1f, 0x40, 0x1f, 0x40, 0x01, 0x01, 0x11, 0x00]);
        j.extend_from_slice(&[0xff, 0xd9]);
        assert!(luma(&j).is_err());
        // 尺寸检查本身
        assert!(check_dims(0, 10).is_err());
        assert!(check_dims(4097, 1).is_err());
        assert!(check_dims(4096, 4096).is_ok());
    }

    #[test]
    fn child_protocol_round_trip() {
        // 成功：输出 texts
        let png = qr_png(LINK, 4, png::ColorType::Grayscale);
        let mut out = Vec::new();
        assert_eq!(child_main(&mut png.as_slice(), &mut out), 0);
        let t = parse_child_output(&out).unwrap();
        assert_eq!(t[0].as_str(), LINK);
        // 失败：输出 error，父进程拿到原因
        let mut out = Vec::new();
        assert_eq!(child_main(&mut &b"not an image"[..], &mut out), 0);
        assert_eq!(parse_child_output(&out).unwrap_err(), "只支持 PNG 和 JPEG 图片");
        // 超过上限的输入
        let big = vec![0u8; MAX_IMAGE_BYTES + 10];
        let mut out = Vec::new();
        child_main(&mut big.as_slice(), &mut out);
        assert!(parse_child_output(&out).unwrap_err().contains("太大"));
        // 子进程崩溃（没有输出）、输出不是 JSON、输出过大
        assert_eq!(parse_child_output(b"").unwrap_err(), "图片无法解码");
        assert_eq!(parse_child_output(b"garbage").unwrap_err(), "图片无法解码");
        assert_eq!(parse_child_output(&vec![b' '; MAX_CHILD_OUTPUT + 1]).unwrap_err(), "图片无法解码");
    }
}
