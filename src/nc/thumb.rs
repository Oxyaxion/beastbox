//! Client thumbnails (`core/preview`) of JPEG photos, computed on request and never stored (§0.3, §0.4, §0.5).
//!
//! `jpeg-decoder` (image-rs, `forbid(unsafe_code)` with `platform_independent`) decodes **directly at 1/2, 1/4 or
//! 1/8 of the size** (scaled IDCT): a 12 Mpx photo never occupies 36 MB. Its own size limit is only checked after
//! decoding, so the dimensions are checked here **before**: a progressive JPEG keeps all its coefficients
//! (≈ 3 bytes per pixel), hence a lower cap. `jpeg-encoder` (`forbid(unsafe_code)` without `simd`) writes the result.

use jpeg_decoder::{CodingProcess, Decoder, PixelFormat};
use std::io::{BufReader, Read};

/// Largest side served; a bigger request gets this size (like Nextcloud's own preview cap).
pub const MAX_SIDE: u16 = 1280;
/// Bytes read from the file at most (the decoder streams; this bounds the CPU spent on one file).
const MAX_BYTES: u64 = 64 * 1024 * 1024;
/// Full image size decoded at most: sequential (memory = the reduced output only) and progressive (≈ 3 bytes/pixel).
const MAX_PIXELS: u64 = 100_000_000;
const MAX_PIXELS_PROGRESSIVE: u64 = 12_000_000;
const QUALITY: u8 = 80;

/// A JPEG thumbnail whose short side is `side` (never enlarged), upright according to the photo's EXIF orientation.
/// `None`: not a JPEG, too big, unsupported (lossless, CMYK, 16 bits) or corrupt.
pub fn make(file: impl Read, side: u16) -> Option<Vec<u8>> {
    let side = side.clamp(1, MAX_SIDE);
    let mut d = Decoder::new(BufReader::new(file.take(MAX_BYTES)));
    d.read_info().ok()?;
    let info = d.info()?;
    let pixels = u64::from(info.width) * u64::from(info.height);
    let cap = match info.coding_process {
        CodingProcess::DctSequential => MAX_PIXELS,
        CodingProcess::DctProgressive => MAX_PIXELS_PROGRESSIVE,
        _ => return None,
    };
    let (channels, color) = match info.pixel_format {
        PixelFormat::L8 => (1, jpeg_encoder::ColorType::Luma),
        PixelFormat::RGB24 => (3, jpeg_encoder::ColorType::Rgb),
        _ => return None,
    };
    if pixels > cap {
        return None;
    }
    // The decoder stops reducing as soon as one axis reaches the request: ask for the size whose short side is `side`.
    let short = u64::from(info.width.min(info.height)).max(1);
    let want = |len: u16| u16::try_from((u64::from(len) * u64::from(side)).div_ceil(short)).unwrap_or(u16::MAX);
    let (w, h) = d.scale(want(info.width), want(info.height)).ok()?;
    let (w, h) = (usize::from(w), usize::from(h));
    d.set_max_decoding_buffer_size(w * h * channels);
    let px = d.decode().ok()?;
    let o = d.exif_data().and_then(orientation).unwrap_or(1);
    let (px, w, h) = shrink(&px, w, h, channels, usize::from(side))?;
    let (px, w, h) = orient(&px, w, h, channels, o)?;
    let mut out = Vec::new();
    jpeg_encoder::Encoder::new(&mut out, QUALITY)
        .encode(&px, u16::try_from(w).ok()?, u16::try_from(h).ok()?, color)
        .ok()?;
    Some(out)
}

/// Area average down to a short side of `side` (never enlarges).
fn shrink(px: &[u8], w: usize, h: usize, c: usize, side: usize) -> Option<(Vec<u8>, usize, usize)> {
    let short = w.min(h);
    if short <= side {
        return Some((px.get(..w * h * c)?.to_vec(), w, h));
    }
    let (nw, nh) = ((w * side / short).max(1), (h * side / short).max(1));
    let span = |i: usize, n: usize, len: usize| (i * len / n, ((i + 1) * len / n).max(i * len / n + 1));
    let mut out = Vec::with_capacity(nw * nh * c);
    for y in 0..nh {
        let (y0, y1) = span(y, nh, h);
        for x in 0..nw {
            let (x0, x1) = span(x, nw, w);
            let n = ((y1 - y0) * (x1 - x0)) as u32;
            for k in 0..c {
                let mut sum = 0u32;
                for sy in y0..y1 {
                    for sx in x0..x1 {
                        sum += u32::from(*px.get((sy * w + sx) * c + k)?);
                    }
                }
                out.push((sum / n) as u8);
            }
        }
    }
    Some((out, nw, nh))
}

/// Applies the EXIF orientation (1–8): the pixels are turned upright, whatever the client does with EXIF.
fn orient(px: &[u8], w: usize, h: usize, c: usize, o: u16) -> Option<(Vec<u8>, usize, usize)> {
    let (nw, nh) = if o >= 5 { (h, w) } else { (w, h) };
    let mut out = Vec::with_capacity(px.len());
    for y in 0..nh {
        for x in 0..nw {
            let (sx, sy) = match o {
                2 => (w - 1 - x, y),
                3 => (w - 1 - x, h - 1 - y),
                4 => (x, h - 1 - y),
                5 => (y, x),
                6 => (y, h - 1 - x),
                7 => (w - 1 - y, h - 1 - x),
                8 => (w - 1 - y, x),
                _ => (x, y),
            };
            let i = (sy * w + sx) * c;
            out.extend_from_slice(px.get(i..i + c)?);
        }
    }
    Some((out, nw, nh))
}

/// EXIF orientation (tag 0x0112 of IFD0) from the TIFF data; every offset is checked, `None` if absent or invalid.
pub fn orientation(t: &[u8]) -> Option<u16> {
    let le = match t.get(..4)? {
        b"II*\0" => true,
        b"MM\0*" => false,
        _ => return None,
    };
    let u16_at = |o: usize| -> Option<u16> {
        let s: [u8; 2] = t.get(o..o.checked_add(2)?)?.try_into().ok()?;
        Some(if le {
            u16::from_le_bytes(s)
        } else {
            u16::from_be_bytes(s)
        })
    };
    let s: [u8; 4] = t.get(4..8)?.try_into().ok()?;
    let ifd0 = usize::try_from(if le {
        u32::from_le_bytes(s)
    } else {
        u32::from_be_bytes(s)
    })
    .ok()?;
    (0..usize::from(u16_at(ifd0)?))
        .map(|k| ifd0.checked_add(2 + 12 * k))
        .find_map(|e| {
            let e = e?;
            (u16_at(e)? == 0x0112).then(|| u16_at(e + 8)).flatten()
        })
        .filter(|o| (1..=8).contains(o))
}

/// Fuzzing entry point (`fuzz/fuzz_targets/thumb.rs`): an arbitrary file never crashes the decoder nor our code
/// (orientation, shrink, rotation), and a result is always a JPEG whose short side is at most the one asked.
#[cfg(feature = "fuzzing")]
#[doc(hidden)]
#[allow(clippy::panic)]
pub fn fuzz(data: &[u8]) {
    let _ = orientation(data);
    if let Some(t) = make(data, 64) {
        let mut d = Decoder::new(t.as_slice());
        let Some(i) = d.read_info().ok().and(d.info()) else {
            panic!("thumbnail not readable");
        };
        if i.width.min(i.height) > 64 {
            panic!("thumbnail too big");
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::indexing_slicing)]
pub(crate) mod tests {
    use super::*;

    /// TIFF data with the orientation in IFD0, in either byte order.
    fn tiff(le: bool, o: u16) -> Vec<u8> {
        let w16 = |v: u16| if le { v.to_le_bytes() } else { v.to_be_bytes() };
        let w32 = |v: u32| if le { v.to_le_bytes() } else { v.to_be_bytes() };
        let mut t = Vec::new();
        t.extend_from_slice(if le { b"II*\0" } else { b"MM\0*" });
        t.extend_from_slice(&w32(8));
        t.extend_from_slice(&w16(1));
        t.extend_from_slice(&w16(0x0112));
        t.extend_from_slice(&w16(3));
        t.extend_from_slice(&w32(1));
        t.extend_from_slice(&w16(o));
        t.extend_from_slice(&[0; 6]);
        t
    }

    /// A real JPEG of `w`×`h` (red on the left half, blue on the right), with an EXIF orientation if not 1.
    pub(crate) fn photo(w: u16, h: u16, o: u16) -> Vec<u8> {
        let mut px = Vec::new();
        for _ in 0..h {
            for x in 0..w {
                let v = if x < w / 2 { 255 } else { 0 };
                px.extend_from_slice(&[v, 0, 255 - v]);
            }
        }
        let mut out = Vec::new();
        let mut e = jpeg_encoder::Encoder::new(&mut out, 90);
        if o != 1 {
            e.add_app_segment(1, [b"Exif\0\0".as_slice(), &tiff(false, o)].concat())
                .unwrap();
        }
        e.encode(&px, w, h, jpeg_encoder::ColorType::Rgb).unwrap();
        out
    }

    pub(crate) fn size(jpeg: &[u8]) -> (u16, u16, Vec<u8>) {
        let mut d = Decoder::new(jpeg);
        let px = d.decode().unwrap();
        let i = d.info().unwrap();
        (i.width, i.height, px)
    }

    #[test]
    fn orientation_both_byte_orders() {
        for le in [true, false] {
            for o in 1..=8 {
                assert_eq!(orientation(&tiff(le, o)), Some(o));
            }
            assert_eq!(orientation(&tiff(le, 9)), None);
        }
        let t = tiff(true, 6);
        for n in 0..t.len() - 6 {
            assert!(orientation(&t[..n]).is_none(), "{n}");
        }
        assert!(orientation(b"II*\0\xff\xff\xff\xff").is_none());
    }

    #[test]
    fn rotations() {
        // 3×2, one byte per pixel: 0 1 2 / 3 4 5.
        let px = [0u8, 1, 2, 3, 4, 5];
        let r = |o| orient(&px, 3, 2, 1, o).unwrap();
        assert_eq!(r(1), (px.to_vec(), 3, 2));
        assert_eq!(r(3), (vec![5, 4, 3, 2, 1, 0], 3, 2));
        // 90° clockwise: the left column (0, 3) becomes the top row, bottom first.
        assert_eq!(r(6), (vec![3, 0, 4, 1, 5, 2], 2, 3));
        assert_eq!(r(8), (vec![2, 5, 1, 4, 0, 3], 2, 3));
        for o in [2, 4, 5, 7] {
            // Mirrors and transpositions: involutions.
            let (a, w, h) = r(o);
            assert_eq!(orient(&a, w, h, 1, o).unwrap().0, px, "{o}");
        }
    }

    #[test]
    fn shrink_averages() {
        let px = [0u8, 255, 100, 100];
        assert_eq!(shrink(&px, 2, 2, 1, 1).unwrap(), (vec![113], 1, 1));
        assert_eq!(shrink(&px, 2, 2, 1, 5).unwrap(), (px.to_vec(), 2, 2));
        assert!(shrink(&px, 3, 3, 1, 1).is_none());
    }

    #[test]
    fn thumbnail_of_a_photo() {
        // 800×400 → short side 100: 200×100.
        let (w, h, _) = size(&make(photo(800, 400, 1).as_slice(), 100).unwrap());
        assert_eq!((w, h), (200, 100));
        // Taken in portrait (orientation 6): served upright, 100×200, red at the top.
        let (w, h, px) = size(&make(photo(800, 400, 6).as_slice(), 100).unwrap());
        assert_eq!((w, h), (100, 200));
        let (top, bottom) = (&px[..3], &px[px.len() - 3..]);
        assert!(
            top[0] > 200 && top[2] < 60 && bottom[0] < 60 && bottom[2] > 200,
            "{top:?} {bottom:?}"
        );
        // Small image: never enlarged; side asked above the cap: capped.
        assert_eq!(size(&make(photo(40, 30, 1).as_slice(), 256).unwrap()).0, 40);
        let (w, h, _) = size(&make(photo(3000, 2000, 1).as_slice(), 4000).unwrap());
        assert_eq!(w.min(h), MAX_SIDE);
    }

    #[test]
    fn refused_inputs() {
        let p = photo(64, 64, 1);
        assert!(make(&b"\x89PNG\r\n\x1a\n"[..], 64).is_none());
        assert!(make(&b""[..], 64).is_none());
        // Truncations: never a panic.
        for n in (0..p.len()).step_by(7) {
            let _ = make(&p[..n], 32);
        }
        // Announced size above the cap (dimensions in the SOF segment): refused before any decoding.
        let mut huge = p.clone();
        let sof = huge.windows(2).position(|w| w == [0xFF, 0xC0]).unwrap();
        huge[sof + 5..sof + 9].copy_from_slice(&[0xFF, 0xFF, 0xFF, 0xFF]);
        assert!(make(huge.as_slice(), 64).is_none());
    }
}
