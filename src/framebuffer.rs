use anyhow::{Result, ensure};

/// Bounded BGRA framebuffer. Whole snapshots may be coalesced; deltas may not.
/// Keeping CopyRect here, rather than forwarding raw RDP orders, preserves
/// correctness when a slow client skips intermediate snapshots.
#[derive(Clone, Debug)]
pub struct Frame {
    pub width: u16,
    pub height: u16,
    pub pixels: Vec<u8>,
}

pub const MAX_PIXELS: usize = 16_777_216;
pub const MAX_DIMENSION: u16 = 8192;

impl Frame {
    pub fn new(width: u16, height: u16) -> Result<Self> {
        let pixels = usize::from(width) * usize::from(height);
        ensure!(width > 0 && height > 0 && width <= MAX_DIMENSION && height <= MAX_DIMENSION
            && pixels <= MAX_PIXELS, "framebuffer exceeds limit (8192 per side, 16 megapixels)");
        Ok(Self { width, height, pixels: vec![0; pixels * 4] })
    }
    pub fn check_rect(&self, x:u16, y:u16, w:u16, h:u16) -> Result<()> {
        ensure!(w > 0 && h > 0 && u32::from(x) + u32::from(w) <= u32::from(self.width)
            && u32::from(y) + u32::from(h) <= u32::from(self.height), "rectangle outside framebuffer");
        Ok(())
    }
    pub fn put(&mut self, x:u16, y:u16, w:u16, h:u16, data:&[u8]) -> Result<()> {
        self.check_rect(x,y,w,h)?;
        let row = usize::from(w)*4;
        ensure!(data.len() == row * usize::from(h), "pixel payload length mismatch");
        for dy in 0..usize::from(h) {
            let start = ((usize::from(y)+dy)*usize::from(self.width)+usize::from(x))*4;
            self.pixels[start..start+row].copy_from_slice(&data[dy*row..(dy+1)*row]);
        }
        Ok(())
    }
    pub fn copy_rect(&mut self, sx:u16, sy:u16, x:u16, y:u16, w:u16, h:u16) -> Result<()> {
        self.check_rect(sx,sy,w,h)?;
        self.check_rect(x,y,w,h)?;
        // memmove per row, reversing rows for downward overlapping copies.
        for n in 0..usize::from(h) {
            let row = if y > sy { usize::from(h)-1-n } else { n };
            let src = ((usize::from(sy)+row)*usize::from(self.width)+usize::from(sx))*4;
            let dst = ((usize::from(y)+row)*usize::from(self.width)+usize::from(x))*4;
            self.pixels.copy_within(src..src+usize::from(w)*4, dst);
        }
        Ok(())
    }
    pub fn fill(&mut self,x:u16,y:u16,w:u16,h:u16,pixel:[u8;4])->Result<()> {
        self.check_rect(x,y,w,h)?;
        for row in y..y+h {
            let start = (usize::from(row)*usize::from(self.width)+usize::from(x))*4;
            for p in self.pixels[start..start+usize::from(w)*4].chunks_exact_mut(4) {
                p.copy_from_slice(&pixel);
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test] fn rejects_zero_and_oversized_frames() {
        assert!(Frame::new(0,1).is_err());
        assert!(Frame::new(65535,65535).is_err());
        assert!(Frame::new(8192,8192).is_err());
    }
    #[test] fn full_width_4k_has_no_8192_byte_row_limit() {
        let mut f=Frame::new(3840,2160).unwrap();
        f.put(0,0,3840,1,&vec![7;3840*4]).unwrap();
        assert_eq!(f.pixels[3840*4-1],7);
    }
    #[test] fn overlapping_copy_preserves_original_pixels() {
        let mut f=Frame::new(4,4).unwrap();
        for (i,p) in f.pixels.chunks_exact_mut(4).enumerate() { p.fill(i as u8); }
        let old=f.clone();
        f.copy_rect(0,0,1,1,3,3).unwrap();
        for y in 0..3 { for x in 0..3 {
            assert_eq!(f.pixels[((y+1)*4+x+1)*4],old.pixels[(y*4+x)*4]);
        }}
    }
    #[test] fn rejects_out_of_bounds_rectangles_and_bad_lengths() {
        let mut f=Frame::new(4,4).unwrap();
        assert!(f.put(65535,0,2,2,&[0;16]).is_err());
        assert!(f.put(0,0,1,1,&[0;3]).is_err());
        assert!(f.copy_rect(0,0,3,3,2,2).is_err());
    }
}
