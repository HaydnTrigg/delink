//! Old "small MSF" PDB container support (PDB 2.00, the Visual C++ 6 era).
//!
//! The `pdb` crate only opens the big MSF 7.00 container. A small MSF holds the
//! same streams, only with 16-bit page numbers and a different header, so it is
//! re-packed here into an in-memory big MSF that the crate can open unchanged.

use anyhow::{anyhow, bail, Result};

const SMALL_MAGIC: &[u8] = b"Microsoft C/C++ program database 2.00\r\n\x1aJG\0\0";
const BIG_MAGIC: &[u8; 32] = b"Microsoft C/C++ MSF 7.00\r\n\x1aDS\0\0\0";
/// Stream size marking a stream that does not exist (as opposed to an empty one).
const NIL_STREAM: u32 = u32::MAX;
const BIG_PAGE_SIZE: usize = 4096;

/// Whether `data` is a small MSF (PDB 2.00) file.
pub fn is_small_msf(data: &[u8]) -> bool {
    data.starts_with(SMALL_MAGIC)
}

/// Re-pack a small MSF file as a big MSF 7.00 file with the same streams.
///
/// The global symbol record stream is the one stream that changes; see
/// [`fix_reference_record_lengths`].
pub fn small_msf_to_big(data: &[u8]) -> Result<Vec<u8>> {
    let mut streams = read_small_msf(data)?;
    if let Some(index) = symbol_records_stream(&streams) {
        if let Some(Some(stream)) = streams.get_mut(index) {
            fix_reference_record_lengths(stream);
        }
    }
    for index in module_symbol_streams(&streams) {
        if let Some(Some(stream)) = streams.get_mut(index) {
            relabel_c11_symbols(stream);
        }
    }
    Ok(write_big_msf(&streams))
}

const CV_SIGNATURE_C11: u32 = 2;
const CV_SIGNATURE_C13: u32 = 4;

/// Let the `pdb` crate read a VC5/VC6 module symbol stream.
///
/// Those streams start with the C11 signature, and the crate refuses anything
/// but C13. The records that follow are the `_ST` kinds (length-prefixed names)
/// that the crate already parses, so only the signature is in the way. The
/// line information that follows the symbols is C11 too, but delink never
/// reads it.
fn relabel_c11_symbols(stream: &mut [u8]) {
    if stream.len() >= 4 && u32_at(stream, 0).ok() == Some(CV_SIGNATURE_C11) {
        stream[..4].copy_from_slice(&CV_SIGNATURE_C13.to_le_bytes());
    }
}

/// Symbol stream index of every module in the DBI module list.
///
/// Each entry is a 64-byte header (the symbol stream index is the `u16` at
/// 0x22) followed by the module and object names, padded to four bytes.
fn module_symbol_streams(streams: &[Option<Vec<u8>>]) -> Vec<usize> {
    let Some(Some(dbi)) = streams.get(3) else {
        return Vec::new();
    };
    if u32_at(dbi, 0).ok() != Some(u32::MAX) {
        return Vec::new();
    }
    let Ok(module_list_size) = u32_at(dbi, 24) else {
        return Vec::new();
    };
    let end = (64 + module_list_size as usize).min(dbi.len());
    let mut off = 64;
    let mut indices = Vec::new();
    while off + 64 <= end {
        if let Ok(index) = u16_at(dbi, off + 0x22) {
            if index != u16::MAX {
                indices.push(index as usize);
            }
        }
        // Skip the two null-terminated names, then align.
        let mut pos = off + 64;
        for _ in 0..2 {
            match dbi[pos..end].iter().position(|&b| b == 0) {
                Some(n) => pos += n + 1,
                None => return indices,
            }
        }
        off = (pos + 3) & !3;
    }
    indices
}

/// Index of the global symbol record stream, from the DBI stream header.
fn symbol_records_stream(streams: &[Option<Vec<u8>>]) -> Option<usize> {
    let dbi = streams.get(3)?.as_ref()?;
    // Only the "new" DBI header (signature -1) names the stream.
    if u32_at(dbi, 0).ok()? != u32::MAX {
        return None;
    }
    Some(u16_at(dbi, 20).ok()? as usize)
}

const S_PROCREF_ST: u16 = 0x0400;
const S_DATAREF_ST: u16 = 0x0401;
const S_LPROCREF_ST: u16 = 0x0403;
/// Record length of a reference without its name: kind, sumName, ibSym, imod, fill.
const REFSYM_LEN: usize = 14;

/// Make VC6 symbol references (`S_PROCREF_ST`, `S_DATAREF_ST`,
/// `S_LPROCREF_ST`) carry their name inside the record.
///
/// VC6 writes the name after the record instead: the record length stops at
/// the module index, and the name follows as a length-prefixed string padded
/// to four bytes. A reader stepping from record to record by length, the `pdb`
/// crate included, then lands inside the name. Growing each length to cover
/// the name and its padding fixes the walk without moving any bytes, so the
/// record offsets the symbol hash tables store stay valid.
fn fix_reference_record_lengths(stream: &mut [u8]) {
    let mut off = 0usize;
    while off + 4 <= stream.len() {
        let len = u16::from_le_bytes([stream[off], stream[off + 1]]) as usize;
        let kind = u16::from_le_bytes([stream[off + 2], stream[off + 3]]);
        let mut next = off + 2 + len;
        if matches!(kind, S_PROCREF_ST | S_DATAREF_ST | S_LPROCREF_ST)
            && len == REFSYM_LEN
            && next < stream.len()
        {
            let name_end = next + 1 + stream[next] as usize;
            let padded = (name_end + 3) & !3;
            if padded <= stream.len() && padded - off - 2 <= u16::MAX as usize {
                let new_len = (padded - off - 2) as u16;
                stream[off..off + 2].copy_from_slice(&new_len.to_le_bytes());
                next = padded;
            }
        }
        off = next;
    }
}

fn u16_at(data: &[u8], off: usize) -> Result<u16> {
    data.get(off..off + 2)
        .map(|b| u16::from_le_bytes(b.try_into().unwrap()))
        .ok_or_else(|| anyhow!("small MSF: read past end at 0x{off:x}"))
}

fn u32_at(data: &[u8], off: usize) -> Result<u32> {
    data.get(off..off + 4)
        .map(|b| u32::from_le_bytes(b.try_into().unwrap()))
        .ok_or_else(|| anyhow!("small MSF: read past end at 0x{off:x}"))
}

/// Small MSF layout:
///
/// ```text
/// 0x00  magic (44 bytes)
/// 0x2C  u32 page size
/// 0x30  u16 free page map page
/// 0x32  u16 page count
/// 0x34  u32 stream directory size, u32 reserved
/// 0x3C  u16 page numbers of the stream directory
/// ```
///
/// The directory is a `u16` stream count, a `u16` reserved, a `(u32 size,
/// u32 reserved)` pair per stream, then each stream's `u16` page numbers.
fn read_small_msf(data: &[u8]) -> Result<Vec<Option<Vec<u8>>>> {
    if !is_small_msf(data) {
        bail!("not a small MSF file");
    }
    let page_size = u32_at(data, 0x2C)? as usize;
    if !page_size.is_power_of_two() || page_size < 0x200 {
        bail!("small MSF: invalid page size {page_size}");
    }

    let read_pages = |pages: &[u16], size: usize| -> Result<Vec<u8>> {
        let mut out = Vec::with_capacity(pages.len() * page_size);
        for &page in pages {
            let start = page as usize * page_size;
            let bytes = data
                .get(start..start + page_size)
                .ok_or_else(|| anyhow!("small MSF: page {page} is past the end of the file"))?;
            out.extend_from_slice(bytes);
        }
        out.truncate(size);
        Ok(out)
    };

    let directory_size = u32_at(data, 0x34)? as usize;
    let directory_pages = (0..directory_size.div_ceil(page_size))
        .map(|i| u16_at(data, 0x3C + 2 * i))
        .collect::<Result<Vec<_>>>()?;
    let directory = read_pages(&directory_pages, directory_size)?;

    let count = u16_at(&directory, 0)? as usize;
    let sizes = (0..count)
        .map(|i| u32_at(&directory, 4 + 8 * i))
        .collect::<Result<Vec<_>>>()?;

    let mut off = 4 + 8 * count;
    let mut streams = Vec::with_capacity(count);
    for size in sizes {
        if size == NIL_STREAM {
            streams.push(None);
            continue;
        }
        let size = size as usize;
        let pages = (0..size.div_ceil(page_size))
            .map(|i| u16_at(&directory, off + 2 * i))
            .collect::<Result<Vec<_>>>()?;
        off += 2 * pages.len();
        streams.push(Some(read_pages(&pages, size)?));
    }
    Ok(streams)
}

/// Big MSF layout: page 0 is the header, pages 1 and 2 the free page maps,
/// then the stream pages, the stream directory pages, and finally the pages
/// listing the directory pages, whose numbers follow the header.
fn write_big_msf(streams: &[Option<Vec<u8>>]) -> Vec<u8> {
    let ps = BIG_PAGE_SIZE;
    let mut pages: Vec<Vec<u8>> = vec![vec![0; ps]; 3];

    let push_pages = |bytes: &[u8], pages: &mut Vec<Vec<u8>>| -> Vec<u32> {
        let mut numbers = Vec::new();
        for chunk in bytes.chunks(ps) {
            numbers.push(pages.len() as u32);
            let mut page = chunk.to_vec();
            page.resize(ps, 0);
            pages.push(page);
        }
        numbers
    };

    let mut directory = Vec::new();
    directory.extend_from_slice(&(streams.len() as u32).to_le_bytes());
    for stream in streams {
        let size = stream.as_ref().map_or(NIL_STREAM, |s| s.len() as u32);
        directory.extend_from_slice(&size.to_le_bytes());
    }
    for stream in streams.iter().flatten() {
        for number in push_pages(stream, &mut pages) {
            directory.extend_from_slice(&number.to_le_bytes());
        }
    }

    let directory_pages: Vec<u8> = push_pages(&directory, &mut pages)
        .iter()
        .flat_map(|n| n.to_le_bytes())
        .collect();
    let directory_map_pages = push_pages(&directory_pages, &mut pages);

    let page_count = pages.len() as u32;
    let header = &mut pages[0];
    header[..32].copy_from_slice(BIG_MAGIC);
    header[32..36].copy_from_slice(&(ps as u32).to_le_bytes());
    header[36..40].copy_from_slice(&1u32.to_le_bytes());
    header[40..44].copy_from_slice(&page_count.to_le_bytes());
    header[44..48].copy_from_slice(&(directory.len() as u32).to_le_bytes());
    for (i, number) in directory_map_pages.iter().enumerate() {
        let at = 52 + 4 * i;
        header[at..at + 4].copy_from_slice(&number.to_le_bytes());
    }

    pages.concat()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Records as the Halo beta (Jan 2002) PDB stores them: an `S_PROCREF_ST`
    /// whose name sits after the record, between two ordinary records.
    #[test]
    fn reference_names_join_their_records() {
        let mut stream = Vec::new();
        stream.extend_from_slice(&hex("0e0003102000000007424f4f4c45414e")); // S_UDT_ST BOOLEAN
        let procref = stream.len();
        stream.extend_from_slice(&hex("0e0000040000000064170000db010000"));
        stream.push(25);
        stream.extend_from_slice(b"XapiValidateDiskPartition");
        stream.extend_from_slice(&[0, 0]);
        let after = stream.len();
        stream.extend_from_slice(&hex("0e000310220000000653495a455f5400")); // S_UDT_ST SIZE_T

        fix_reference_record_lengths(&mut stream);

        let len = u16::from_le_bytes([stream[procref], stream[procref + 1]]) as usize;
        assert_eq!(procref + 2 + len, after);
        // A second pass leaves an already joined record alone.
        let fixed = stream.clone();
        fix_reference_record_lengths(&mut stream);
        assert_eq!(stream, fixed);
    }

    fn hex(s: &str) -> Vec<u8> {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }

    /// Build a small MSF by hand and check every stream survives the round trip.
    #[test]
    fn small_msf_round_trip() {
        let page_size = 0x400usize;
        let streams: Vec<Option<Vec<u8>>> = vec![
            Some(Vec::new()),
            Some((0..100u8).collect()),
            None,
            Some((0..3000u32).map(|i| i as u8).collect()),
        ];

        // Pages: 0 header, 1 free page map, then stream pages, then the directory.
        let mut pages: Vec<Vec<u8>> = vec![vec![0; page_size]; 2];
        let mut stream_pages = Vec::new();
        for stream in streams.iter().flatten() {
            for chunk in stream.chunks(page_size) {
                stream_pages.push(pages.len() as u16);
                let mut page = chunk.to_vec();
                page.resize(page_size, 0);
                pages.push(page);
            }
        }
        let mut directory = Vec::new();
        directory.extend_from_slice(&(streams.len() as u16).to_le_bytes());
        directory.extend_from_slice(&0u16.to_le_bytes());
        for stream in &streams {
            let size = stream.as_ref().map_or(NIL_STREAM, |s| s.len() as u32);
            directory.extend_from_slice(&size.to_le_bytes());
            directory.extend_from_slice(&0u32.to_le_bytes());
        }
        for number in &stream_pages {
            directory.extend_from_slice(&number.to_le_bytes());
        }
        let directory_page = pages.len() as u16;
        let mut page = directory.clone();
        page.resize(page_size, 0);
        pages.push(page);

        let header = &mut pages[0];
        header[..SMALL_MAGIC.len()].copy_from_slice(SMALL_MAGIC);
        header[0x2C..0x30].copy_from_slice(&(page_size as u32).to_le_bytes());
        header[0x30..0x32].copy_from_slice(&1u16.to_le_bytes());
        header[0x34..0x38].copy_from_slice(&(directory.len() as u32).to_le_bytes());
        header[0x3C..0x3E].copy_from_slice(&directory_page.to_le_bytes());
        let small = pages.concat();

        assert!(is_small_msf(&small));
        assert_eq!(read_small_msf(&small).unwrap(), streams);

        let big = write_big_msf(&streams);
        let mut pdb = pdb::PDB::open(std::io::Cursor::new(big)).unwrap();
        for (i, expected) in streams.iter().enumerate() {
            // The crate reports a nil stream as an error rather than `None`.
            let stream = pdb.raw_stream(pdb::StreamIndex(i as u16)).ok().flatten();
            assert_eq!(
                stream.map(|s| s.as_slice().to_vec()),
                *expected,
                "stream {i}"
            );
        }
    }
}
