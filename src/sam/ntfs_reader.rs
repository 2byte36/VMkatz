use std::io::{Read, Seek};

use ntfs::NtfsReadSeek;

use crate::error::Result;
use super::ntfs_fallback;

/// Wraps a Read+Seek with a partition offset.
pub(crate) struct PartitionReader<'a, R: Read + Seek> {
    inner: &'a mut R,
    offset: u64,
}

impl<'a, R: Read + Seek> PartitionReader<'a, R> {
    pub(crate) fn new(inner: &'a mut R, offset: u64) -> Self {
        Self { inner, offset }
    }

    /// Access the underlying reader (for fallback paths that manage offsets themselves).
    fn inner_mut(&mut self) -> &mut R {
        self.inner
    }
}

impl<R: Read + Seek> Read for PartitionReader<'_, R> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        self.inner.read(buf)
    }
}

impl<R: Read + Seek> Seek for PartitionReader<'_, R> {
    fn seek(&mut self, pos: std::io::SeekFrom) -> std::io::Result<u64> {
        match pos {
            std::io::SeekFrom::Start(offset) => {
                let actual = self
                    .inner
                    .seek(std::io::SeekFrom::Start(self.offset + offset))?;
                Ok(actual - self.offset)
            }
            std::io::SeekFrom::Current(delta) => {
                let actual = self.inner.seek(std::io::SeekFrom::Current(delta))?;
                Ok(actual.saturating_sub(self.offset))
            }
            std::io::SeekFrom::End(delta) => {
                let actual = self.inner.seek(std::io::SeekFrom::End(delta))?;
                Ok(actual.saturating_sub(self.offset))
            }
        }
    }
}

/// Find a directory entry by name (case-insensitive).
pub(crate) fn find_entry<'n, R: Read + Seek>(
    ntfs: &'n ntfs::Ntfs,
    dir: &ntfs::NtfsFile<'n>,
    reader: &mut R,
    name: &str,
) -> Result<ntfs::NtfsFile<'n>> {
    let index = dir.directory_index(reader).map_err(|e| {
        crate::error::VmkatzError::DecryptionError(format!(
            "Directory index error for '{}': {}",
            name, e
        ))
    })?;
    let mut iter = index.entries();
    while let Some(entry) = iter.next(reader) {
        let entry = entry.map_err(|e| {
            crate::error::VmkatzError::DecryptionError(format!("Dir entry error: {}", e))
        })?;
        // key() returns Option<Result<NtfsFileName>>
        let key = match entry.key() {
            Some(Ok(k)) => k,
            Some(Err(e)) => {
                log::warn!("Index key error: {}", e);
                continue;
            }
            None => continue, // Last entry sentinel, no key
        };
        if key.name().to_string_lossy().eq_ignore_ascii_case(name) {
            let file = entry.to_file(ntfs, reader).map_err(|e| {
                crate::error::VmkatzError::DecryptionError(format!(
                    "Failed to open '{}': {}",
                    name, e
                ))
            })?;
            return Ok(file);
        }
    }
    Err(crate::error::VmkatzError::DiskFormatError(format!(
        "NTFS entry '{}' not found",
        name
    )))
}

/// Read file data ($DATA attribute) into a Vec<u8>.
pub(crate) fn read_file_data<R: Read + Seek>(
    file: &ntfs::NtfsFile,
    reader: &mut R,
) -> Result<Vec<u8>> {
    let data_item = file
        .data(reader, "")
        .ok_or_else(|| {
            crate::error::VmkatzError::DecryptionError("No $DATA attribute".to_string())
        })?
        .map_err(|e| crate::error::VmkatzError::DecryptionError(format!("$DATA error: {}", e)))?;
    let data_attr = data_item.to_attribute().map_err(|e| {
        crate::error::VmkatzError::DecryptionError(format!("to_attribute error: {}", e))
    })?;
    let mut data_value = data_attr.value(reader).map_err(|e| {
        crate::error::VmkatzError::DecryptionError(format!("Attribute value error: {}", e))
    })?;
    let len = data_value.len();
    let mut buf = vec![0u8; len as usize];
    data_value.read_exact(reader, &mut buf).map_err(|e| {
        crate::error::VmkatzError::DecryptionError(format!("Read file data error: {}", e))
    })?;
    Ok(buf)
}

/// List all file/directory names in a directory.
pub(crate) fn list_directory<'n, R: Read + Seek>(
    _ntfs: &'n ntfs::Ntfs,
    dir: &ntfs::NtfsFile<'n>,
    reader: &mut R,
) -> Result<Vec<(String, bool)>> {
    let index = dir.directory_index(reader).map_err(|e| {
        crate::error::VmkatzError::DecryptionError(format!("Directory index error: {}", e))
    })?;
    let mut entries = Vec::new();
    let mut seen = std::collections::HashSet::new();
    let mut iter = index.entries();
    while let Some(entry) = iter.next(reader) {
        let entry = match entry {
            Ok(e) => e,
            Err(_) => continue,
        };
        let key = match entry.key() {
            Some(Ok(k)) => k,
            _ => continue,
        };
        let name = key.name().to_string_lossy().to_string();
        // Skip NTFS special entries and dedup (NTFS may list WIN8.3 short + long names)
        if name == "." || name == ".." || name.starts_with('$') {
            continue;
        }
        let is_dir = key.is_directory();
        if seen.insert(name.to_lowercase()) {
            entries.push((name, is_dir));
        }
    }
    Ok(entries)
}

/// Navigate to a directory by path components.
pub(crate) fn navigate_to_dir<'n, R: Read + Seek>(
    ntfs: &'n ntfs::Ntfs,
    root: &ntfs::NtfsFile<'n>,
    reader: &mut R,
    path: &str,
) -> Result<ntfs::NtfsFile<'n>> {
    let components: Vec<&str> = path
        .split(['\\', '/'])
        .filter(|s| !s.is_empty())
        .collect();
    let mut current = root.clone();
    for &component in &components {
        current = find_entry(ntfs, &current, reader, component)?;
    }
    Ok(current)
}

/// Read SAM, SYSTEM, and (optionally) SECURITY hive files from NTFS filesystem.
pub(super) fn read_hive_files<R: Read + Seek>(
    reader: &mut R,
    partition_offset: u64,
) -> Result<super::HiveFiles> {
    // Wrap reader with partition offset
    let mut part_reader = PartitionReader::new(reader, partition_offset);

    let ntfs = match ntfs::Ntfs::new(&mut part_reader) {
        Ok(n) => n,
        Err(e) => {
            log::info!("NTFS parse error: {}, trying MFTMirr fallback", e);
            return ntfs_fallback::try_mftmirr_fallback(part_reader.inner_mut(), partition_offset);
        }
    };

    match ntfs.root_directory(&mut part_reader) {
        Ok(root) => {
            // Navigate: Windows/System32/config/
            let windows = find_entry(&ntfs, &root, &mut part_reader, "Windows")?;
            let system32 = find_entry(&ntfs, &windows, &mut part_reader, "System32")?;
            let config = find_entry(&ntfs, &system32, &mut part_reader, "config")?;

            let sam_file = find_entry(&ntfs, &config, &mut part_reader, "SAM")?;
            let system_file = find_entry(&ntfs, &config, &mut part_reader, "SYSTEM")?;

            let sam_data = read_file_data(&sam_file, &mut part_reader)?;
            let system_data = read_file_data(&system_file, &mut part_reader)?;

            // SECURITY hive is optional - not all disk images may have it accessible
            let security_data = find_entry(&ntfs, &config, &mut part_reader, "SECURITY")
                .ok()
                .and_then(|f| read_file_data(&f, &mut part_reader).ok());

            Ok((sam_data, system_data, security_data))
        }
        Err(e) => {
            log::info!("NTFS root dir error: {}, trying MFTMirr fallback", e,);
            // Drop ntfs/part_reader borrows, then use MFTMirr fallback
            drop(ntfs);
            ntfs_fallback::try_mftmirr_fallback(part_reader.inner_mut(), partition_offset)
        }
    }
}

/// Read NTDS.dit + SYSTEM hive from NTFS filesystem.
pub(super) fn read_ntds_artifacts<R: Read + Seek>(
    reader: &mut R,
    partition_offset: u64,
) -> Result<(Vec<u8>, Vec<u8>)> {
    let mut part_reader = PartitionReader::new(reader, partition_offset);

    let ntfs = ntfs::Ntfs::new(&mut part_reader).map_err(|e| {
        crate::error::VmkatzError::DecryptionError(format!("NTFS parse error: {}", e))
    })?;

    let root = ntfs.root_directory(&mut part_reader).map_err(|e| {
        crate::error::VmkatzError::DecryptionError(format!("NTFS root dir error: {}", e))
    })?;

    let windows = find_entry(&ntfs, &root, &mut part_reader, "Windows")?;

    let ntds_dir = find_entry(&ntfs, &windows, &mut part_reader, "NTDS")?;
    let ntds_file = find_entry(&ntfs, &ntds_dir, &mut part_reader, "ntds.dit")?;
    let ntds_data = read_file_data(&ntds_file, &mut part_reader)?;

    let system32 = find_entry(&ntfs, &windows, &mut part_reader, "System32")?;
    let config = find_entry(&ntfs, &system32, &mut part_reader, "config")?;
    let system_file = find_entry(&ntfs, &config, &mut part_reader, "SYSTEM")?;
    let system_data = read_file_data(&system_file, &mut part_reader)?;

    Ok((ntds_data, system_data))
}
