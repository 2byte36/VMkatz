#![cfg(feature = "sam")]

use std::io::{Read, Seek, SeekFrom};
use std::path::Path;
use vmkatz::disk::DiskImage;
use vmkatz::disk::qcow2::QcowDisk;
use vmkatz::disk::vdi::VdiDisk;

#[test]
fn test_open_qcow2() {
    let path = Path::new("/tmp/test.qcow2");
    if !path.exists() {
        return;
    }
    let mut disk = QcowDisk::open(path).expect("failed to open QCOW2");
    assert_eq!(disk.disk_size(), 85899345920); // 80 GB

    // Read MBR and check signature
    let mut mbr = [0u8; 512];
    disk.read_exact(&mut mbr).expect("failed to read MBR");
    assert_eq!(mbr[510], 0x55);
    assert_eq!(mbr[511], 0xAA);

    // Check NTFS signature at LBA 2048 (byte offset 0x100000)
    disk.seek(SeekFrom::Start(2048 * 512)).unwrap();
    let mut ntfs_hdr = [0u8; 8];
    disk.read_exact(&mut ntfs_hdr).unwrap();
    assert_eq!(&ntfs_hdr[3..8], b"NTFS ");
}

#[test]
fn test_qcow2_sam_extraction() {
    let path = Path::new("/tmp/test.qcow2");
    if !path.exists() {
        return;
    }
    let secrets = vmkatz::sam::extract_disk_secrets(path).expect("SAM extraction failed");
    assert!(!secrets.sam_entries.is_empty(), "should find SAM entries");
    // At minimum, Administrator (RID 500) and Guest (RID 501) should exist
    let admin = secrets.sam_entries.iter().find(|e| e.rid == 500);
    assert!(admin.is_some(), "Administrator account not found");
}

#[test]
fn test_open_base_vdi() {
    let path = Path::new("/home/user/vm/windows10-clean/windows10-clean.vdi");
    if !path.exists() {
        return;
    }
    let mut disk = VdiDisk::open(path).expect("failed to open base VDI");
    assert_eq!(disk.disk_size(), 85899345920); // 80 GB

    // Read MBR and check signature
    let mut mbr = [0u8; 512];
    disk.read_exact(&mut mbr).expect("failed to read MBR");
    assert_eq!(mbr[510], 0x55);
    assert_eq!(mbr[511], 0xAA);

    // Check NTFS signature at LBA 2048 (byte offset 0x100000)
    disk.seek(SeekFrom::Start(2048 * 512)).unwrap();
    let mut ntfs_hdr = [0u8; 8];
    disk.read_exact(&mut ntfs_hdr).unwrap();
    assert_eq!(&ntfs_hdr[3..8], b"NTFS ");
}

#[test]
fn test_open_diff_vdi() {
    let path = Path::new(
        "/home/user/vm/windows10-clean/Snapshots/{29fc354e-2d14-424f-95be-d4f79d10e922}.vdi",
    );
    if !path.exists() {
        return;
    }
    let mut disk = VdiDisk::open(path).expect("failed to open diff VDI");
    assert_eq!(disk.disk_size(), 85899345920);

    // MBR should be readable (from parent via fallthrough)
    let mut mbr = [0u8; 512];
    disk.read_exact(&mut mbr).expect("failed to read MBR");
    assert_eq!(mbr[510], 0x55);
    assert_eq!(mbr[511], 0xAA);
}
