//! rminject — Universal mimalloc injector & runner for Rust / Win32 binaries.
//!
//! Unlike standard `minject` (which only redirects `ucrtbase!malloc`), `rminject`
//! injects `miheap.dll`, which hooks both `KERNEL32!HeapAlloc` (used by Rust's
//! `std::alloc::System` and `/MT` static CRT) and dynamic CRT heap imports,
//! routing them to the active `mimalloc.dll` on PATH.

use std::env;
use std::ffi::OsStr;
use std::fs;
use std::os::windows::ffi::OsStrExt;
use std::path::{Path, PathBuf};
use std::process::{Command, ExitCode};

const MIHEAP_ENV_DLL: &str = "miheap-env.dll";
const MIHEAP_ENV_EXPORT: &str = "MiHeapEnvInit";
const MIHEAP_DLL: &str = "miheap.dll";
const MIHEAP_ENTRY_EXPORT: &str = "MiHeapInstallHooks";
const DEFAULT_MIMALLOC_DIR: &str = r"C:\mimalloc";

const REQUIRED_MIMALLOC_EXPORTS: &[&str] = &[
    "mi_malloc",
    "mi_zalloc",
    "mi_calloc",
    "mi_realloc",
    "mi_rezalloc",
    "mi_recalloc",
    "mi_malloc_aligned",
    "mi_malloc_aligned_at",
    "mi_realloc_aligned",
    "mi_realloc_aligned_at",
    "mi_recalloc_aligned",
    "mi_recalloc_aligned_at",
    "mi_aligned_recalloc",
    "mi_expand",
    "mi_free",
    "mi_usable_size",
    "mi_is_in_heap_region",
    "mi_version",
    "mi_stats_print",
    "mi_heap_new",
    "mi_heap_destroy",
    "mi_heap_malloc",
    "mi_heap_zalloc",
    "mi_heap_realloc",
    "mi_heap_rezalloc",
    "mi_strdup",
    "mi_wcsdup",
    "mi_mbsdup",
    "mi_dupenv_s",
    "mi_wdupenv_s",
    "mi_check_owned",
];

// ---- Minimal Win32 / NT FFI for --inject (in-memory PE64 import injection) ----
#[repr(C)]
struct StartupInfoW {
    cb: u32,
    lp_reserved: *mut u16,
    lp_desktop: *mut u16,
    lp_title: *mut u16,
    dw_x: u32,
    dw_y: u32,
    dw_x_size: u32,
    dw_y_size: u32,
    dw_x_count_chars: u32,
    dw_y_count_chars: u32,
    dw_fill_attribute: u32,
    dw_flags: u32,
    w_show_window: u16,
    cb_reserved2: u16,
    lp_reserved2: *mut u8,
    h_std_input: isize,
    h_std_output: isize,
    h_std_error: isize,
}

#[repr(C)]
struct ProcessInformation {
    h_process: isize,
    h_thread: isize,
    dw_process_id: u32,
    dw_thread_id: u32,
}

#[repr(C)]
struct ProcessBasicInformation {
    reserved1: usize,
    peb_base_address: usize,
    reserved2: [usize; 2],
    unique_process_id: usize,
    reserved3: usize,
}

#[repr(C)]
struct MemoryBasicInformation {
    base_address: usize,
    allocation_base: usize,
    allocation_protect: u32,
    partition_id: u16,
    _pad1: u16,
    region_size: usize,
    state: u32,
    protect: u32,
    mem_type: u32,
    _pad2: u32,
}

type PfnNtQueryInformationProcess = unsafe extern "system" fn(
    process_handle: isize,
    process_information_class: u32,
    process_information: *mut core::ffi::c_void,
    process_information_length: u32,
    return_length: *mut u32,
) -> i32;

#[link(name = "kernel32")]
extern "system" {
    fn CreateProcessW(
        lp_application_name: *const u16,
        lp_command_line: *mut u16,
        lp_process_attributes: *mut core::ffi::c_void,
        lp_thread_attributes: *mut core::ffi::c_void,
        b_inherit_handles: i32,
        dw_creation_flags: u32,
        lp_environment: *mut core::ffi::c_void,
        lp_current_directory: *const u16,
        lp_startup_info: *const StartupInfoW,
        lp_process_information: *mut ProcessInformation,
    ) -> i32;
    fn VirtualAllocEx(
        h_process: isize,
        lp_address: *mut core::ffi::c_void,
        dw_size: usize,
        fl_allocation_type: u32,
        fl_protect: u32,
    ) -> *mut core::ffi::c_void;
    fn VirtualProtectEx(
        h_process: isize,
        lp_address: *mut core::ffi::c_void,
        dw_size: usize,
        fl_new_protect: u32,
        lpfl_old_protect: *mut u32,
    ) -> i32;
    fn VirtualQueryEx(
        h_process: isize,
        lp_address: *const core::ffi::c_void,
        lp_buffer: *mut MemoryBasicInformation,
        dw_length: usize,
    ) -> usize;
    fn ReadProcessMemory(
        h_process: isize,
        lp_base_address: *const core::ffi::c_void,
        lp_buffer: *mut core::ffi::c_void,
        n_size: usize,
        lp_number_of_bytes_read: *mut usize,
    ) -> i32;
    fn WriteProcessMemory(
        h_process: isize,
        lp_base_address: *mut core::ffi::c_void,
        lp_buffer: *const core::ffi::c_void,
        n_size: usize,
        lp_number_of_bytes_written: *mut usize,
    ) -> i32;
    fn GetModuleHandleW(lp_module_name: *const u16) -> isize;
    fn GetProcAddress(h_module: isize, lp_proc_name: *const u8) -> *const core::ffi::c_void;
    fn ResumeThread(h_thread: isize) -> u32;
    fn WaitForSingleObject(h_handle: isize, dw_milliseconds: u32) -> u32;
    fn GetExitCodeProcess(h_process: isize, lp_exit_code: *mut u32) -> i32;
    fn TerminateProcess(h_process: isize, u_exit_code: u32) -> i32;
    fn CloseHandle(h_object: isize) -> i32;
    fn GetLastError() -> u32;
    fn MoveFileExW(lp_existing_file_name: *const u16, lp_new_file_name: *const u16, dw_flags: u32) -> i32;
}

// ---- PE32 / PE64 helpers ----
#[derive(Clone, Debug)]
struct Section {
    vsz: u32,
    va: u32,
    rsz: u32,
    rptr: u32,
}

struct PeInfo {
    machine: u16,
    is_64bit: bool,
    image_base: u64,
    pe_off: usize,
    opt_off: usize,
    nsec: usize,
    sec_align: u32,
    file_align: u32,
    size_of_headers: u32,
    dll_chars: u16,
    dd_off: usize,
    dirs: Vec<(u32, u32)>,
    sec_table_off: usize,
    secs: Vec<Section>,
}

fn read_u16(buf: &[u8], off: usize) -> u16 {
    u16::from_le_bytes(buf[off..off + 2].try_into().unwrap())
}

fn read_u32(buf: &[u8], off: usize) -> u32 {
    u32::from_le_bytes(buf[off..off + 4].try_into().unwrap())
}

fn read_u64(buf: &[u8], off: usize) -> u64 {
    u64::from_le_bytes(buf[off..off + 8].try_into().unwrap())
}

fn write_u16(buf: &mut [u8], off: usize, v: u16) {
    buf[off..off + 2].copy_from_slice(&v.to_le_bytes());
}

fn write_u32(buf: &mut [u8], off: usize, v: u32) {
    buf[off..off + 4].copy_from_slice(&v.to_le_bytes());
}

fn write_u64(buf: &mut [u8], off: usize, v: u64) {
    buf[off..off + 8].copy_from_slice(&v.to_le_bytes());
}

fn align_up(val: usize, align: usize) -> usize {
    (val + align - 1) & !(align - 1)
}

fn align_up_u64(val: u64, align: u64) -> u64 {
    val.saturating_add(align - 1) & !(align - 1)
}

fn parse_pe_any(data: &[u8]) -> Result<PeInfo, String> {
    if data.len() < 0x40 || &data[0..2] != b"MZ" {
        return Err("Not a valid MZ executable".into());
    }
    let pe_off = read_u32(data, 0x3C) as usize;
    if pe_off + 24 > data.len() || &data[pe_off..pe_off + 4] != b"PE\0\0" {
        return Err("Missing PE signature".into());
    }
    let machine = read_u16(data, pe_off + 4);
    let nsec = read_u16(data, pe_off + 6) as usize;
    let opt_sz = read_u16(data, pe_off + 20) as usize;
    let opt_off = pe_off + 24;
    if opt_sz < 2 || opt_off + opt_sz > data.len() {
        return Err("Truncated optional header".into());
    }
    let magic = read_u16(data, opt_off);
    let (is_64bit, image_base, num_rva_off, dd_off) = match magic {
        0x20B => {
            if opt_sz < 112 {
                return Err("Truncated PE32+ optional header".into());
            }
            (true, read_u64(data, opt_off + 24), opt_off + 108, opt_off + 112)
        }
        0x10B => {
            if opt_sz < 96 {
                return Err("Truncated PE32 optional header".into());
            }
            (false, read_u32(data, opt_off + 28) as u64, opt_off + 92, opt_off + 96)
        }
        _ => {
            return Err(format!("Unsupported PE optional header magic=0x{magic:04x}"));
        }
    };
    let sec_align = read_u32(data, opt_off + 32);
    let file_align = read_u32(data, opt_off + 36);
    let size_of_headers = read_u32(data, opt_off + 60);
    let dll_chars = read_u16(data, opt_off + 70);
    let avail_dirs = (opt_off + opt_sz).saturating_sub(dd_off) / 8;
    let num_rva = (read_u32(data, num_rva_off) as usize).min(16).min(avail_dirs);
    let mut dirs = Vec::with_capacity(num_rva);
    for i in 0..num_rva {
        dirs.push((read_u32(data, dd_off + i * 8), read_u32(data, dd_off + i * 8 + 4)));
    }
    let sec_table_off = opt_off + opt_sz;
    if sec_table_off + nsec * 40 > data.len() {
        return Err("Truncated section table".into());
    }
    let mut secs = Vec::with_capacity(nsec);
    for i in 0..nsec {
        let o = sec_table_off + i * 40;
        secs.push(Section {
            vsz: read_u32(data, o + 8),
            va: read_u32(data, o + 12),
            rsz: read_u32(data, o + 16),
            rptr: read_u32(data, o + 20),
        });
    }
    Ok(PeInfo {
        machine,
        is_64bit,
        image_base,
        pe_off,
        opt_off,
        nsec,
        sec_align,
        file_align,
        size_of_headers,
        dll_chars,
        dd_off,
        dirs,
        sec_table_off,
        secs,
    })
}

fn parse_pe(data: &[u8]) -> Result<PeInfo, String> {
    let info = parse_pe_any(data)?;
    if info.machine != 0x8664 {
        return Err(format!(
            "Only x86-64 PE64 is supported (got machine=0x{:04x})",
            info.machine
        ));
    }
    if !info.is_64bit {
        return Err("Only PE32+ (64-bit) is supported".into());
    }
    Ok(info)
}

fn rva_to_off(secs: &[Section], rva: u32) -> Option<usize> {
    for s in secs {
        let span = s.vsz.max(s.rsz);
        if rva >= s.va && rva < s.va.saturating_add(span) {
            return Some((s.rptr + (rva - s.va)) as usize);
        }
    }
    None
}

fn read_cstr(data: &[u8], off: usize) -> Result<String, String> {
    if off >= data.len() {
        return Err("String offset out of bounds".into());
    }
    let end = data[off..]
        .iter()
        .position(|&b| b == 0)
        .ok_or_else(|| "Unterminated C string".to_string())?;
    Ok(String::from_utf8_lossy(&data[off..off + end]).into_owned())
}

#[derive(Debug)]
struct ImportDesc {
    dll: String,
    raw: [u32; 5],
    funcs: Vec<String>,
}

fn read_thunk_names(data: &[u8], info: &PeInfo, thunk_rva: u32) -> Vec<String> {
    let mut funcs = Vec::new();
    if thunk_rva == 0 {
        return funcs;
    }
    let Some(mut toff) = rva_to_off(&info.secs, thunk_rva) else {
        return funcs;
    };
    if info.is_64bit {
        while toff + 8 <= data.len() {
            let val = read_u64(data, toff);
            if val == 0 {
                break;
            }
            if (val & (1u64 << 63)) != 0 {
                funcs.push(format!("ORD#{}", val & 0xFFFF));
            } else if let Some(fno) = rva_to_off(&info.secs, (val & 0x7FFF_FFFF) as u32) {
                if let Ok(name) = read_cstr(data, fno + 2) {
                    funcs.push(name);
                }
            }
            toff += 8;
        }
    } else {
        while toff + 4 <= data.len() {
            let val = read_u32(data, toff);
            if val == 0 {
                break;
            }
            if (val & (1u32 << 31)) != 0 {
                funcs.push(format!("ORD#{}", val & 0xFFFF));
            } else if let Some(fno) = rva_to_off(&info.secs, val & 0x7FFF_FFFF) {
                if let Ok(name) = read_cstr(data, fno + 2) {
                    funcs.push(name);
                }
            }
            toff += 4;
        }
    }
    funcs
}

fn parse_imports(data: &[u8], info: &PeInfo) -> Result<Vec<ImportDesc>, String> {
    if info.dirs.len() < 2 || info.dirs[1].0 == 0 {
        return Ok(Vec::new());
    }
    let mut off = rva_to_off(&info.secs, info.dirs[1].0)
        .ok_or_else(|| format!("Import directory RVA 0x{:x} unmapped", info.dirs[1].0))?;
    let mut out = Vec::new();
    while off + 20 <= data.len() {
        let ilt = read_u32(data, off);
        let ts = read_u32(data, off + 4);
        let fwd = read_u32(data, off + 8);
        let name_rva = read_u32(data, off + 12);
        let iat = read_u32(data, off + 16);
        if ilt == 0 && name_rva == 0 && iat == 0 {
            break;
        }
        let noff = rva_to_off(&info.secs, name_rva)
            .ok_or_else(|| format!("Import DLL name RVA 0x{name_rva:x} unmapped"))?;
        let dll = read_cstr(data, noff)?;
        let thunk_rva = if ilt != 0 { ilt } else { iat };
        let funcs = read_thunk_names(data, info, thunk_rva);
        out.push(ImportDesc {
            dll,
            raw: [ilt, ts, fwd, name_rva, iat],
            funcs,
        });
        off += 20;
    }
    Ok(out)
}

fn parse_delay_imports(data: &[u8], info: &PeInfo) -> Vec<ImportDesc> {
    if info.dirs.len() <= 13 || info.dirs[13].0 == 0 {
        return Vec::new();
    }
    let Some(mut off) = rva_to_off(&info.secs, info.dirs[13].0) else {
        return Vec::new();
    };
    let dir_size = info.dirs[13].1 as usize;
    let mut out = Vec::new();
    let mut idx = 0usize;
    while off + 32 <= data.len() && idx < 4096 {
        if dir_size >= 32 && idx * 32 >= dir_size {
            break;
        }
        let gr_attrs = read_u32(data, off);
        let name_raw = read_u32(data, off + 4);
        let iat_raw = read_u32(data, off + 12);
        let int_raw = read_u32(data, off + 16);
        if name_raw == 0 {
            break;
        }
        let to_rva = |val: u32| -> u32 {
            if val == 0 || (gr_attrs & 1) != 0 {
                val
            } else {
                val.wrapping_sub(info.image_base as u32)
            }
        };
        let name_rva = to_rva(name_raw);
        let int_rva = to_rva(int_raw);
        let iat_rva = to_rva(iat_raw);
        if let Some(noff) = rva_to_off(&info.secs, name_rva) {
            if let Ok(dll) = read_cstr(data, noff) {
                let funcs = read_thunk_names(data, info, int_rva);
                out.push(ImportDesc {
                    dll,
                    raw: [int_rva, 0, 0, name_rva, iat_rva],
                    funcs,
                });
            }
        }
        off += 32;
        idx += 1;
    }
    out
}

fn read_dependent_load_flags(data: &[u8], info: &PeInfo) -> Option<u16> {
    if info.dirs.len() <= 10 || info.dirs[10].0 == 0 {
        return None;
    }
    let lc_off = rva_to_off(&info.secs, info.dirs[10].0)?;
    if info.is_64bit {
        if lc_off + 0x50 <= data.len() && read_u32(data, lc_off) >= 0x50 {
            return Some(read_u16(data, lc_off + 0x4E));
        }
    } else if lc_off + 0x38 <= data.len() && read_u32(data, lc_off) >= 0x38 {
        return Some(read_u16(data, lc_off + 0x36));
    }
    None
}

fn parse_exports(data: &[u8], info: &PeInfo) -> Result<Vec<String>, String> {
    if info.dirs.is_empty() || info.dirs[0].0 == 0 {
        return Ok(Vec::new());
    }
    let eo = rva_to_off(&info.secs, info.dirs[0].0)
        .ok_or_else(|| "Export directory unmapped".to_string())?;
    let n_names = read_u32(data, eo + 24) as usize;
    let addr_names_rva = read_u32(data, eo + 32);
    let no = rva_to_off(&info.secs, addr_names_rva)
        .ok_or_else(|| "Export name table unmapped".to_string())?;
    let mut names = Vec::with_capacity(n_names);
    for i in 0..n_names {
        let nrva = read_u32(data, no + i * 4);
        if let Some(off) = rva_to_off(&info.secs, nrva) {
            if let Ok(s) = read_cstr(data, off) {
                names.push(s);
            }
        }
    }
    Ok(names)
}

fn compute_pe_checksum(data: &[u8], checksum_off: usize) -> u32 {
    let mut sum: u64 = 0;
    let mut i = 0;
    let len = data.len();
    while i + 1 < len {
        if i != checksum_off && i != checksum_off + 2 {
            sum += u16::from_le_bytes([data[i], data[i + 1]]) as u64;
        }
        i += 2;
    }
    if len % 2 == 1 {
        sum += data[len - 1] as u64;
    }
    while sum > 0xFFFF {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    (sum as u32).wrapping_add(len as u32)
}

fn patch_pe(path: &Path, make_backup: bool) -> Result<bool, String> {
    let raw = fs::read(path).map_err(|e| format!("Cannot read {}: {e}", path.display()))?;
    let info = parse_pe(&raw)?;
    let existing = parse_imports(&raw, &info)?;
    let has_env = existing
        .iter()
        .any(|d| d.dll.eq_ignore_ascii_case(MIHEAP_ENV_DLL));
    let has_heap = existing
        .iter()
        .any(|d| d.dll.eq_ignore_ascii_case(MIHEAP_DLL));
    if has_env && has_heap {
        println!(
            "[skip] {} already imports {MIHEAP_ENV_DLL} + {MIHEAP_DLL}",
            path.display()
        );
        return Ok(false);
    }

    // Build list of descriptors to prepend: [miheap-env.dll, miheap.dll] (skipping any already present)
    let mut to_add: Vec<(&str, &str)> = Vec::new();
    if !has_env {
        to_add.push((MIHEAP_ENV_DLL, MIHEAP_ENV_EXPORT));
    }
    if !has_heap {
        to_add.push((MIHEAP_DLL, MIHEAP_ENTRY_EXPORT));
    }

    let new_hdr_off = info.sec_table_off + info.nsec * 40;
    let min_raw = info
        .secs
        .iter()
        .filter(|s| s.rptr > 0)
        .map(|s| s.rptr as usize)
        .min()
        .unwrap_or(info.size_of_headers as usize);
    let hdr_limit = min_raw.min(info.size_of_headers as usize);
    if new_hdr_off + 40 > hdr_limit {
        return Err(format!(
            "No header room in {} for new section header (need {}, avail {})",
            path.display(),
            new_hdr_off + 40,
            hdr_limit
        ));
    }

    let mut buf = raw;
    // Strip trailing Authenticode certificate table if present
    if info.dirs.len() > 4 {
        let (sec_rva, sec_sz) = info.dirs[4];
        if sec_rva != 0 && sec_sz != 0 {
            if (sec_rva as usize).saturating_add(sec_sz as usize) == buf.len() {
                buf.truncate(sec_rva as usize);
            }
            write_u32(&mut buf, info.dd_off + 4 * 8, 0);
            write_u32(&mut buf, info.dd_off + 4 * 8 + 4, 0);
        }
    }
    // Clear Bound Import directory (index 11)
    if info.dirs.len() > 11 {
        write_u32(&mut buf, info.dd_off + 11 * 8, 0);
        write_u32(&mut buf, info.dd_off + 11 * 8 + 4, 0);
    }
    // Clear LoadConfig.DependentLoadFlags (offset 0x4E in IMAGE_LOAD_CONFIG_DIRECTORY64)
    // when set (e.g. /DEPENDENTLOADFLAG:0x800 = LOAD_LIBRARY_SEARCH_SYSTEM32), otherwise
    // Windows refuses to load miheap-env.dll / miheap.dll / mimalloc.dll from PATH.
    if info.dirs.len() > 10 && info.dirs[10].0 != 0 {
        if let Some(lc_off) = rva_to_off(&info.secs, info.dirs[10].0) {
            if lc_off + 0x50 <= buf.len() {
                let lc_size = read_u32(&buf, lc_off);
                let dep_flags = read_u16(&buf, lc_off + 0x4E);
                if lc_size >= 0x50 && dep_flags != 0 {
                    write_u16(&mut buf, lc_off + 0x4E, 0);
                    println!(
                        "[info] cleared LoadConfig.DependentLoadFlags (0x{dep_flags:04x} -> 0x0000) in {}",
                        path.display()
                    );
                }
            }
        }
    }

    let sec_align = info.sec_align as usize;
    let file_align = info.file_align as usize;
    let last_va_end = info
        .secs
        .iter()
        .map(|s| s.va as usize + align_up(s.vsz.max(s.rsz) as usize, sec_align))
        .max()
        .unwrap_or(sec_align);
    let new_va = align_up(last_va_end, sec_align) as u32;
    let new_raw_off = align_up(buf.len(), file_align);
    if new_raw_off > buf.len() {
        buf.resize(new_raw_off, 0);
    }

    // Build .miimp section contents:
    // [new descriptors...] [existing descriptors...] [20-byte null terminator]
    let num_desc = to_add.len() + existing.len();
    let imp_table_sz = (num_desc + 1) * 20;
    let mut cursor = align_up(imp_table_sz, 8);
    let mut layout = Vec::with_capacity(to_add.len());
    for &(dll_name, exp_name) in &to_add {
        let ilt_off = align_up(cursor, 8);
        let iat_off = ilt_off + 16;
        let dll_str_off = iat_off + 16;
        let dll_bytes = format!("{dll_name}\0").into_bytes();
        let ibn_off = align_up(dll_str_off + dll_bytes.len(), 2);
        let mut ibn_bytes = Vec::with_capacity(2 + exp_name.len() + 1);
        ibn_bytes.extend_from_slice(&0u16.to_le_bytes());
        ibn_bytes.extend_from_slice(exp_name.as_bytes());
        ibn_bytes.push(0);
        cursor = ibn_off + ibn_bytes.len();
        layout.push((ilt_off, iat_off, dll_str_off, dll_bytes, ibn_off, ibn_bytes));
    }

    let sec_vsz = cursor;
    let sec_rsz = align_up(sec_vsz, file_align);
    let mut sec_data = vec![0u8; sec_rsz];

    // Write new descriptors 0..to_add.len()
    for (idx, (ilt_off, iat_off, dll_str_off, dll_bytes, ibn_off, ibn_bytes)) in
        layout.iter().enumerate()
    {
        let base = idx * 20;
        write_u32(&mut sec_data, base, new_va + *ilt_off as u32);
        write_u32(&mut sec_data, base + 4, 0);
        write_u32(&mut sec_data, base + 8, 0);
        write_u32(&mut sec_data, base + 12, new_va + *dll_str_off as u32);
        write_u32(&mut sec_data, base + 16, new_va + *iat_off as u32);

        let ibn_rva = (new_va + *ibn_off as u32) as u64;
        write_u64(&mut sec_data, *ilt_off, ibn_rva);
        write_u64(&mut sec_data, *iat_off, ibn_rva);

        sec_data[*dll_str_off..*dll_str_off + dll_bytes.len()].copy_from_slice(dll_bytes);
        sec_data[*ibn_off..*ibn_off + ibn_bytes.len()].copy_from_slice(ibn_bytes);
    }

    // Existing descriptors after the newly prepended ones
    for (i, d) in existing.iter().enumerate() {
        let base = (to_add.len() + i) * 20;
        for (k, &v) in d.raw.iter().enumerate() {
            write_u32(&mut sec_data, base + k * 4, v);
        }
    }

    buf.extend_from_slice(&sec_data);

    // Section header .miimp (READ|WRITE|INITIALIZED_DATA = 0xC0000040)
    let sec_name = if has_heap { b".mienv\0\0" } else { b".miimp\0\0" };
    buf[new_hdr_off..new_hdr_off + 8].copy_from_slice(sec_name);
    write_u32(&mut buf, new_hdr_off + 8, sec_vsz as u32);
    write_u32(&mut buf, new_hdr_off + 12, new_va);
    write_u32(&mut buf, new_hdr_off + 16, sec_rsz as u32);
    write_u32(&mut buf, new_hdr_off + 20, new_raw_off as u32);
    buf[new_hdr_off + 24..new_hdr_off + 36].fill(0);
    write_u32(&mut buf, new_hdr_off + 36, 0xC000_0040);

    // Update PE headers
    let new_size_of_image = align_up(new_va as usize + sec_vsz, sec_align) as u32;
    write_u16(&mut buf, info.pe_off + 6, (info.nsec + 1) as u16);
    write_u32(&mut buf, info.opt_off + 56, new_size_of_image);
    write_u32(&mut buf, info.dd_off + 8, new_va);
    write_u32(&mut buf, info.dd_off + 12, imp_table_sz as u32);

    let checksum_off = info.opt_off + 64;
    let csum = compute_pe_checksum(&buf, checksum_off);
    write_u32(&mut buf, checksum_off, csum);

    if make_backup {
        let bak = backup_path(path);
        if !bak.exists() {
            fs::copy(path, &bak)
                .map_err(|e| format!("Failed creating backup {}: {e}", bak.display()))?;
            println!("[backup] {}", bak.display());
        }
    }

    let tmp = path.with_extension(format!(
        "{}.rminject.tmp",
        path.extension().and_then(|s| s.to_str()).unwrap_or("bin")
    ));
    fs::write(&tmp, &buf).map_err(|e| format!("Cannot write {}: {e}", tmp.display()))?;
    let src_w = to_wide_null(tmp.as_os_str());
    let dst_w = to_wide_null(path.as_os_str());
    const MOVEFILE_REPLACE_EXISTING: u32 = 0x1;
    const MOVEFILE_WRITE_THROUGH: u32 = 0x8;
    let moved = unsafe {
        MoveFileExW(
            src_w.as_ptr(),
            dst_w.as_ptr(),
            MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH,
        )
    };
    if moved == 0 {
        let err = unsafe { GetLastError() };
        let _ = fs::remove_file(&tmp);
        return Err(format!(
            "Cannot replace {} (Win32 error {err}; is the process currently running?)",
            path.display()
        ));
    }

    let added_str: Vec<String> = to_add.iter().map(|(d, e)| format!("{d}!{e}")).collect();
    println!(
        "[ok] patched {} (+{}, VA=0x{new_va:x}, size={} B)",
        path.display(),
        added_str.join(" +"),
        buf.len()
    );
    Ok(true)
}

fn backup_path(path: &Path) -> PathBuf {
    let mut s = path.as_os_str().to_os_string();
    s.push(".bak");
    PathBuf::from(s)
}

fn restore_pe(path: &Path) -> Result<(), String> {
    let bak = backup_path(path);
    if !bak.exists() {
        return Err(format!("Backup not found: {}", bak.display()));
    }
    fs::copy(&bak, path).map_err(|e| format!("Failed restoring {}: {e}", path.display()))?;
    println!("[restored] {} <- {}", path.display(), bak.display());
    Ok(())
}

fn find_on_path(filename: &str) -> Option<PathBuf> {
    let path_var = env::var_os("PATH")?;
    for dir in env::split_paths(&path_var) {
        let cand = dir.join(filename);
        if cand.is_file() {
            return Some(cand);
        }
    }
    None
}

fn active_mimalloc_dir() -> PathBuf {
    let default_dir = PathBuf::from(DEFAULT_MIMALLOC_DIR);
    if default_dir.join(MIHEAP_DLL).is_file() || default_dir.join("mimalloc.dll").is_file() {
        return default_dir;
    }
    if let Some(p) = find_on_path(MIHEAP_DLL).or_else(|| find_on_path("mimalloc.dll")) {
        if let Some(parent) = p.parent() {
            return parent.to_path_buf();
        }
    }
    default_dir
}

fn update_mimalloc(source_spec: &str) -> Result<(), String> {
    let dest_dir = active_mimalloc_dir();
    let dest = dest_dir.join("mimalloc.dll");

    let src = match source_spec {
        "v1" => PathBuf::from(r"C:\mimalloc\out\v1\mimalloc.dll"),
        "v2" => PathBuf::from(r"C:\mimalloc\out\v2\mimalloc.dll"),
        "v3" => PathBuf::from(r"C:\mimalloc\out\v3\mimalloc.dll"),
        "prev" | "rollback" => dest_dir.join("mimalloc.dll.prev"),
        other => PathBuf::from(other),
    };
    if !src.is_file() {
        return Err(format!("mimalloc binary not found: {}", src.display()));
    }
    let data = fs::read(&src).map_err(|e| format!("Cannot read {}: {e}", src.display()))?;
    let info = parse_pe(&data)?;
    let exports = parse_exports(&data, &info)?;
    let missing: Vec<&str> = REQUIRED_MIMALLOC_EXPORTS
        .iter()
        .copied()
        .filter(|req| !exports.iter().any(|e| e == req))
        .collect();
    if !missing.is_empty() {
        return Err(format!(
            "{} is missing required mimalloc exports: {:?}",
            src.display(),
            missing
        ));
    }

    let src_canon = fs::canonicalize(&src).unwrap_or_else(|_| src.clone());
    let dest_canon = fs::canonicalize(&dest).unwrap_or_else(|_| dest.clone());
    if src_canon == dest_canon {
        println!(
            "[ok] {} is already the active mimalloc.dll ({} exports verified)",
            dest.display(),
            exports.len()
        );
        return Ok(());
    }

    let prev = dest_dir.join("mimalloc.dll.prev");
    if dest.exists() {
        // Rename existing DLL out of the way so updates work even if a running app has it mapped.
        let src_w = to_wide_null(dest.as_os_str());
        let prev_w = to_wide_null(prev.as_os_str());
        const MOVEFILE_REPLACE_EXISTING: u32 = 0x1;
        let moved = unsafe { MoveFileExW(src_w.as_ptr(), prev_w.as_ptr(), MOVEFILE_REPLACE_EXISTING) };
        if moved == 0 {
            // If mimalloc.dll.prev itself is still locked by an older process, use a PID-stamped name
            let alt_prev = dest_dir.join(format!("mimalloc.dll.prev.{}", std::process::id()));
            let alt_w = to_wide_null(alt_prev.as_os_str());
            let _ = unsafe { MoveFileExW(src_w.as_ptr(), alt_w.as_ptr(), MOVEFILE_REPLACE_EXISTING) };
        }
    }
    fs::copy(&src, &dest).map_err(|e| {
        format!(
            "Failed updating {} (close apps currently holding mimalloc.dll): {e}",
            dest.display()
        )
    })?;
    println!(
        "[ok] updated active mimalloc.dll: {} -> {} ({} exports verified)",
        src.display(),
        dest.display(),
        exports.len()
    );
    Ok(())
}

struct PeAnalysis {
    arch: String,
    size_bytes: usize,
    signed: bool,
    cfg: bool,
    dependent_load_flags: Option<u16>,
    has_miheap: bool,
    has_miheap_env: bool,
    has_minject: bool,
    delay_imports_count: usize,
    has_heap_alloc: bool,
    has_ntdll_rtl_alloc: bool,
    has_ntdll_heap: bool,
    has_ucrt: bool,
    has_msvcrt: bool,
    has_legacy_crt: bool,
    legacy_crts: Vec<String>,
    custom_allocators: Vec<String>,
    gc_runtimes: Vec<String>,
    sample_imports: Vec<(String, bool)>,
}

fn dll_basename_lower(dll: &str) -> String {
    dll.rsplit(['\\', '/'])
        .next()
        .unwrap_or(dll)
        .to_ascii_lowercase()
}

fn push_unique_ci(vec: &mut Vec<String>, val: &str) {
    if !vec.iter().any(|x| x.eq_ignore_ascii_case(val)) {
        vec.push(val.to_string());
    }
}

fn is_legacy_crt_dll(base_lower: &str) -> bool {
    const PREFIXES: &[&str] = &["msvcr80", "msvcr90", "msvcr100", "msvcr110", "msvcr120"];
    base_lower.ends_with(".dll") && PREFIXES.iter().any(|p| base_lower.starts_with(p))
}

fn is_custom_allocator_dll(base_lower: &str) -> bool {
    matches!(
        base_lower,
        "mimalloc.dll" | "tier0.dll" | "tbbmalloc.dll" | "jemalloc.dll" | "chrome.dll" | "chrome_elf.dll"
    )
}

fn is_gc_runtime_dll(base_lower: &str) -> bool {
    matches!(
        base_lower,
        "jvm.dll" | "coreclr.dll" | "clrjit.dll" | "unityplayer.dll"
    ) || (base_lower.starts_with("mono-") && base_lower.ends_with(".dll"))
}

fn analyze_pe(path: &Path) -> Result<PeAnalysis, String> {
    let data = fs::read(path).map_err(|e| format!("Cannot read {}: {e}", path.display()))?;
    let info = parse_pe_any(&data)?;
    let regular_imports = parse_imports(&data, &info)?;
    let delay_imports = parse_delay_imports(&data, &info);
    let dependent_load_flags = read_dependent_load_flags(&data, &info);

    let arch = match info.machine {
        0x8664 => "x64".to_string(),
        0x014c => "x86".to_string(),
        0xAA64 => "arm64".to_string(),
        other => format!("unknown(0x{other:04x})"),
    };
    let signed = info.dirs.len() > 4 && info.dirs[4].0 != 0 && info.dirs[4].1 > 0;
    let cfg = (info.dll_chars & 0x4000) != 0;

    let mut has_miheap = false;
    let mut has_miheap_env = false;
    let mut has_minject = false;
    let mut has_heap_alloc = false;
    let mut has_ntdll_rtl_alloc = false;
    let mut has_ntdll_heap = false;
    let mut has_ucrt = false;
    let mut has_msvcrt = false;
    let mut legacy_crts = Vec::new();
    let mut custom_allocators = Vec::new();
    let mut gc_runtimes = Vec::new();
    let mut sample_imports = Vec::new();

    for (is_delay, desc) in regular_imports
        .iter()
        .map(|d| (false, d))
        .chain(delay_imports.iter().map(|d| (true, d)))
    {
        if sample_imports.len() < 8 {
            sample_imports.push((desc.dll.clone(), is_delay));
        }
        let base = dll_basename_lower(&desc.dll);
        if base == MIHEAP_DLL {
            has_miheap = true;
        } else if base == MIHEAP_ENV_DLL {
            has_miheap_env = true;
        } else if base == "mimalloc-redirect.dll" {
            has_minject = true;
        }

        if base == "ucrtbase.dll" || base == "ucrtbased.dll" || base.starts_with("api-ms-win-crt-heap-")
        {
            has_ucrt = true;
        } else if base == "msvcrt.dll" {
            has_msvcrt = true;
        } else if is_legacy_crt_dll(&base) {
            push_unique_ci(&mut legacy_crts, &desc.dll);
        }

        if base == "kernel32.dll"
            || base == "kernelbase.dll"
            || base.starts_with("api-ms-win-core-heap-")
        {
            if desc.funcs.iter().any(|f| f == "HeapAlloc") {
                has_heap_alloc = true;
            }
        } else if base == "ntdll.dll" {
            if desc.funcs.iter().any(|f| f == "RtlAllocateHeap") {
                has_ntdll_rtl_alloc = true;
                has_ntdll_heap = true;
            } else if desc.funcs.iter().any(|f| {
                matches!(
                    f.as_str(),
                    "RtlReAllocateHeap" | "RtlFreeHeap" | "RtlSizeHeap"
                )
            }) {
                has_ntdll_heap = true;
            }
        }

        if is_custom_allocator_dll(&base) {
            push_unique_ci(&mut custom_allocators, &desc.dll);
        }
        if is_gc_runtime_dll(&base) {
            push_unique_ci(&mut gc_runtimes, &desc.dll);
        }
    }

    Ok(PeAnalysis {
        arch,
        size_bytes: data.len(),
        signed,
        cfg,
        dependent_load_flags,
        has_miheap,
        has_miheap_env,
        has_minject,
        delay_imports_count: delay_imports.len(),
        has_heap_alloc,
        has_ntdll_rtl_alloc,
        has_ntdll_heap,
        has_ucrt,
        has_msvcrt,
        has_legacy_crt: !legacy_crts.is_empty(),
        legacy_crts,
        custom_allocators,
        gc_runtimes,
        sample_imports,
    })
}

fn classify_pe(a: &PeAnalysis) -> (&'static str, &'static str, String) {
    if a.arch != "x64" {
        return (
            "unsupported_arch",
            "unsupported_arch",
            format!(
                "Unsupported PE architecture ({}); Phase 1-3 supports x64 PE32+ only.",
                a.arch
            ),
        );
    }
    if a.has_miheap {
        return (
            "miheap",
            "already_mimalloc",
            "Already imports miheap.dll (universal mimalloc redirector).".into(),
        );
    }
    if !a.gc_runtimes.is_empty() {
        return (
            "gc_runtime",
            "gc_runtime",
            format!(
                "Managed / GC runtime detected ({}); use runtime-native memory flags.",
                a.gc_runtimes.join(", ")
            ),
        );
    }
    let non_mi_custom: Vec<&str> = a
        .custom_allocators
        .iter()
        .filter(|d| !dll_basename_lower(d).eq("mimalloc.dll"))
        .map(|s| s.as_str())
        .collect();
    if !non_mi_custom.is_empty() {
        return (
            "custom_allocator",
            "custom_allocator",
            format!(
                "Custom allocator detected ({}); non-CRT custom/arena allocators are skipped by rminject.",
                non_mi_custom.join(", ")
            ),
        );
    }
    if a
        .custom_allocators
        .iter()
        .any(|d| dll_basename_lower(d) == "mimalloc.dll")
    {
        return (
            "mimalloc",
            "already_mimalloc",
            "Already imports mimalloc.dll.".into(),
        );
    }
    if a.has_ucrt {
        return (
            "crt_ucrt",
            "eligible",
            "Dynamic UCRT (ucrtbase.dll / api-ms-win-crt-heap); eligible for non-destructive inline CRT hooks.".into(),
        );
    }
    if a.has_msvcrt {
        return (
            "crt_msvcrt",
            "eligible",
            "Dynamic MSVCRT (msvcrt.dll); eligible for non-destructive inline CRT hooks.".into(),
        );
    }
    if a.has_legacy_crt {
        return (
            "crt_legacy",
            "eligible",
            format!(
                "Legacy dynamic MSVC CRT ({}); eligible for non-destructive inline CRT hooks.",
                a.legacy_crts.join(", ")
            ),
        );
    }
    if a.has_heap_alloc || a.has_ntdll_heap {
        return (
            "win32_heap",
            "eligible",
            "Static CRT (/MT) or Rust Win32 HeapAlloc/RtlAllocateHeap; eligible for scoped IAT hooks.".into(),
        );
    }
    (
        "unknown",
        "ineligible",
        "No direct CRT heap or Win32 HeapAlloc imports detected in top-level executable.".into(),
    )
}

fn json_escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 2);
    out.push('"');
    for ch in s.chars() {
        match ch {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

fn show_status(paths: &[String]) -> Result<(), String> {
    let mi_dll = find_on_path("mimalloc.dll");
    let mh_dll = find_on_path(MIHEAP_DLL);
    let me_dll = find_on_path(MIHEAP_ENV_DLL);
    let toml_path = active_mimalloc_dir().join("miheap.toml");
    println!(
        "active mimalloc.dll   : {}",
        mi_dll
            .as_ref()
            .map(|p| p.display().to_string())
            .unwrap_or_else(|| "<NOT FOUND ON PATH>".into())
    );
    println!(
        "active miheap.dll     : {}",
        mh_dll
            .as_ref()
            .map(|p| p.display().to_string())
            .unwrap_or_else(|| "<NOT FOUND ON PATH>".into())
    );
    println!(
        "active miheap-env.dll : {}",
        me_dll
            .as_ref()
            .map(|p| p.display().to_string())
            .unwrap_or_else(|| "<NOT FOUND ON PATH>".into())
    );
    println!(
        "active miheap.toml    : {}",
        if toml_path.is_file() {
            toml_path.display().to_string()
        } else {
            format!("<missing: {}>", toml_path.display())
        }
    );
    for p in paths {
        let path = Path::new(p);
        let a = analyze_pe(path)?;
        let dep_str = match a.dependent_load_flags {
            Some(f) => format!("0x{f:04x}"),
            None => "none".to_string(),
        };
        let heap_alloc_any = a.has_heap_alloc || a.has_ntdll_rtl_alloc;
        let custom_str = if a.custom_allocators.is_empty() {
            "none".to_string()
        } else {
            a.custom_allocators.join(",")
        };
        let gc_str = if a.gc_runtimes.is_empty() {
            "none".to_string()
        } else {
            a.gc_runtimes.join(",")
        };
        println!(
            "\n{} ({} B, arch={}, CFG={}, signed={}, DependentLoadFlags={dep_str})",
            path.display(),
            a.size_bytes,
            a.arch,
            a.cfg,
            a.signed,
        );
        println!(
            "  miheap_env={}  miheap={}  minject={}  delay_imports={}",
            a.has_miheap_env, a.has_miheap, a.has_minject, a.delay_imports_count
        );
        println!(
            "  heap_alloc={}  crt_ucrt={}  crt_msvcrt={}  crt_legacy={}",
            heap_alloc_any, a.has_ucrt, a.has_msvcrt, a.has_legacy_crt
        );
        println!(
            "  custom_allocator={custom_str}  gc_runtime={gc_str}"
        );
        for (idx, (dll, is_delay)) in a.sample_imports.iter().take(5).enumerate() {
            if *is_delay {
                println!("  [{idx}] {dll} [delay]");
            } else {
                println!("  [{idx}] {dll}");
            }
        }
    }
    Ok(())
}

fn cmd_inspect(args: &[String]) -> Result<i32, String> {
    let mut as_json = false;
    let mut target: Option<&str> = None;
    for a in args {
        match a.as_str() {
            "--json" => as_json = true,
            s if s.starts_with('-') => return Err(format!("Unknown inspect flag: {s}")),
            s => {
                if target.is_some() {
                    return Err("Usage: rminject inspect [--json] <binary>".into());
                }
                target = Some(s);
            }
        }
    }
    let Some(t) = target else {
        return Err("Usage: rminject inspect [--json] <binary>".into());
    };
    let path = Path::new(t);
    let a = analyze_pe(path)?;
    let (allocator_kind, eligibility, reason) = classify_pe(&a);
    let dep_hex = format!("0x{:04x}", a.dependent_load_flags.unwrap_or(0));

    if as_json {
        println!(
            "{{\n  \"path\": {},\n  \"arch\": {},\n  \"signed\": {},\n  \"cfg\": {},\n  \"dependent_load_flags\": {},\n  \"has_miheap\": {},\n  \"has_miheap_env\": {},\n  \"allocator_kind\": {},\n  \"eligibility\": {},\n  \"reason\": {},\n  \"imports\": {{ \"heap_alloc\": {}, \"ucrt\": {}, \"msvcrt\": {}, \"legacy_crt\": {}, \"ntdll_heap\": {} }}\n}}",
            json_escape(&path.display().to_string()),
            json_escape(&a.arch),
            a.signed,
            a.cfg,
            json_escape(&dep_hex),
            a.has_miheap,
            a.has_miheap_env,
            json_escape(allocator_kind),
            json_escape(eligibility),
            json_escape(&reason),
            a.has_heap_alloc,
            a.has_ucrt,
            a.has_msvcrt,
            a.has_legacy_crt,
            a.has_ntdll_heap,
        );
    } else {
        println!("path                 : {}", path.display());
        println!("arch                 : {}", a.arch);
        println!("signed               : {}", a.signed);
        println!("cfg                  : {}", a.cfg);
        println!("dependent_load_flags : {dep_hex}");
        println!("has_miheap           : {}", a.has_miheap);
        println!("has_miheap_env       : {}", a.has_miheap_env);
        println!("allocator_kind       : {allocator_kind}");
        println!("eligibility          : {eligibility}");
        println!("reason               : {reason}");
        println!(
            "imports              : heap_alloc={} ucrt={} msvcrt={} legacy_crt={} ntdll_heap={}",
            a.has_heap_alloc, a.has_ucrt, a.has_msvcrt, a.has_legacy_crt, a.has_ntdll_heap
        );
    }
    Ok(0)
}

fn cmd_config(args: &[String]) -> Result<i32, String> {
    let toml_path = active_mimalloc_dir().join("miheap.toml");
    if args.iter().any(|a| a == "--path") {
        println!("{}", toml_path.display());
        return Ok(0);
    }
    if args.iter().any(|a| a == "--edit" || a == "-e") {
        let editor = env::var("EDITOR").unwrap_or_else(|_| "nvim".into());
        let status = Command::new(&editor)
            .arg(&toml_path)
            .status()
            .map_err(|e| format!("Failed launching editor {editor}: {e}"))?;
        return Ok(status.code().unwrap_or(0));
    }
    println!("# Active config: {}", toml_path.display());
    if toml_path.is_file() {
        let content = fs::read_to_string(&toml_path)
            .map_err(|e| format!("Cannot read {}: {e}", toml_path.display()))?;
        print!("{content}");
    } else {
        println!("(not created yet — run build.ps1 -Install or create {})", toml_path.display());
    }
    Ok(0)
}

fn to_wide_null(s: &OsStr) -> Vec<u16> {
    s.encode_wide().chain(std::iter::once(0)).collect()
}

fn quote_win_arg(arg: &str) -> String {
    if !arg.is_empty() && !arg.contains([' ', '\t', '"']) {
        return arg.to_string();
    }
    let mut out = String::from("\"");
    let mut backslashes = 0usize;
    for ch in arg.chars() {
        if ch == '\\' {
            backslashes += 1;
        } else if ch == '"' {
            for _ in 0..backslashes * 2 + 1 {
                out.push('\\');
            }
            out.push('"');
            backslashes = 0;
        } else {
            for _ in 0..backslashes {
                out.push('\\');
            }
            backslashes = 0;
            out.push(ch);
        }
    }
    for _ in 0..backslashes * 2 {
        out.push('\\');
    }
    out.push('"');
    out
}

fn resolve_executable(cmd: &str) -> Result<PathBuf, String> {
    let p = Path::new(cmd);
    let cand = if p.is_file() {
        Some(p.to_path_buf())
    } else if !cmd.to_ascii_lowercase().ends_with(".exe") && Path::new(&format!("{cmd}.exe")).is_file()
    {
        Some(PathBuf::from(format!("{cmd}.exe")))
    } else if let Ok(cwd) = env::current_dir() {
        let in_cwd = cwd.join(cmd);
        if in_cwd.is_file() {
            Some(in_cwd)
        } else {
            let in_cwd_exe = cwd.join(format!("{cmd}.exe"));
            if in_cwd_exe.is_file() {
                Some(in_cwd_exe)
            } else {
                find_on_path(cmd).or_else(|| find_on_path(&format!("{cmd}.exe")))
            }
        }
    } else {
        find_on_path(cmd).or_else(|| find_on_path(&format!("{cmd}.exe")))
    };

    let resolved = cand.ok_or_else(|| format!("Executable not found: {cmd}"))?;
    let abs = if resolved.is_absolute() {
        resolved
    } else {
        env::current_dir()
            .map(|d| d.join(&resolved))
            .unwrap_or(resolved)
    };
    Ok(abs)
}

fn expand_env_vars(raw: &str) -> String {
    let mut out = String::with_capacity(raw.len());
    let bytes = raw.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' {
            if let Some(rel_end) = raw[i + 1..].find('%') {
                let var = &raw[i + 1..i + 1 + rel_end];
                if !var.is_empty() {
                    if let Ok(val) = env::var(var) {
                        out.push_str(&val);
                        i += rel_end + 2;
                        continue;
                    }
                }
            }
        }
        out.push(bytes[i] as char);
        i += 1;
    }
    out
}

fn parse_toml_value(raw: &str) -> String {
    let s = raw.trim_start();
    if let Some(q) = s.chars().next().filter(|&c| c == '"' || c == '\'') {
        let mut out = String::new();
        let mut chars = s[1..].chars();
        while let Some(c) = chars.next() {
            if c == q {
                break;
            }
            if q == '"' && c == '\\' {
                if let Some(esc) = chars.next() {
                    match esc {
                        'n' => out.push('\n'),
                        'r' => out.push('\r'),
                        't' => out.push('\t'),
                        '\\' => out.push('\\'),
                        '"' => out.push('"'),
                        other => out.push(other),
                    }
                }
            } else {
                out.push(c);
            }
        }
        return out;
    }
    let before_comment = s.split('#').next().unwrap_or("");
    before_comment.trim().to_string()
}

fn load_toml_env_for_exe(exe_path: &Path, use_large: bool) -> Vec<(String, String)> {
    let exe_name = exe_path
        .file_name()
        .and_then(|s| s.to_str())
        .unwrap_or("");
    let mut files: Vec<PathBuf> = Vec::new();
    let global = active_mimalloc_dir().join("miheap.toml");
    if global.is_file() {
        files.push(global);
    }
    if let Some(dir) = exe_path.parent() {
        let local = dir.join("miheap.toml");
        if local.is_file() && !files.iter().any(|f| f == &local) {
            files.push(local);
        }
    }
    if let Ok(explicit) = env::var("MIHEAP_CONFIG") {
        let p = PathBuf::from(explicit);
        if p.is_file() {
            files.push(p);
        }
    }

    let mut pairs: Vec<(String, String)> = Vec::new();
    let set_pair = |pairs: &mut Vec<(String, String)>, k: &str, v: String| {
        if let Some(entry) = pairs.iter_mut().find(|(ek, _)| ek.eq_ignore_ascii_case(k)) {
            entry.1 = v;
        } else {
            pairs.push((k.to_string(), v));
        }
    };

    // Pass order guarantees [Settings] -> [Environment] -> [Large] (when --large) -> [Process."<exe>"]
    let mut passes: Vec<u8> = vec![1, 2];
    if use_large {
        passes.push(3);
    }
    passes.push(4);

    for file in files {
        let Ok(text) = fs::read_to_string(&file) else {
            continue;
        };
        for &target_sec in &passes {
            let mut active_sec = 0u8; // 1=settings, 2=env, 3=large, 4=proc_match
            for raw_line in text.lines() {
                let line = raw_line.trim_start_matches('\u{feff}').trim();
                if line.is_empty() || line.starts_with('#') {
                    continue;
                }
                if line.starts_with('[') && line.ends_with(']') {
                    let hdr = line[1..line.len() - 1].trim();
                    if hdr.eq_ignore_ascii_case("Settings") || hdr.eq_ignore_ascii_case("miheap") {
                        active_sec = 1;
                    } else if hdr.eq_ignore_ascii_case("Environment")
                        || hdr.eq_ignore_ascii_case("env")
                        || hdr.eq_ignore_ascii_case("mimalloc")
                    {
                        active_sec = 2;
                    } else if hdr.eq_ignore_ascii_case("Large")
                        || hdr.eq_ignore_ascii_case("LargePages")
                        || hdr.eq_ignore_ascii_case("Huge")
                    {
                        active_sec = 3;
                    } else {
                        let target = hdr
                            .strip_prefix("Process.")
                            .or_else(|| hdr.strip_prefix("process."))
                            .or_else(|| hdr.strip_prefix("App."))
                            .unwrap_or(hdr)
                            .trim_matches(|c| c == '"' || c == '\'');
                        active_sec = if target.eq_ignore_ascii_case(exe_name) {
                            4
                        } else {
                            0
                        };
                    }
                    continue;
                }
                if active_sec != target_sec {
                    continue;
                }
                let Some((k_raw, v_raw)) = line.split_once('=') else {
                    continue;
                };
                let key = k_raw.trim();
                let val = expand_env_vars(&parse_toml_value(v_raw));
                match active_sec {
                    1 => {
                        if key.eq_ignore_ascii_case("spawn_console") {
                            set_pair(&mut pairs, "MIHEAP_CONSOLE", val);
                        } else if key.eq_ignore_ascii_case("console_pause") {
                            set_pair(&mut pairs, "MIHEAP_CONSOLE_PAUSE", val);
                        }
                    }
                    2..=4 => {
                        let mapped = if key.eq_ignore_ascii_case("spawn_console") {
                            "MIHEAP_CONSOLE"
                        } else if key.eq_ignore_ascii_case("console_pause") {
                            "MIHEAP_CONSOLE_PAUSE"
                        } else {
                            key
                        };
                        set_pair(&mut pairs, mapped, val);
                    }
                    _ => {}
                }
            }
        }
    }
    pairs
}

fn binary_has_miheap_env(exe_path: &Path) -> bool {
    let Ok(data) = fs::read(exe_path) else {
        return false;
    };
    let Ok(info) = parse_pe(&data) else {
        return false;
    };
    let Ok(imports) = parse_imports(&data, &info) else {
        return false;
    };
    imports
        .iter()
        .any(|d| d.dll.eq_ignore_ascii_case(MIHEAP_ENV_DLL))
}

struct ChildGuard {
    h_process: isize,
    h_thread: isize,
    armed: bool,
}

impl Drop for ChildGuard {
    fn drop(&mut self) {
        unsafe {
            if self.armed && self.h_process != 0 {
                TerminateProcess(self.h_process, 1);
            }
            if self.h_thread != 0 {
                CloseHandle(self.h_thread);
            }
            if self.h_process != 0 {
                CloseHandle(self.h_process);
            }
        }
    }
}

unsafe fn read_remote_exact(h_process: isize, addr: u64, buf: &mut [u8]) -> Result<(), String> {
    let mut nread = 0usize;
    if ReadProcessMemory(
        h_process,
        addr as *const core::ffi::c_void,
        buf.as_mut_ptr() as *mut core::ffi::c_void,
        buf.len(),
        &mut nread,
    ) == 0
        || nread != buf.len()
    {
        return Err(format!(
            "ReadProcessMemory failed at 0x{addr:016x} ({} B, win32={})",
            buf.len(),
            GetLastError()
        ));
    }
    Ok(())
}

unsafe fn write_remote_exact(h_process: isize, addr: u64, buf: &[u8]) -> Result<(), String> {
    let mut nwritten = 0usize;
    if WriteProcessMemory(
        h_process,
        addr as *mut core::ffi::c_void,
        buf.as_ptr() as *const core::ffi::c_void,
        buf.len(),
        &mut nwritten,
    ) == 0
        || nwritten != buf.len()
    {
        return Err(format!(
            "WriteProcessMemory failed at 0x{addr:016x} ({} B, win32={})",
            buf.len(),
            GetLastError()
        ));
    }
    Ok(())
}

unsafe fn write_remote_protected(h_process: isize, addr: u64, buf: &[u8]) -> Result<(), String> {
    const PAGE_READWRITE: u32 = 0x04;
    let mut old_prot = 0u32;
    if VirtualProtectEx(
        h_process,
        addr as *mut core::ffi::c_void,
        buf.len(),
        PAGE_READWRITE,
        &mut old_prot,
    ) == 0
    {
        return Err(format!(
            "VirtualProtectEx(RW) failed at 0x{addr:016x} ({} B, win32={})",
            buf.len(),
            GetLastError()
        ));
    }
    let write_res = write_remote_exact(h_process, addr, buf);
    let mut dummy = 0u32;
    let _ = VirtualProtectEx(
        h_process,
        addr as *mut core::ffi::c_void,
        buf.len(),
        old_prot,
        &mut dummy,
    );
    write_res
}

unsafe fn read_remote_cstr(h_process: isize, addr: u64) -> Result<String, String> {
    let mut bytes = Vec::with_capacity(64);
    let mut cur = addr;
    while bytes.len() < 512 {
        let page_rem = (0x1000 - (cur & 0xFFF)) as usize;
        let chunk_len = page_rem.min(512 - bytes.len()).min(128);
        let mut chunk = vec![0u8; chunk_len];
        read_remote_exact(h_process, cur, &mut chunk)?;
        if let Some(pos) = chunk.iter().position(|&b| b == 0) {
            bytes.extend_from_slice(&chunk[..pos]);
            return Ok(String::from_utf8_lossy(&bytes).into_owned());
        }
        bytes.extend_from_slice(&chunk);
        cur = cur.saturating_add(chunk_len as u64);
    }
    Err(format!("Unterminated remote C string at 0x{addr:016x}"))
}

unsafe fn query_remote_image_base(h_process: isize) -> Result<u64, String> {
    let ntdll_w = to_wide_null(OsStr::new("ntdll.dll"));
    let ntdll = GetModuleHandleW(ntdll_w.as_ptr());
    if ntdll == 0 {
        return Err("GetModuleHandleW(ntdll.dll) failed".into());
    }
    let proc_ptr = GetProcAddress(ntdll, c"NtQueryInformationProcess".as_ptr().cast());
    if proc_ptr.is_null() {
        return Err("GetProcAddress(NtQueryInformationProcess) failed".into());
    }
    let nt_query: PfnNtQueryInformationProcess = std::mem::transmute(proc_ptr);
    let mut pbi = ProcessBasicInformation {
        reserved1: 0,
        peb_base_address: 0,
        reserved2: [0, 0],
        unique_process_id: 0,
        reserved3: 0,
    };
    let mut ret_len = 0u32;
    let status = nt_query(
        h_process,
        0,
        &mut pbi as *mut _ as *mut core::ffi::c_void,
        std::mem::size_of::<ProcessBasicInformation>() as u32,
        &mut ret_len,
    );
    if status < 0 || pbi.peb_base_address == 0 {
        return Err(format!(
            "NtQueryInformationProcess(ProcessBasicInformation) failed: NTSTATUS=0x{status:08x}"
        ));
    }
    let mut ib_buf = [0u8; 8];
    read_remote_exact(h_process, (pbi.peb_base_address + 0x10) as u64, &mut ib_buf)?;
    let image_base = u64::from_le_bytes(ib_buf);
    if image_base == 0 {
        return Err("Remote PEB ImageBaseAddress is 0".into());
    }
    Ok(image_base)
}

unsafe fn alloc_remote_within_2gb(
    h_process: isize,
    image_base: u64,
    size_of_image: u32,
    alloc_size: usize,
) -> Result<u64, String> {
    const MEM_FREE: u32 = 0x10000;
    const MEM_COMMIT_RESERVE: u32 = 0x3000;
    const PAGE_READWRITE: u32 = 0x04;

    // PE32+ IMAGE_IMPORT_DESCRIPTOR RVAs are unsigned 32-bit offsets above ImageBase.
    // Restrict to [ImageBase + SizeOfImage .. ImageBase + 2 GiB) so every RVA fits cleanly.
    let scan_start = align_up_u64(image_base.saturating_add(size_of_image as u64), 0x10000);
    let max_end = image_base.saturating_add(0x7FFF_FFFF);
    let mut cur = scan_start;

    while cur < max_end {
        let mut mbi = MemoryBasicInformation {
            base_address: 0,
            allocation_base: 0,
            allocation_protect: 0,
            partition_id: 0,
            _pad1: 0,
            region_size: 0,
            state: 0,
            protect: 0,
            mem_type: 0,
            _pad2: 0,
        };
        let q = VirtualQueryEx(
            h_process,
            cur as *const core::ffi::c_void,
            &mut mbi,
            std::mem::size_of::<MemoryBasicInformation>(),
        );
        if q == 0 || mbi.region_size == 0 {
            break;
        }
        let region_end = (mbi.base_address as u64).saturating_add(mbi.region_size as u64);
        if mbi.state == MEM_FREE {
            let mut cand = align_up_u64((mbi.base_address as u64).max(scan_start), 0x10000);
            let limit = region_end.min(max_end);
            while cand.saturating_add(alloc_size as u64) <= limit {
                let remote = VirtualAllocEx(
                    h_process,
                    cand as *mut core::ffi::c_void,
                    alloc_size,
                    MEM_COMMIT_RESERVE,
                    PAGE_READWRITE,
                );
                if !remote.is_null() {
                    let remote_u64 = remote as u64;
                    if remote_u64 >= image_base
                        && remote_u64 - image_base + (alloc_size as u64) <= 0x7FFF_FFFF
                    {
                        return Ok(remote_u64);
                    }
                }
                cand = cand.saturating_add(0x10000);
            }
        }
        let next = align_up_u64(region_end, 0x10000);
        if next <= cur {
            break;
        }
        cur = next;
    }

    Err(format!(
        "Cannot allocate {alloc_size} B remote RW memory within +2 GiB RVA window of ImageBase 0x{image_base:016x} (SizeOfImage=0x{size_of_image:x})"
    ))
}

fn build_child_env_block(overrides: &[(String, String)], ensure_path_dir: Option<&Path>) -> Vec<u16> {
    let mut vars: Vec<(String, String)> = env::vars_os()
        .map(|(k, v)| (k.to_string_lossy().into_owned(), v.to_string_lossy().into_owned()))
        .collect();

    if let Some(dir) = ensure_path_dir {
        let dir_str = dir.to_string_lossy().into_owned();
        let dir_norm = dir_str.trim_end_matches(['\\', '/']).to_ascii_lowercase();
        if let Some((_, path_val)) = vars.iter_mut().find(|(k, _)| k.eq_ignore_ascii_case("PATH")) {
            let already = env::split_paths(OsStr::new(path_val.as_str())).any(|p| {
                p.to_string_lossy()
                    .trim_end_matches(['\\', '/'])
                    .to_ascii_lowercase()
                    == dir_norm
            });
            if !already {
                if path_val.is_empty() {
                    *path_val = dir_str;
                } else {
                    *path_val = format!("{dir_str};{path_val}");
                }
            }
        } else {
            vars.push(("PATH".to_string(), dir_str));
        }
    }

    for (k, v) in overrides {
        if let Some(entry) = vars.iter_mut().find(|(ek, _)| ek.eq_ignore_ascii_case(k)) {
            entry.1 = v.clone();
        } else {
            vars.push((k.clone(), v.clone()));
        }
    }

    vars.sort_by_key(|a| a.0.to_ascii_uppercase());

    let mut block = Vec::new();
    for (k, v) in vars {
        let line = format!("{k}={v}");
        block.extend(OsStr::new(&line).encode_wide());
        block.push(0);
    }
    block.push(0);
    block
}

fn run_with_inmemory_pe_inject(
    exe_path: &Path,
    args: &[String],
    dlls: &[(PathBuf, &str)],
    env_overrides: &[(String, String)],
    mimalloc_dir: &Path,
) -> Result<i32, String> {
    let mut cmdline = quote_win_arg(&exe_path.to_string_lossy());
    for a in args {
        cmdline.push(' ');
        cmdline.push_str(&quote_win_arg(a));
    }
    let app_w = to_wide_null(exe_path.as_os_str());
    let mut cmdline_w = to_wide_null(OsStr::new(&cmdline));
    let mut env_block = build_child_env_block(env_overrides, Some(mimalloc_dir));

    let si = StartupInfoW {
        cb: std::mem::size_of::<StartupInfoW>() as u32,
        lp_reserved: std::ptr::null_mut(),
        lp_desktop: std::ptr::null_mut(),
        lp_title: std::ptr::null_mut(),
        dw_x: 0,
        dw_y: 0,
        dw_x_size: 0,
        dw_y_size: 0,
        dw_x_count_chars: 0,
        dw_y_count_chars: 0,
        dw_fill_attribute: 0,
        dw_flags: 0,
        w_show_window: 0,
        cb_reserved2: 0,
        lp_reserved2: std::ptr::null_mut(),
        h_std_input: 0,
        h_std_output: 0,
        h_std_error: 0,
    };
    let mut pi = ProcessInformation {
        h_process: 0,
        h_thread: 0,
        dw_process_id: 0,
        dw_thread_id: 0,
    };

    const CREATE_SUSPENDED: u32 = 0x4;
    const CREATE_UNICODE_ENVIRONMENT: u32 = 0x0000_0400;
    const INFINITE: u32 = 0xFFFF_FFFF;

    unsafe {
        if CreateProcessW(
            app_w.as_ptr(),
            cmdline_w.as_mut_ptr(),
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            1,
            CREATE_SUSPENDED | CREATE_UNICODE_ENVIRONMENT,
            env_block.as_mut_ptr() as *mut core::ffi::c_void,
            std::ptr::null(),
            &si,
            &mut pi,
        ) == 0
        {
            return Err(format!("CreateProcessW failed: error {}", GetLastError()));
        }

        let mut child = ChildGuard {
            h_process: pi.h_process,
            h_thread: pi.h_thread,
            armed: true,
        };

        let image_base = query_remote_image_base(child.h_process)?;
        let mut hdr = vec![0u8; 0x1000];
        read_remote_exact(child.h_process, image_base, &mut hdr)?;
        if &hdr[0..2] != b"MZ" {
            return Err(format!("Remote image at 0x{image_base:016x} missing MZ header"));
        }
        let pe_off = read_u32(&hdr, 0x3C) as usize;
        if pe_off + 24 > hdr.len() || &hdr[pe_off..pe_off + 4] != b"PE\0\0" {
            return Err(format!("Remote image at 0x{image_base:016x} missing PE signature"));
        }
        let machine = read_u16(&hdr, pe_off + 4);
        if machine != 0x8664 {
            return Err(format!(
                "In-memory PE injection requires x86-64 PE64 (got machine=0x{machine:04x})"
            ));
        }
        let opt_sz = read_u16(&hdr, pe_off + 20) as usize;
        let opt_off = pe_off + 24;
        if opt_off + opt_sz > hdr.len() {
            let need = align_up(opt_off + opt_sz, 0x1000);
            if need > 0x10_0000 {
                return Err("Remote PE optional header exceeds 1 MiB".into());
            }
            hdr.resize(need, 0);
            read_remote_exact(child.h_process, image_base, &mut hdr)?;
        }
        if opt_sz < 112 || read_u16(&hdr, opt_off) != 0x20B {
            return Err("Remote target is not a valid PE32+ (64-bit) image".into());
        }

        let size_of_image = read_u32(&hdr, opt_off + 56);
        let avail_dirs = (opt_off + opt_sz).saturating_sub(opt_off + 112) / 8;
        let num_rva = (read_u32(&hdr, opt_off + 108) as usize).min(16).min(avail_dirs);
        let dd_off = opt_off + 112;
        let read_dir = |idx: usize| -> (u32, u32) {
            if idx < num_rva {
                (read_u32(&hdr, dd_off + idx * 8), read_u32(&hdr, dd_off + idx * 8 + 4))
            } else {
                (0, 0)
            }
        };
        let (imp_rva, _) = read_dir(1);
        let (lc_rva, _) = read_dir(10);
        let (bound_rva, bound_sz) = read_dir(11);

        let mut existing_raw: Vec<[u32; 5]> = Vec::new();
        let mut has_env = false;
        let mut has_heap = false;
        if imp_rva != 0 {
            for idx in 0..4096usize {
                let mut desc = [0u8; 20];
                read_remote_exact(
                    child.h_process,
                    image_base + imp_rva as u64 + (idx * 20) as u64,
                    &mut desc,
                )?;
                let ilt = read_u32(&desc, 0);
                let ts = read_u32(&desc, 4);
                let fwd = read_u32(&desc, 8);
                let name_rva = read_u32(&desc, 12);
                let iat = read_u32(&desc, 16);
                if ilt == 0 && name_rva == 0 && iat == 0 {
                    break;
                }
                if name_rva != 0 {
                    if let Ok(dll_name) = read_remote_cstr(child.h_process, image_base + name_rva as u64)
                    {
                        let base = dll_basename_lower(&dll_name);
                        if base == MIHEAP_ENV_DLL {
                            has_env = true;
                        } else if base == MIHEAP_DLL {
                            has_heap = true;
                        }
                    }
                }
                existing_raw.push([ilt, ts, fwd, name_rva, iat]);
            }
        }

        let mut to_add: Vec<(String, &str)> = Vec::new();
        for (path, exp_name) in dlls {
            let file_name = path
                .file_name()
                .and_then(|s| s.to_str())
                .unwrap_or("")
                .to_string();
            let base = dll_basename_lower(&file_name);
            if (base == MIHEAP_ENV_DLL && has_env) || (base == MIHEAP_DLL && has_heap) {
                continue;
            }
            to_add.push((path.to_string_lossy().into_owned(), *exp_name));
        }

        if !to_add.is_empty() {
            if num_rva <= 1 {
                return Err("Remote PE header has no DataDirectory[IMPORT] slot".into());
            }
            let num_desc = to_add.len() + existing_raw.len();
            let imp_table_sz = (num_desc + 1) * 20;
            let mut cursor = align_up(imp_table_sz, 8);
            let mut layout = Vec::with_capacity(to_add.len());
            for (dll_name, exp_name) in &to_add {
                let ilt_off = align_up(cursor, 8);
                let iat_off = ilt_off + 16;
                let dll_str_off = iat_off + 16;
                let dll_bytes = format!("{dll_name}\0").into_bytes();
                let ibn_off = align_up(dll_str_off + dll_bytes.len(), 2);
                let mut ibn_bytes = Vec::with_capacity(2 + exp_name.len() + 1);
                ibn_bytes.extend_from_slice(&0u16.to_le_bytes());
                ibn_bytes.extend_from_slice(exp_name.as_bytes());
                ibn_bytes.push(0);
                cursor = ibn_off + ibn_bytes.len();
                layout.push((ilt_off, iat_off, dll_str_off, dll_bytes, ibn_off, ibn_bytes));
            }

            let alloc_size = align_up(cursor, 0x1000);
            let remote_addr = alloc_remote_within_2gb(
                child.h_process,
                image_base,
                size_of_image,
                alloc_size,
            )?;
            let new_va = (remote_addr - image_base) as u32;

            let mut payload = vec![0u8; cursor];
            for (idx, (ilt_off, iat_off, dll_str_off, dll_bytes, ibn_off, ibn_bytes)) in
                layout.iter().enumerate()
            {
                let base = idx * 20;
                write_u32(&mut payload, base, new_va + *ilt_off as u32);
                write_u32(&mut payload, base + 4, 0);
                write_u32(&mut payload, base + 8, 0);
                write_u32(&mut payload, base + 12, new_va + *dll_str_off as u32);
                write_u32(&mut payload, base + 16, new_va + *iat_off as u32);

                let ibn_rva = (new_va + *ibn_off as u32) as u64;
                write_u64(&mut payload, *ilt_off, ibn_rva);
                write_u64(&mut payload, *iat_off, ibn_rva);

                payload[*dll_str_off..*dll_str_off + dll_bytes.len()].copy_from_slice(dll_bytes);
                payload[*ibn_off..*ibn_off + ibn_bytes.len()].copy_from_slice(ibn_bytes);
            }

            for (i, raw) in existing_raw.iter().enumerate() {
                let base = (to_add.len() + i) * 20;
                for (k, &v) in raw.iter().enumerate() {
                    write_u32(&mut payload, base + k * 4, v);
                }
            }

            write_remote_exact(child.h_process, remote_addr, &payload)?;

            // Clear BoundImport directory (index 11) in remote PE header if present
            if num_rva > 11 && (bound_rva != 0 || bound_sz != 0) {
                write_remote_protected(
                    child.h_process,
                    image_base + (dd_off + 11 * 8) as u64,
                    &[0u8; 8],
                )?;
            }

            // Clear remote LoadConfig.DependentLoadFlags (offset 0x4E) if non-zero
            if lc_rva != 0 {
                let mut lc_hdr = [0u8; 0x50];
                if read_remote_exact(child.h_process, image_base + lc_rva as u64, &mut lc_hdr).is_ok()
                {
                    let lc_size = read_u32(&lc_hdr, 0);
                    let dep_flags = read_u16(&lc_hdr, 0x4E);
                    if lc_size >= 0x50 && dep_flags != 0 {
                        write_remote_protected(
                            child.h_process,
                            image_base + lc_rva as u64 + 0x4E,
                            &[0u8; 2],
                        )?;
                    }
                }
            }

            // Repoint DataDirectory[IMPORT] to the newly allocated descriptor table
            let mut new_imp_dir = [0u8; 8];
            write_u32(&mut new_imp_dir, 0, new_va);
            write_u32(&mut new_imp_dir, 4, imp_table_sz as u32);
            write_remote_protected(
                child.h_process,
                image_base + (dd_off + 8) as u64,
                &new_imp_dir,
            )?;
        }

        if ResumeThread(child.h_thread) == u32::MAX {
            return Err(format!("ResumeThread failed: error {}", GetLastError()));
        }
        child.armed = false;

        WaitForSingleObject(child.h_process, INFINITE);
        let mut exit_code: u32 = 0;
        GetExitCodeProcess(child.h_process, &mut exit_code);
        Ok(exit_code as i32)
    }
}

fn cmd_run(args: &[String]) -> Result<i32, String> {
    let mut use_large = false;
    let mut no_huge_pages = false;
    let mut verbose = false;
    let mut quiet = false;
    let mut console = false;
    let mut inject = false;
    let mut follow_children = false;
    let mut hook_private_heaps = false;
    let mut log_file: Option<String> = None;
    let mut explicit_envs: Vec<(String, String)> = Vec::new();
    let mut i = 0usize;
    while i < args.len() {
        match args[i].as_str() {
            "--large" | "-l" => {
                use_large = true;
                i += 1;
            }
            "--no-huge-pages" => {
                no_huge_pages = true;
                i += 1;
            }
            "--verbose" | "-v" | "--stats" => {
                verbose = true;
                i += 1;
            }
            "--quiet" | "-q" => {
                quiet = true;
                i += 1;
            }
            "--console" => {
                console = true;
                i += 1;
            }
            "--inject" | "-i" => {
                inject = true;
                i += 1;
            }
            "--follow-children" => {
                follow_children = true;
                i += 1;
            }
            "--hook-private-heaps" => {
                hook_private_heaps = true;
                i += 1;
            }
            "--env" => {
                i += 1;
                if i >= args.len() {
                    return Err("--env requires KEY=VAL".into());
                }
                let Some((k, v)) = args[i].split_once('=') else {
                    return Err(format!("Invalid --env argument (expected KEY=VAL): {}", args[i]));
                };
                if k.is_empty() {
                    return Err("Invalid --env argument: empty key".into());
                }
                explicit_envs.push((k.to_string(), v.to_string()));
                i += 1;
            }
            s if s.starts_with("--env=") => {
                let kv = &s["--env=".len()..];
                let Some((k, v)) = kv.split_once('=') else {
                    return Err(format!("Invalid --env argument (expected KEY=VAL): {s}"));
                };
                if k.is_empty() {
                    return Err("Invalid --env argument: empty key".into());
                }
                explicit_envs.push((k.to_string(), v.to_string()));
                i += 1;
            }
            "--log-file" => {
                i += 1;
                if i >= args.len() {
                    return Err("--log-file requires a path".into());
                }
                log_file = Some(args[i].clone());
                i += 1;
            }
            "--" => {
                i += 1;
                break;
            }
            s if s.starts_with('-') => {
                return Err(format!("Unknown run flag: {s}"));
            }
            _ => break,
        }
    }
    if i >= args.len() {
        return Err("Usage: rminject run [flags] <command> [args...]".into());
    }
    let exe_path = resolve_executable(&args[i])?;
    let rest = &args[i + 1..];

    // Settings come from miheap.toml (never hardcoded in rminject.exe).
    // For binaries patched with miheap-env.dll, miheap-env.dll loads miheap.toml
    // natively at startup (including for subprocesses), so we only pass explicit
    // CLI overrides here (such as MIHEAP_LARGE=1 for --large, which enables [Large]
    // while still letting [Process."<exe>"] override it!).
    let mut overrides: Vec<(String, String)> = Vec::new();
    let has_env_dll = !inject && binary_has_miheap_env(&exe_path);
    if !has_env_dll {
        overrides = load_toml_env_for_exe(&exe_path, use_large);
    }

    let set_override = |vec: &mut Vec<(String, String)>, k: &str, v: &str| {
        if let Some(e) = vec.iter_mut().find(|(ek, _)| ek.eq_ignore_ascii_case(k)) {
            e.1 = v.to_string();
        } else {
            vec.push((k.to_string(), v.to_string()));
        }
    };

    if use_large {
        set_override(&mut overrides, "MIHEAP_LARGE", "1");
    }
    if no_huge_pages {
        set_override(&mut overrides, "MIHEAP_LARGE", "0");
        set_override(&mut overrides, "MIMALLOC_RESERVE_HUGE_OS_PAGES", "0");
        set_override(&mut overrides, "MIMALLOC_ALLOW_LARGE_OS_PAGES", "0");
    }
    if verbose {
        set_override(&mut overrides, "MIMALLOC_VERBOSE", "1");
        set_override(&mut overrides, "MIMALLOC_SHOW_STATS", "1");
        set_override(&mut overrides, "MIHEAP_LOG", "1");
    }
    if quiet {
        set_override(&mut overrides, "MIMALLOC_VERBOSE", "0");
        set_override(&mut overrides, "MIMALLOC_SHOW_STATS", "0");
        set_override(&mut overrides, "MIHEAP_QUIET", "1");
    }
    if console {
        set_override(&mut overrides, "MIHEAP_CONSOLE", "1");
    }
    if follow_children {
        set_override(&mut overrides, "MIHEAP_FOLLOW_CHILDREN", "1");
    }
    if hook_private_heaps {
        set_override(&mut overrides, "MIHEAP_HOOK_PRIVATE_HEAPS", "1");
    }
    if let Some(lf) = log_file {
        set_override(&mut overrides, "MIHEAP_LOG", "1");
        set_override(&mut overrides, "MIHEAP_LOG_FILE", &lf);
    }
    for (k, v) in explicit_envs {
        set_override(&mut overrides, &k, &v);
    }

    if inject {
        let dir = active_mimalloc_dir();
        let env_dll = dir.join(MIHEAP_ENV_DLL);
        let heap_dll = dir.join(MIHEAP_DLL);
        if !heap_dll.is_file() {
            return Err(format!("{MIHEAP_DLL} not found in {}", dir.display()));
        }
        let mut dlls: Vec<(PathBuf, &str)> = Vec::new();
        if env_dll.is_file() {
            dlls.push((env_dll, MIHEAP_ENV_EXPORT));
        }
        dlls.push((heap_dll, MIHEAP_ENTRY_EXPORT));
        return run_with_inmemory_pe_inject(&exe_path, rest, &dlls, &overrides, &dir);
    }

    let mut child = Command::new(&exe_path);
    child.args(rest);
    for (k, v) in &overrides {
        child.env(k, v);
    }
    let status = child
        .status()
        .map_err(|e| format!("Failed launching {}: {e}", exe_path.display()))?;
    Ok(status.code().unwrap_or(1))
}

fn print_usage() {
    eprintln!(
        "rminject — Universal mimalloc injector & TOML-driven runner for Rust / Win32 binaries

USAGE:
  rminject patch [--no-backup] <binary.exe|dll...>   Inject miheap-env.dll + miheap.dll into x64 PEs
  rminject <binary.exe|dll>                          Shorthand for `rminject patch <binary>`
  rminject restore <binary.exe|dll...>               Restore from .bak backup(s)
  rminject status [binary.exe|dll...]                Show active DLLs, config & PE hook status
  rminject inspect [--json] <binary.exe|dll>         Inspect PE allocator linkage & eligibility
  rminject config [--path | --edit]                  Show or edit global C:\\mimalloc\\miheap.toml
  rminject update-mimalloc <v1|v2|v3|path.dll>       Replace active C:\\mimalloc\\mimalloc.dll
  rminject run [OPTIONS] <cmd> [args...]             Run binary (resolves CWD & PATH) using miheap.toml

RUN OPTIONS (optional overrides on top of miheap.toml):
  --large, -l              Activate [Large] section from miheap.toml (still applies [Process] overrides)
  --inject, -i             In-memory PE import-table inject miheap-env + miheap without modifying binary on disk
  --follow-children        Set MIHEAP_FOLLOW_CHILDREN=1 for child process propagation
  --hook-private-heaps     Set MIHEAP_HOOK_PRIVATE_HEAPS=1 to back HeapCreate heaps with mimalloc
  --env KEY=VAL            Override an environment variable (repeatable, e.g. --env MIMALLOC_RESERVE_HUGE_OS_PAGES=3)
  --verbose, -v            Enable MIMALLOC_VERBOSE=1, MIMALLOC_SHOW_STATS=1, MIHEAP_LOG=1
  --console                Spawn a separate console window for stdout/stderr/mimalloc output
  --log-file <path>        Also write [miheap] logs to a file
  --no-huge-pages          Disable large/huge OS pages
  --quiet, -q              Suppress verbose/stats output"
    );
}

fn dispatch(args: &[String]) -> Result<i32, String> {
    match args[0].as_str() {
        "patch" | "-i" => {
            let mut backup = true;
            let mut targets = Vec::new();
            for a in &args[1..] {
                if a == "--no-backup" {
                    backup = false;
                } else {
                    targets.push(a);
                }
            }
            if targets.is_empty() {
                Err("No target binary specified".into())
            } else {
                for t in targets {
                    patch_pe(Path::new(t), backup)?;
                }
                Ok(0)
            }
        }
        "restore" => {
            if args.len() < 2 {
                Err("No target binary specified".into())
            } else {
                for t in &args[1..] {
                    restore_pe(Path::new(t))?;
                }
                Ok(0)
            }
        }
        "status" | "verify" => {
            show_status(&args[1..])?;
            Ok(0)
        }
        "inspect" => cmd_inspect(&args[1..]),
        "config" => cmd_config(&args[1..]),
        "update-mimalloc" | "set-mimalloc" => {
            if args.len() != 2 {
                Err("Usage: rminject update-mimalloc <v1|v2|v3|path/to/mimalloc.dll>".into())
            } else {
                update_mimalloc(&args[1])?;
                Ok(0)
            }
        }
        "run" => cmd_run(&args[1..]),
        other => {
            if Path::new(other).is_file() {
                for t in args {
                    patch_pe(Path::new(t), true)?;
                }
                Ok(0)
            } else {
                Err(format!("Unknown subcommand or missing file: {other}"))
            }
        }
    }
}

fn main() -> ExitCode {
    let args: Vec<String> = env::args().skip(1).collect();
    if args.is_empty() || matches!(args[0].as_str(), "-h" | "--help" | "help") {
        print_usage();
        return ExitCode::SUCCESS;
    }

    match dispatch(&args) {
        Ok(code) => ExitCode::from((code & 0xFF) as u8),
        Err(msg) => {
            eprintln!("error: {msg}");
            ExitCode::FAILURE
        }
    }
}
