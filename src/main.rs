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
    "mi_malloc_aligned",
    "mi_realloc_aligned",
    "mi_expand",
    "mi_free",
    "mi_usable_size",
    "mi_is_in_heap_region",
    "mi_version",
    "mi_stats_print",
];

// ---- Minimal Win32 FFI for --inject (early-bird CREATE_SUSPENDED APC) ----
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
    fn WriteProcessMemory(
        h_process: isize,
        lp_base_address: *mut core::ffi::c_void,
        lp_buffer: *const core::ffi::c_void,
        n_size: usize,
        lp_number_of_bytes_written: *mut usize,
    ) -> i32;
    fn GetModuleHandleW(lp_module_name: *const u16) -> isize;
    fn GetProcAddress(h_module: isize, lp_proc_name: *const u8) -> *const core::ffi::c_void;
    fn QueueUserAPC(
        pfn_apc: *const core::ffi::c_void,
        h_thread: isize,
        dw_data: usize,
    ) -> u32;
    fn ResumeThread(h_thread: isize) -> u32;
    fn WaitForSingleObject(h_handle: isize, dw_milliseconds: u32) -> u32;
    fn GetExitCodeProcess(h_process: isize, lp_exit_code: *mut u32) -> i32;
    fn TerminateProcess(h_process: isize, u_exit_code: u32) -> i32;
    fn CloseHandle(h_object: isize) -> i32;
    fn GetLastError() -> u32;
    fn MoveFileExW(lp_existing_file_name: *const u16, lp_new_file_name: *const u16, dw_flags: u32) -> i32;
}

// ---- PE64 helpers ----
#[derive(Clone, Debug)]
struct Section {
    vsz: u32,
    va: u32,
    rsz: u32,
    rptr: u32,
}

struct PeInfo {
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

fn parse_pe(data: &[u8]) -> Result<PeInfo, String> {
    if data.len() < 0x40 || &data[0..2] != b"MZ" {
        return Err("Not a valid MZ executable".into());
    }
    let pe_off = read_u32(data, 0x3C) as usize;
    if pe_off + 24 > data.len() || &data[pe_off..pe_off + 4] != b"PE\0\0" {
        return Err("Missing PE signature".into());
    }
    let machine = read_u16(data, pe_off + 4);
    if machine != 0x8664 {
        return Err(format!("Only x86-64 PE64 is supported (got machine=0x{machine:04x})"));
    }
    let nsec = read_u16(data, pe_off + 6) as usize;
    let opt_sz = read_u16(data, pe_off + 20) as usize;
    let opt_off = pe_off + 24;
    if opt_off + opt_sz > data.len() {
        return Err("Truncated optional header".into());
    }
    let magic = read_u16(data, opt_off);
    if magic != 0x20B {
        return Err(format!("Only PE32+ (64-bit) is supported (got magic=0x{magic:04x})"));
    }
    let sec_align = read_u32(data, opt_off + 32);
    let file_align = read_u32(data, opt_off + 36);
    let size_of_headers = read_u32(data, opt_off + 60);
    let dll_chars = read_u16(data, opt_off + 70);
    let num_rva = (read_u32(data, opt_off + 108) as usize).min(16);
    let dd_off = opt_off + 112;
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
        let mut funcs = Vec::new();
        let thunk_rva = if ilt != 0 { ilt } else { iat };
        if let Some(mut toff) = rva_to_off(&info.secs, thunk_rva) {
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
        }
        out.push(ImportDesc {
            dll,
            raw: [ilt, ts, fwd, name_rva, iat],
            funcs,
        });
        off += 20;
    }
    Ok(out)
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
        let data = fs::read(path).map_err(|e| format!("Cannot read {p}: {e}"))?;
        let info = parse_pe(&data)?;
        let imports = parse_imports(&data, &info)?;
        let has_miheap = imports.iter().any(|d| d.dll.eq_ignore_ascii_case(MIHEAP_DLL));
        let has_env = imports
            .iter()
            .any(|d| d.dll.eq_ignore_ascii_case(MIHEAP_ENV_DLL));
        let has_minject = imports
            .iter()
            .any(|d| d.dll.eq_ignore_ascii_case("mimalloc-redirect.dll"));
        let has_heapalloc = imports.iter().any(|d| {
            d.dll.eq_ignore_ascii_case("kernel32.dll")
                && d.funcs.iter().any(|f| f == "HeapAlloc")
        });
        let has_crt = imports.iter().any(|d| {
            let l = d.dll.to_ascii_lowercase();
            l.starts_with("api-ms-win-crt-heap-") || l == "ucrtbase.dll"
        });
        let signed = info.dirs.len() > 4 && info.dirs[4].1 > 0;
        let cfg = (info.dll_chars & 0x4000) != 0;
        println!(
            "\n{} ({} B, CFG={cfg}, signed={signed})\n  miheap_env={has_env}  miheap={has_miheap}  minject={has_minject}  HeapAlloc={has_heapalloc}  crt_heap={has_crt}",
            path.display(),
            data.len()
        );
        for (idx, d) in imports.iter().take(5).enumerate() {
            println!("  [{idx}] {}", d.dll);
        }
    }
    Ok(())
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

fn load_toml_env_for_exe(exe_path: &Path) -> Vec<(String, String)> {
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

    for file in files {
        let Ok(text) = fs::read_to_string(&file) else {
            continue;
        };
        let mut active_sec = 0u8; // 0=none, 1=settings, 2=env, 3=proc_match
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
                } else {
                    let target = hdr
                        .strip_prefix("Process.")
                        .or_else(|| hdr.strip_prefix("process."))
                        .or_else(|| hdr.strip_prefix("App."))
                        .unwrap_or(hdr)
                        .trim_matches(|c| c == '"' || c == '\'');
                    active_sec = if target.eq_ignore_ascii_case(exe_name) {
                        3
                    } else {
                        0
                    };
                }
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
                2 | 3 => {
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

fn run_with_early_apc_inject(exe_path: &Path, args: &[String], dll_paths: &[PathBuf]) -> Result<i32, String> {
    let mut cmdline = quote_win_arg(&exe_path.to_string_lossy());
    for a in args {
        cmdline.push(' ');
        cmdline.push_str(&quote_win_arg(a));
    }
    let app_w = to_wide_null(exe_path.as_os_str());
    let mut cmdline_w = to_wide_null(OsStr::new(&cmdline));

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
    const MEM_COMMIT_RESERVE: u32 = 0x3000;
    const PAGE_READWRITE: u32 = 0x04;
    const INFINITE: u32 = 0xFFFF_FFFF;

    unsafe {
        if CreateProcessW(
            app_w.as_ptr(),
            cmdline_w.as_mut_ptr(),
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            1,
            CREATE_SUSPENDED,
            std::ptr::null_mut(),
            std::ptr::null(),
            &si,
            &mut pi,
        ) == 0
        {
            return Err(format!("CreateProcessW failed: error {}", GetLastError()));
        }

        let k32_w = to_wide_null(OsStr::new("kernel32.dll"));
        let k32 = GetModuleHandleW(k32_w.as_ptr());
        let load_lib = GetProcAddress(k32, b"LoadLibraryW\0".as_ptr());
        if load_lib.is_null() {
            TerminateProcess(pi.h_process, 1);
            CloseHandle(pi.h_thread);
            CloseHandle(pi.h_process);
            return Err("GetProcAddress(LoadLibraryW) failed".into());
        }

        for dll_path in dll_paths {
            let dll_w = to_wide_null(dll_path.as_os_str());
            let byte_len = dll_w.len() * 2;
            let remote = VirtualAllocEx(
                pi.h_process,
                std::ptr::null_mut(),
                byte_len,
                MEM_COMMIT_RESERVE,
                PAGE_READWRITE,
            );
            if remote.is_null() {
                let err = GetLastError();
                TerminateProcess(pi.h_process, 1);
                CloseHandle(pi.h_thread);
                CloseHandle(pi.h_process);
                return Err(format!("VirtualAllocEx failed: error {err}"));
            }

            let mut written = 0usize;
            if WriteProcessMemory(
                pi.h_process,
                remote,
                dll_w.as_ptr() as *const _,
                byte_len,
                &mut written,
            ) == 0
                || QueueUserAPC(load_lib, pi.h_thread, remote as usize) == 0
            {
                let err = GetLastError();
                TerminateProcess(pi.h_process, 1);
                CloseHandle(pi.h_thread);
                CloseHandle(pi.h_process);
                return Err(format!("Early-bird APC injection failed: error {err}"));
            }
        }

        ResumeThread(pi.h_thread);
        WaitForSingleObject(pi.h_process, INFINITE);
        let mut exit_code: u32 = 0;
        GetExitCodeProcess(pi.h_process, &mut exit_code);
        CloseHandle(pi.h_thread);
        CloseHandle(pi.h_process);
        Ok(exit_code as i32)
    }
}

fn cmd_run(args: &[String]) -> Result<i32, String> {
    let mut no_huge_pages = false;
    let mut verbose = false;
    let mut quiet = false;
    let mut console = false;
    let mut inject = false;
    let mut log_file: Option<String> = None;
    let mut i = 0usize;
    while i < args.len() {
        match args[i].as_str() {
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
    // CLI overrides here. For unpatched / --inject binaries, we also load miheap.toml
    // into the environment before launching.
    let mut overrides: Vec<(String, String)> = Vec::new();
    let has_env_dll = !inject && binary_has_miheap_env(&exe_path);
    if !has_env_dll {
        overrides = load_toml_env_for_exe(&exe_path);
    }

    let set_override = |vec: &mut Vec<(String, String)>, k: &str, v: &str| {
        if let Some(e) = vec.iter_mut().find(|(ek, _)| ek.eq_ignore_ascii_case(k)) {
            e.1 = v.to_string();
        } else {
            vec.push((k.to_string(), v.to_string()));
        }
    };

    if no_huge_pages {
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
    if let Some(lf) = log_file {
        set_override(&mut overrides, "MIHEAP_LOG", "1");
        set_override(&mut overrides, "MIHEAP_LOG_FILE", &lf);
    }

    if inject {
        let dir = active_mimalloc_dir();
        let env_dll = dir.join(MIHEAP_ENV_DLL);
        let heap_dll = dir.join(MIHEAP_DLL);
        if !heap_dll.is_file() {
            return Err(format!("{MIHEAP_DLL} not found in {}", dir.display()));
        }
        let mut dlls = Vec::new();
        if env_dll.is_file() {
            dlls.push(env_dll);
        }
        dlls.push(heap_dll);
        for (k, v) in &overrides {
            env::set_var(k, v);
        }
        return run_with_early_apc_inject(&exe_path, rest, &dlls);
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
  rminject config [--path | --edit]                  Show or edit global C:\\mimalloc\\miheap.toml
  rminject update-mimalloc <v1|v2|v3|path.dll>       Replace active C:\\mimalloc\\mimalloc.dll
  rminject run [OPTIONS] <cmd> [args...]             Run binary (resolves CWD & PATH) using miheap.toml

RUN OPTIONS (optional overrides on top of miheap.toml):
  --inject, -i         Early-bird APC inject miheap-env + miheap without modifying binary on disk
  --verbose, -v        Enable MIMALLOC_VERBOSE=1, MIMALLOC_SHOW_STATS=1, MIHEAP_LOG=1
  --console            Spawn a separate console window for stdout/stderr/mimalloc output
  --log-file <path>    Also write [miheap] logs to a file
  --no-huge-pages      Disable large/huge OS pages
  --quiet, -q          Suppress verbose/stats output"
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
