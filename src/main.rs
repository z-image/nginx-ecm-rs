#![allow(non_camel_case_types)]

use std::fs;
use std::io::prelude::*;
use std::mem;
use std::path::Path;
use std::slice;

use structopt::StructOpt;

const NGX_FC_HEADER_VERSION: ngx_uint_t = 5;


// nginx bindings
type u_char = std::os::raw::c_uchar;
type u_short = std::os::raw::c_ushort;
type time_t = std::os::raw::c_long;
type ngx_uint_t = usize;

#[repr(C)]
struct ngx_http_file_cache_header_t {
    version: ngx_uint_t,
    valid_sec: time_t,
    updating_sec: time_t,
    error_sec: time_t,
    last_modified: time_t,
    date: time_t,
    crc32: u32,
    valid_msec: u_short,
    header_start: u_short,
    body_start: u_short,
    etag_len: u_char,
    etag: [u_char; 128usize],
    vary_len: u_char,
    vary: [u_char; 128usize],
    variant: [u_char; 16usize],
}


fn nginx_file_cache_read(file: &Path) {
    let mut chd: ngx_http_file_cache_header_t = unsafe { mem::zeroed() };
    let chd_size = mem::size_of::<ngx_http_file_cache_header_t>();

    let mut fd = fs::File::open(file).unwrap();

    unsafe {
        let chd_slice = slice::from_raw_parts_mut(&mut chd as *mut _ as *mut u8, chd_size);
        fd.read_exact(chd_slice).unwrap();
    }

    if chd.version != NGX_FC_HEADER_VERSION {
        panic!("FATAL: {} header version mismatch. Expected {}, got {}.",
            file.to_str().unwrap(), NGX_FC_HEADER_VERSION, chd.version);
    }

    // println!("{} {} {} {}", file.to_str().unwrap(), chd.valid_sec, chd.updating_sec, chd.error_sec);
}


fn path_walk(dir: &Path) {
    for result in dir.read_dir().unwrap() {
        if let Ok(entry) = result {
            let path = entry.path();
            let file_type = entry.file_type().unwrap();
            if file_type.is_dir() {
                path_walk(&path);
            } else if file_type.is_file() {
                nginx_file_cache_read(&path);
            } else {
                panic!("ERROR: {:?} is neither file nor directory.", path);
            }
        }
    }
}


#[derive(StructOpt, Debug)]
struct Opt {
    cache_dir: String,
}


pub fn main() {
    let opt = Opt::from_args();

    let path = Path::new(&opt.cache_dir);
    path_walk(path);
}
