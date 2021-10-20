#![allow(non_camel_case_types)]
#![deny(clippy::all)]
#![deny(clippy::pedantic)]

use std::convert::TryFrom;
use std::error;
use std::fmt;
use std::fs;
use std::io::prelude::*;
use std::mem;
use std::path::Path;
use std::slice;
use std::str;
use std::time::SystemTime;

use std::sync::atomic::{AtomicBool, Ordering};
use structopt::StructOpt;

extern crate chrono;
use chrono::prelude::*;

extern crate chrono_english;
use chrono_english::{parse_date_string, Dialect};

#[macro_use]
extern crate lazy_static;

// Thread-safe global variables.
lazy_static! {
	static ref OPT: Opt = Opt::from_args();
}

static PRINT_HEADER: AtomicBool = AtomicBool::new(false);

const NGX_FC_HEADER_VERSION: ngx_uint_t = 5;

// nginx bindings
type u_char = std::os::raw::c_uchar;
type u_short = std::os::raw::c_ushort;
type time_t = std::os::raw::c_long;
type ngx_uint_t = usize;

#[derive(Debug)]
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
	etag: [u_char; 128_usize],
	vary_len: u_char,
	vary: [u_char; 128_usize],
	variant: [u_char; 16_usize],
}

struct CacheMeta {
	path: String,
	cache_header: ngx_http_file_cache_header_t,
	key: Option<String>,
}

#[derive(PartialEq, Debug)]
enum CacheStatus {
	Hit,
	Updating,
	Stale,
	Expired,
}

impl fmt::Display for CacheStatus {
	fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
		match *self {
			CacheStatus::Hit => "Hit".fmt(f),
			CacheStatus::Updating => "Updating".fmt(f),
			CacheStatus::Stale => "Stale".fmt(f),
			CacheStatus::Expired => "Expired".fmt(f),
		}
	}
}

fn calc_cache_status(now: i64, valid_sec: i64, updating_sec: i64, error_sec: i64) -> CacheStatus {
	// Expiration fields meaning is as follows (nginx-1.18.0/src/http/ngx_http_upstream.c):
	//  valid_sec = ngx_time() + n (where n is max-age or s-maxage)
	//  updating_sec = stale-while-revalidate
	//  error_sec = stale-while-revalidate || stale-if-error
	// Validation (nginx-1.18.0/src/http/ngx_http_file_cache.c):
	//  if (c->valid_sec < now) {
	//    c->stale_updating = c->valid_sec + c->updating_sec >= now;
	//    c->stale_error = c->valid_sec + c->error_sec >= now;
	//  }
	if valid_sec < now {
		if valid_sec + updating_sec >= now {
			CacheStatus::Updating
		} else if valid_sec + error_sec >= now {
			CacheStatus::Stale
		} else {
			CacheStatus::Expired
		}
	} else {
		CacheStatus::Hit
	}
}

fn humanize_time(uts: i64, human: bool) -> String {
	if human && uts != 0 {
		Local.timestamp(uts, 0).format("%Y-%m-%dT%H:%M:%S").to_string()
	} else {
		uts.to_string()
	}
}

fn cache_meta_print(cache_meta: &CacheMeta, status: &CacheStatus) {
	let path = &cache_meta.path;
	let cache_header = &cache_meta.cache_header;
	let key = &cache_meta.key;

	let valid = humanize_time(cache_header.valid_sec, OPT.human_time);
	let updating = if cache_header.updating_sec > 0 {
		humanize_time(cache_header.valid_sec + cache_header.updating_sec, OPT.human_time)
	} else {
		cache_header.updating_sec.to_string()
	};
	let error = if cache_header.error_sec > 0 {
		humanize_time(cache_header.valid_sec + cache_header.error_sec, OPT.human_time)
	} else {
		cache_header.error_sec.to_string()
	};

	let mut header = format!(
		"{:55}  {:>19}  {:>19}  {:>19}  {:>7}",
		"path", "expires", "if-updating", "if-error", "status"
	);
	if key.is_some() {
		header = format!("{} {}", header, "key");
	}

	// Print header only once.
	if !OPT.no_header && !PRINT_HEADER.load(Ordering::Relaxed) {
		println!("{}", header);
		PRINT_HEADER.store(true, Ordering::Relaxed);
	}

	match key {
		Some(key) => println!(
			"{:55}  {:>19}  {:>19}  {:>19}  {:>8}  {}",
			path,
			valid,
			updating,
			error,
			status,
			key.trim().trim_start_matches("KEY: ")
		),
		None => println!(
			"{:55}  {:>19}  {:>19}  {:>19}  {:>8}",
			path, valid, updating, error, status
		),
	}
}

fn is_match(cache_meta: &CacheMeta, time_range: (Option<i64>, Option<i64>), key_re: Option<&String>) -> bool {
	let (after_ts, before_ts) = time_range;

	let cache_header = &cache_meta.cache_header;

	let max_valid =
		(cache_header.valid_sec + cache_header.updating_sec).max(cache_header.valid_sec + cache_header.error_sec);

	if let Some(before_ts) = before_ts {
		if max_valid > before_ts {
			return false;
		}
	}

	if let Some(after_ts) = after_ts {
		if max_valid < after_ts {
			return false;
		}
	}

	if let Some(key_re) = key_re {
		if let Some(key) = &cache_meta.key {
			if !key.contains(key_re) {
				return false;
			}
		}
	}

	true
}

fn nginx_file_cache_read(path: &Path, read_key: bool) -> Result<CacheMeta, Box<dyn error::Error>> {
	let display = path.display();
	let mut cache_header: ngx_http_file_cache_header_t = unsafe { mem::zeroed() };
	let cache_header_size = mem::size_of::<ngx_http_file_cache_header_t>();

	let mut file = match fs::File::open(path) {
		Err(why) => panic!("couldn't open {}: {}", display, why),
		Ok(file) => file,
	};

	#[allow(clippy::semicolon_if_nothing_returned, clippy::ptr_as_ptr)]
	unsafe {
		// std::io::read_exact() expects a reference to mutable u8 buffer with known length.
		// slice is Rust’s solution to (raw) pointer+length.
		// In the end, cache_header and cache_header_slice point to the same memory.
		let cache_header_slice = slice::from_raw_parts_mut(&mut cache_header as *mut _ as *mut u8, cache_header_size);
		file.read_exact(cache_header_slice)?
	};

	if cache_header.version != NGX_FC_HEADER_VERSION {
		panic!(
			"FATAL: {} header version mismatch. Expected {}, got {}.",
			display, NGX_FC_HEADER_VERSION, cache_header.version
		);
	}

	let max_key_size = 8190; // apache's LimitRequestLine
	let min_header_start = cache_header_size + b"\nKEY: C\n".len();
	if (cache_header.header_start as usize) < min_header_start || (cache_header.header_start as usize) > max_key_size {
		panic!("FATAL: {} invalid header_start {}", display, cache_header.header_start);
	}

	let key = if read_key {
		let mut buf = vec![0_u8; cache_header.header_start as usize - cache_header_size];
		file.read_exact(&mut buf)?;

		let key = str::from_utf8(&buf)?;
		let key = key.strip_prefix("\nKEY: ");

		if key.is_none() {
			return Err("missing key label".into());
		}

		Some(key.unwrap().to_string())
	} else {
		Option::None
	};

	if OPT.debug {
		eprintln!("D: path {}, key {:?}", display, key);
	}

	Ok(CacheMeta {
		path: path.to_str().unwrap().to_string(),
		cache_header,
		key,
	})
}

fn purge(path: &Path) {
	if OPT.debug {
		eprintln!("unlink() {}", path.display());
	}

	if let Err(e) = fs::remove_file(path) {
		if !OPT.hide_unlink_errors {
			eprintln!("purge({}) failed: {:?}", path.display(), e);
		}
	}
}

fn path_walk(dir: &Path, time_range: (Option<i64>, Option<i64>)) {
	let rd_itr = match dir.read_dir() {
		Ok(rd_itr) => rd_itr,
		Err(e) => panic!("{} {:?}", dir.display(), e),
	};

	for entry in rd_itr.flatten() {
		let path = entry.path();
		let file_type = entry.file_type().unwrap();

		if file_type.is_dir() {
			path_walk(&path, time_range);
		} else if file_type.is_file() {
			let cache_meta = match nginx_file_cache_read(&path, OPT.match_key.is_some()) {
				Ok(cm) => cm,
				Err(e) => {
					eprintln!("nginx_file_cache_read({}) error: {:?}", path.display(), e);
					continue;
				}
			};

			if !is_match(&cache_meta, time_range, OPT.match_key.as_ref()) {
				continue;
			}

			if !OPT.quiet {
				let uts = SystemTime::now()
					.duration_since(SystemTime::UNIX_EPOCH)
					.unwrap()
					.as_secs();
				let uts = i64::try_from(uts).expect("SystemTime::now() u64 -> i64 overflow?");
				let status = calc_cache_status(
					uts,
					cache_meta.cache_header.valid_sec,
					cache_meta.cache_header.updating_sec,
					cache_meta.cache_header.error_sec,
				);
				cache_meta_print(&cache_meta, &status);
			}

			if OPT.purge {
				purge(path.as_path());
			}
		} else {
			panic!("ERROR: {:?} is neither file nor directory.", path);
		}
	}
}

// structopt will be merged in clap 3.x soon
#[allow(clippy::struct_excessive_bools)]
#[derive(StructOpt, Debug)]
struct Opt {
	cache_dir: String,

	#[structopt(long = "debug", short = "d")]
	debug: bool,

	#[structopt(long = "quiet", short = "q")]
	quiet: bool,

	#[structopt(long = "hide-unlink-errors")]
	hide_unlink_errors: bool,

	#[structopt(long = "no-header")]
	no_header: bool,

	#[structopt(long = "human-time")]
	human_time: bool,

	#[structopt(long = "expires-after", short = "a")]
	expires_after: Option<String>,

	/// Default is now() if no --expires-after and --expires-before were given; check with --debug
	#[structopt(long = "expires-before", short = "b")]
	expires_before: Option<String>,

	/// Usually key is an URL. Non-regex substring match.
	#[structopt(long = "match-key")]
	match_key: Option<String>,

	/// Purge ALL matched cache files (not limited to Expired)
	#[structopt(long = "purge")]
	purge: bool,
}

pub fn main() {
	let expires_before: Option<String>;

	let mut exp_aft_ts: Option<i64> = Option::None;
	let mut exp_bef_ts: Option<i64> = Option::None;

	if OPT.expires_after.is_none() && OPT.expires_before.is_none() {
		expires_before = Option::Some("now".to_string());
	} else {
		expires_before = OPT.expires_before.clone();
	}

	if let Some(tmp_after) = &OPT.expires_after {
		let exp_a_dt = parse_date_string(tmp_after, Local::now(), Dialect::Uk).unwrap();
		if OPT.debug {
			eprintln!("After: {}", exp_a_dt);
		}
		exp_aft_ts = Option::Some(exp_a_dt.timestamp());
	}

	if let Some(tmp_before) = expires_before {
		let exp_b_dt = parse_date_string(&tmp_before, Local::now(), Dialect::Uk).unwrap();
		if OPT.debug {
			eprintln!("Before: {}", exp_b_dt);
		}
		exp_bef_ts = Option::Some(exp_b_dt.timestamp());
	}

	let time_range = (exp_aft_ts, exp_bef_ts);
	let path = Path::new(&OPT.cache_dir);

	if OPT.debug && OPT.match_key.is_some() {
		eprintln!("Match: {}", OPT.match_key.as_ref().unwrap());
	}

	if let Some(a) = exp_aft_ts {
		if let Some(b) = exp_bef_ts {
			if b < a {
				panic!("Conflicting expires options: before < after ({} < {}).", b, a);
			}
		}
	}

	path_walk(path, time_range);
}

#[cfg(test)]
mod tests {
	use super::*;
	use proptest::prelude::*;

	#[test]
	fn test_calc_cache_status() {
		let now = 100;
		assert_eq!(calc_cache_status(now, 101, 0, 0), CacheStatus::Hit);
		assert_eq!(calc_cache_status(now, 100, 0, 0), CacheStatus::Hit);
		assert_eq!(calc_cache_status(now, 100, 1, 1), CacheStatus::Hit);

		assert_eq!(calc_cache_status(now, 99, 1, 0), CacheStatus::Updating);
		assert_eq!(calc_cache_status(now, 99, 1, 1), CacheStatus::Updating);

		assert_eq!(calc_cache_status(now, 99, 0, 1), CacheStatus::Stale);

		assert_eq!(calc_cache_status(now, 99, 0, 0), CacheStatus::Expired);
		assert_eq!(calc_cache_status(now, 98, 0, 0), CacheStatus::Expired);
		assert_eq!(calc_cache_status(now, 98, 1, 0), CacheStatus::Expired);
		assert_eq!(calc_cache_status(now, 98, 0, 1), CacheStatus::Expired);
		assert_eq!(calc_cache_status(now, 98, 1, 1), CacheStatus::Expired);
	}

	#[test]
	fn test_humanize_time() {
		assert_eq!(humanize_time(100, false), "100");
		assert_eq!(humanize_time(100, true), "1970-01-01T02:01:40");
		assert_eq!(humanize_time(0, false), "0");
		assert_eq!(humanize_time(0, true), "0");
	}

	#[test]
	fn test_is_match() {
		let cache_header: ngx_http_file_cache_header_t = unsafe { mem::zeroed() };
		let path = "/var/nginx/cache/a/b/deadbeef".to_string();
		let key = Option::None;
		let mut cm = CacheMeta {
			path,
			cache_header,
			key,
		};

		// valid_sec alone
		cm.cache_header.valid_sec = 150;
		assert!(
			is_match(&cm, (Some(100), Some(200)), Option::None),
			"expiration is within filter limits"
		);

		cm.cache_header.valid_sec = 100;
		assert!(
			is_match(&cm, (Some(100), Some(200)), Option::None),
			"expiration is within filter limits (= after)"
		);

		cm.cache_header.valid_sec = 200;
		assert!(
			is_match(&cm, (Some(100), Some(200)), Option::None),
			"expiration is within filter limits (= before)"
		);

		cm.cache_header.valid_sec = 50;
		assert!(
			!is_match(&cm, (Some(100), Some(200)), Option::None),
			"expiration is outside filter limits (< after)"
		);

		cm.cache_header.valid_sec = 250;
		assert!(
			!is_match(&cm, (Some(100), Some(200)), Option::None),
			"expiration outside filter limits (> before)"
		);

		cm.cache_header.valid_sec = 50;

		cm.cache_header.updating_sec = 50;
		assert!(
			is_match(&cm, (Some(100), Some(200)), Option::None),
			"expiration/updating is within filter limits (=after, <before)"
		);
		cm.cache_header.updating_sec = 49;
		assert!(
			!is_match(&cm, (Some(100), Some(200)), Option::None),
			"expiration/updating is outside filter limits (<after)"
		);

		cm.cache_header.updating_sec = 0;

		cm.cache_header.error_sec = 150;
		assert!(
			is_match(&cm, (Some(100), Some(200)), Option::None),
			"expiration/error is within filter limits (>after, =before)"
		);
		cm.cache_header.error_sec = 151;
		assert!(
			!is_match(&cm, (Some(100), Some(200)), Option::None),
			"expiration/error is outside filter limits (>after, >before)"
		);

		// fix valid_sec for key match tests
		cm.cache_header.valid_sec = 150;
		cm.cache_header.updating_sec = 0;
		cm.cache_header.error_sec = 0;

		cm.key = Some("http://example.com/white".to_string());
		assert!(
			is_match(&cm, (Some(100), Some(200)), Some(&"white".to_string())),
			"key matches"
		);
		assert!(
			!is_match(&cm, (Some(100), Some(200)), Some(&"black".to_string())),
			"key doesn't match"
		);
	}

	proptest! {
		#[test]
		fn match_any_printable_key_string(s in ".*") {
			let cache_header: ngx_http_file_cache_header_t = unsafe { mem::zeroed() };
			let path = "/var/nginx/cache/a/b/deadbeef".to_string();
			let key = Some(s.clone());
			let mut cm = CacheMeta {path, cache_header, key};

			cm.cache_header.valid_sec = 150;
			cm.cache_header.updating_sec = 0;
			cm.cache_header.error_sec = 0;

			prop_assert_eq!(true, is_match(&cm, (Some(100), Some(200)), Some(&s)), "random data");
		}

		#[test]
		fn match_corrupted_data_no_crash(s in ".{336}") {
			let path = "/var/nginx/cache/a/b/deadbeef".to_string();

			let mut cache_header: ngx_http_file_cache_header_t = unsafe { mem::zeroed() };
			let cache_header_size = mem::size_of::<ngx_http_file_cache_header_t>();
			let cache_header_slice = unsafe { slice::from_raw_parts_mut(&mut cache_header as *mut _ as *mut u8, cache_header_size) };

			cache_header_slice.copy_from_slice(&s.as_bytes()[1..=336]);

			let key = Some(s);

			let cm = CacheMeta {path, cache_header, key};

			prop_assert_eq!(false, is_match(&cm, (Some(100), Some(200)), Some(&"x".to_string())), "random data");
		}
	}
}
