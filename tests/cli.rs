#![allow(non_camel_case_types)]

use assert_cmd::prelude::*;
use predicates::prelude::*;
use std::convert::TryInto;
use std::fs;
use std::io::{ErrorKind, Write};
use std::mem;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::process::Command;
use std::slice;

// nginx bindings
type u_char = std::os::raw::c_uchar;
type u_short = std::os::raw::c_ushort;
type time_t = std::os::raw::c_long;
type ngx_uint_t = usize;

// #[derive(Debug)] // Requires rust 1.47 due to std::array::LengthAtMost32
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

const CLI_NAME: &str = "nginx-ecm-rs";

#[link(name = "c")]
extern "C" {
	fn geteuid() -> u32;
}

fn create_cache_file(
	tmp_dir: &std::path::Path,
	version: usize,
	key: Option<&[u8]>,
) -> Result<std::path::PathBuf, Box<dyn std::error::Error>> {
	let mut file_path = tmp_dir.to_path_buf();
	let mut file = Option::None;

	// Create unique file if called multiple times from single test (3 attempts)
	for i in 1..=3 {
		file_path = tmp_dir.join(format!("cache-file-{}", i));
		file = match fs::OpenOptions::new().write(true).create_new(true).open(&file_path) {
			Ok(f) => Some(f),
			Err(e) => {
				if e.kind() == ErrorKind::AlreadyExists {
					continue;
				}
				panic!("{:#?}", e);
			}
		};
		if file.is_some() {
			break;
		}
	}
	let mut file = file.unwrap();

	let key = match key {
		Some(key) => key,
		None => b"\nKEY: .",
	};

	let mut cache_header: ngx_http_file_cache_header_t = unsafe { mem::zeroed() };
	let cache_header_size = mem::size_of::<ngx_http_file_cache_header_t>();

	cache_header.version = version;
	cache_header.header_start = (cache_header_size + key.len()).try_into().unwrap();

	unsafe {
		let cache_header_slice = slice::from_raw_parts_mut(&mut cache_header as *mut _ as *mut u8, cache_header_size);
		file.write_all(cache_header_slice)?;
	}
	file.write_all(key)?;

	Ok(file_path)
}

#[test]
fn cache_dir_doesnt_exist() -> Result<(), Box<dyn std::error::Error>> {
	let mut cmd = Command::cargo_bin("nginx-ecm-rs")?;
	cmd.arg("/no/such/dir/");
	cmd.assert()
		.failure()
		.stderr(predicate::str::contains("No such file or directory"));

	Ok(())
}

#[test]
fn cache_dir_no_permission() -> Result<(), Box<dyn std::error::Error>> {
	let euid = unsafe { geteuid() };

	// skip test if root
	if euid == 0 {
		assert!(true, "SKIP")
	} else {
		let dir = tempfile::tempdir().unwrap();
		let path = dir.path();

		let metadata = path.metadata()?;
		let mut permissions = metadata.permissions();
		permissions.set_mode(0o000);
		fs::set_permissions(path, permissions)?;

		let mut cmd = Command::cargo_bin("nginx-ecm-rs")?;
		cmd.arg(path);
		cmd.assert()
			.failure()
			.stderr(predicate::str::contains("Permission denied"));
	}

	Ok(())
}

#[test]
fn special_file() -> Result<(), Box<dyn std::error::Error>> {
	let dir = tempfile::tempdir()?;

	Command::new("mkfifo").arg(dir.path().join("fifo")).status().unwrap();

	let mut cmd = Command::cargo_bin(CLI_NAME)?;
	cmd.arg(dir.path());
	cmd.assert()
		.failure()
		.stderr(predicate::str::contains("neither file nor directory"));

	Ok(())
}

#[test]
fn cache_file_no_permission() -> Result<(), Box<dyn std::error::Error>> {
	let euid = unsafe { geteuid() };

	// skip test if root
	if euid == 0 {
		assert!(true, "SKIP")
	} else {
		let dir = tempfile::tempdir().unwrap();
		let path = dir.path();

		let file_path = dir.path().join("cache-test.bin");
		fs::File::create(&file_path)?;

		let metadata = file_path.metadata()?;
		let mut permissions = metadata.permissions();
		permissions.set_mode(0o000);
		fs::set_permissions(file_path, permissions)?;

		let mut cmd = Command::cargo_bin("nginx-ecm-rs")?;
		cmd.arg(path);
		cmd.assert()
			.failure()
			.stderr(predicate::str::contains("Permission denied"));
	}

	Ok(())
}

#[test]
fn short_cache_file() -> Result<(), Box<dyn std::error::Error>> {
	let dir = tempfile::tempdir()?;
	let file_path = dir.path().join("cache-test.bin");
	let mut file = fs::File::create(&file_path)?;

	writeln!(file, ".")?;

	let mut cmd = Command::cargo_bin(CLI_NAME)?;
	cmd.arg(dir.path());
	cmd.assert()
		.success()
		.stderr(predicate::str::contains("failed to fill whole buffer"));

	Ok(())
}

#[test]
fn valid_nginx_cache_file() -> Result<(), Box<dyn std::error::Error>> {
	let dir_path = Path::new("tests/data");

	let mut cmd = Command::cargo_bin(CLI_NAME)?;
	cmd.arg(dir_path).arg("--match-key").arg("zimage.example.com");
	cmd.assert()
		.success()
		.stdout(predicate::str::contains("77cefbbd3b90b3f68899b6c7aa02d007"));

	Ok(())
}

#[test]
fn valid_generated_cache_file() -> Result<(), Box<dyn std::error::Error>> {
	let tmp_dir = tempfile::tempdir()?;
	create_cache_file(tmp_dir.path(), 5, Some(b"\nKEY: http://example.com/hello.html"))?;

	let mut cmd = Command::cargo_bin(CLI_NAME)?;
	cmd.arg(tmp_dir.path()).arg("--match-key").arg("example.com");
	cmd.assert().success().stdout(predicate::str::contains("example"));

	Ok(())
}

#[test]
fn invalid_cache_header_version() -> Result<(), Box<dyn std::error::Error>> {
	let tmp_dir = tempfile::tempdir()?;
	create_cache_file(tmp_dir.path(), 6, None)?;

	let mut cmd = Command::cargo_bin(CLI_NAME)?;
	cmd.arg(tmp_dir.path());
	cmd.assert()
		.failure()
		.stderr(predicate::str::contains("header version mismatch"));

	Ok(())
}

#[test]
fn invalid_key_string() -> Result<(), Box<dyn std::error::Error>> {
	let tmp_dir = tempfile::tempdir()?;

	// 0xfe is invalid utf9 sequence
	//                             \n     K     E     Y     :    \s
	let bytes: &'static [u8] = &[0x0a, 0x4b, 0x45, 0x59, 0x3a, 0x20, 0xfe, 0x0a];
	let key = Some(bytes);
	let file_path = create_cache_file(tmp_dir.path(), 5, key)?;

	let mut cmd = Command::cargo_bin(CLI_NAME)?;
	cmd.arg(tmp_dir.path()).arg("--match-key").arg("example.com");

	let res = cmd.assert().success().try_stderr(predicate::str::contains("Utf8Error"));

	if let Err(e) = res {
		let bad_file = tempfile::NamedTempFile::new().unwrap();
		let bad_path = bad_file.into_temp_path();
		let bad_path = bad_path.keep()?;
		fs::copy(&file_path, &bad_path).unwrap();
		panic!("Test file preserved as {} due to {}", bad_path.display(), e);
	}

	Ok(())
}

#[test]
fn purge_purges_only_matched() -> Result<(), Box<dyn std::error::Error>> {
	let tmp_dir = tempfile::tempdir()?;
	let tmp_dir = tmp_dir.path();

	let fcom = create_cache_file(tmp_dir, 5, Some(b"\nKEY: http://example.com/hello.html"))?;
	let forg = create_cache_file(tmp_dir, 5, Some(b"\nKEY: http://example.org/hello.html"))?;

	assert!(fcom.exists());
	assert!(forg.exists());

	let mut cmd = Command::cargo_bin(CLI_NAME)?;
	cmd.arg(tmp_dir).arg("--match-key").arg("example.com").arg("--purge");
	cmd.assert().success().stdout(predicate::str::contains("example.com"));

	assert!(!fcom.exists());
	assert!(forg.exists());

	Ok(())
}
