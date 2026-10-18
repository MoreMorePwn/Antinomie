// SPDX-License-Identifier: MIT
//! Incremental SQLite index for the append-only packed-object index file.
use super::super::{
    CHUNK_RECORD_SIZE, CHUNK_TAG, FIELD_RECORD_SIZE, FIELD_TAG, FieldKey, HEADER_SIZE, INDEX_FILE,
    MAGIC, VERSION,
};
use super::{MAX_CHUNK_SIZE, MAX_SEGMENT_SIZE};
use crate::{archive_io, storage};
use rusqlite::{Connection, OptionalExtension, TransactionBehavior, params};
use sha2::{Digest, Sha256};
use std::{
    fs::{self, File},
    io::{self, BufReader, Read, Seek, SeekFrom},
    os::unix::{
        ffi::OsStrExt,
        fs::{MetadataExt, PermissionsExt},
    },
    path::{Path, PathBuf},
    sync::{Arc, Mutex, OnceLock},
};

const SCHEMA_VERSION: i64 = 1;
const READ_PIECE: usize = 64 * 1024;
const UPDATE_PIECE: u64 = 1024 * 1024;
const MAX_CACHED_CONNECTIONS: usize = 8;
const STATE_ID: i64 = 1;
type CacheConnections = Mutex<Vec<(PathBuf, Arc<Mutex<Connection>>)>>;
static CACHE_CONNECTIONS: OnceLock<CacheConnections> = OnceLock::new();

/// An unsigned integer encoded so SQLite's BLOB order is numeric order.
fn ordered_u64(value: u64) -> [u8; 8] {
    value.to_be_bytes()
}

fn invalid_cache(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}

fn invalid_cache_data(message: &'static str) -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidData,
        format!("packed-object index cache data: {message}"),
    )
}

pub(super) fn sql_error(error: rusqlite::Error) -> io::Error {
    io::Error::other(format!("packed-object index cache: {error}"))
}

fn cache_path(objects: &Path) -> io::Result<PathBuf> {
    let cache_root = match std::env::var_os("XDG_CACHE_HOME") {
        Some(path) if Path::new(&path).is_absolute() => PathBuf::from(path),
        Some(_) => {
            return Err(retained_cache_error(io::Error::new(
                io::ErrorKind::InvalidInput,
                "XDG_CACHE_HOME must be an absolute path",
            )));
        }
        None => match std::env::var_os("HOME") {
            Some(path) if Path::new(&path).is_absolute() => PathBuf::from(path).join(".cache"),
            Some(_) => {
                return Err(retained_cache_error(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "HOME must be an absolute path when XDG_CACHE_HOME is unset",
                )));
            }
            None => {
                return Err(retained_cache_error(io::Error::new(
                    io::ErrorKind::NotFound,
                    "private packed-object cache location is unavailable; set XDG_CACHE_HOME or HOME",
                )));
            }
        },
    };
    let root = cache_root.join("antinomie/object-pack");
    storage::private_dir(&root).map_err(retained_cache_error)?;
    let path = fs::canonicalize(objects)?;
    let digest = Sha256::digest(path.as_os_str().as_bytes());
    let name = digest
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    Ok(root.join(format!("{name}.sqlite")))
}

fn retained_cache_error(error: io::Error) -> io::Error {
    io::Error::new(
        error.kind(),
        format!(
            "{}; original object index and captured raw data are retained",
            error
        ),
    )
}

fn cache_database_error(error: io::Error, path: &Path) -> io::Error {
    io::Error::new(
        error.kind(),
        format!(
            "{error}; disposable packed-object cache: {}. Close Antinomie and every other process reading this archive before removing this cache database and any stale -journal file to rebuild it. The original objects.idx and captured raw data are retained",
            path.display()
        ),
    )
}

fn open_cache(path: &Path) -> io::Result<Connection> {
    let mut connection = Connection::open(path).map_err(sql_error)?;
    fs::set_permissions(path, fs::Permissions::from_mode(0o600)).map_err(retained_cache_error)?;
    connection
        .busy_timeout(std::time::Duration::from_secs(5))
        .map_err(sql_error)?;
    connection
        .execute_batch(
            "PRAGMA trusted_schema=OFF; PRAGMA cache_size=-512; \
             PRAGMA temp_store=FILE; PRAGMA temp.cache_size=-128;",
        )
        .map_err(sql_error)?;
    let version: i64 = connection
        .query_row("PRAGMA user_version", [], |row| row.get(0))
        .map_err(sql_error)?;
    if version != SCHEMA_VERSION {
        connection
            .execute_batch("PRAGMA journal_mode=DELETE;")
            .map_err(sql_error)?;
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(sql_error)?;
        let version: i64 = transaction
            .query_row("PRAGMA user_version", [], |row| row.get(0))
            .map_err(sql_error)?;
        if version != SCHEMA_VERSION {
            transaction
                .execute_batch(
                    "DROP TABLE IF EXISTS chunks; DROP TABLE IF EXISTS fields; \
                 DROP TABLE IF EXISTS metadata; \
                 CREATE TABLE metadata ( \
                   id INTEGER PRIMARY KEY CHECK(id=1), \
                   identity TEXT NOT NULL, \
                   source_len BLOB NOT NULL CHECK(length(source_len)=8), \
                   indexed BLOB NOT NULL CHECK(length(indexed)=8), \
                   stopped INTEGER NOT NULL CHECK(stopped IN (0,1)) \
                 ); \
                 CREATE TABLE fields (number INTEGER PRIMARY KEY, key BLOB NOT NULL); \
                 CREATE TABLE chunks ( \
                   key BLOB NOT NULL, object_offset BLOB NOT NULL CHECK(length(object_offset)=8), \
                   size INTEGER NOT NULL, location BLOB NOT NULL CHECK(length(location)=8), \
                   PRIMARY KEY(key, object_offset) \
                 ) WITHOUT ROWID; \
                 PRAGMA user_version=1;",
                )
                .map_err(sql_error)?;
        }
        transaction.commit().map_err(sql_error)?;
    }
    Ok(connection)
}

/// Return the archive's SQLite connection from a small process-wide LRU.
/// The global lock protects only the path-to-handle map; SQLite open/close and
/// all database work happen after releasing it.
fn cached_connection(path: &Path) -> io::Result<Arc<Mutex<Connection>>> {
    let connections = CACHE_CONNECTIONS.get_or_init(|| Mutex::new(Vec::new()));
    {
        let mut entries = connections
            .lock()
            .map_err(|_| retained_cache_error(io::Error::other("cache map lock poisoned")))?;
        if let Some(index) = entries.iter().position(|(cached, _)| cached == path) {
            let entry = entries.remove(index);
            let handle = Arc::clone(&entry.1);
            entries.push(entry);
            return Ok(handle);
        }
    }

    // Opening the database may block on filesystem work, so do it outside the
    // global LRU lock. Recheck under the lock in case another caller won.
    let candidate = Arc::new(Mutex::new(open_cache(path)?));
    let mut evicted = None;
    let mut unused = None;
    let handle = {
        let mut entries = connections
            .lock()
            .map_err(|_| retained_cache_error(io::Error::other("cache map lock poisoned")))?;
        if let Some(index) = entries.iter().position(|(cached, _)| cached == path) {
            let entry = entries.remove(index);
            let handle = Arc::clone(&entry.1);
            entries.push(entry);
            unused = Some(candidate);
            handle
        } else {
            if entries.len() == MAX_CACHED_CONNECTIONS {
                evicted = Some(entries.remove(0).1);
            }
            entries.push((path.to_path_buf(), Arc::clone(&candidate)));
            candidate
        }
    };
    // Dropping a rusqlite connection may perform filesystem work too.
    drop(unused);
    drop(evicted);
    Ok(handle)
}

/// Ensure `connection` has every complete record from the pinned source file.
/// Each database transaction applies at most one MiB of index records.
fn update(
    objects: &Path,
    connection: &mut Connection,
    file: &File,
    identity: &str,
    source_len: u64,
) -> io::Result<()> {
    loop {
        let (done, progressed) = update_piece(objects, connection, file, identity, source_len)?;
        if done || !progressed {
            return Ok(());
        }
    }
}

fn update_piece(
    objects: &Path,
    connection: &mut Connection,
    file: &File,
    identity: &str,
    source_len: u64,
) -> io::Result<(bool, bool)> {
    let cached: Option<(String, Vec<u8>, Vec<u8>, i64)> = connection
        .query_row(
            "SELECT identity, source_len, indexed, stopped FROM metadata WHERE id=?1",
            params![STATE_ID],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
        )
        .optional()
        .map_err(sql_error)?;
    if let Some((cached_identity, cached_len, cached_cursor, stopped)) = &cached {
        let prior_len = u64::from_be_bytes(
            cached_len
                .as_slice()
                .try_into()
                .map_err(|_| invalid_cache_data("invalid source length"))?,
        );
        let cursor = u64::from_be_bytes(
            cached_cursor
                .as_slice()
                .try_into()
                .map_err(|_| invalid_cache_data("invalid index cursor"))?,
        );
        let unchanged = cached_identity == identity
            && source_len == prior_len
            && (cursor == source_len || source_len < HEADER_SIZE || *stopped != 0);
        if unchanged {
            if file.metadata()?.len() < source_len {
                return Err(invalid_cache("object index shrank while being read"));
            }
            verify_source(objects, identity, source_len)?;
            return Ok((true, false));
        }
    }

    let transaction = connection
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .map_err(sql_error)?;
    let state: Option<(String, Vec<u8>, Vec<u8>, i64)> = transaction
        .query_row(
            "SELECT identity, source_len, indexed, stopped FROM metadata WHERE id=?1",
            params![STATE_ID],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
        )
        .optional()
        .map_err(sql_error)?;

    let mut cursor = 0_u64;
    let mut stopped = false;
    let mut progressed = false;
    let mut incomplete_tail = false;
    let mut prior_len = 0_u64;
    if let Some((cached_identity, cached_len, cached_cursor, cached_stopped)) = state {
        prior_len = u64::from_be_bytes(
            cached_len
                .as_slice()
                .try_into()
                .map_err(|_| invalid_cache_data("invalid source length"))?,
        );
        cursor = u64::from_be_bytes(
            cached_cursor
                .as_slice()
                .try_into()
                .map_err(|_| invalid_cache_data("invalid index cursor"))?,
        );
        stopped = cached_stopped != 0;
        if cached_identity != identity || source_len < prior_len || cursor > source_len {
            transaction
                .execute("DELETE FROM chunks", [])
                .map_err(sql_error)?;
            transaction
                .execute("DELETE FROM fields", [])
                .map_err(sql_error)?;
            cursor = 0;
            stopped = false;
            prior_len = 0;
        }
    }
    if prior_len == 0 || cursor == 0 {
        transaction
            .execute("DELETE FROM chunks", [])
            .map_err(sql_error)?;
        transaction
            .execute("DELETE FROM fields", [])
            .map_err(sql_error)?;
        cursor = 0;
        stopped = false;
    }

    if cursor == 0 && source_len >= HEADER_SIZE {
        let mut header = [0_u8; HEADER_SIZE as usize];
        read_exact_at(file, &mut header, 0)?;
        if &header[..8] != MAGIC
            || u32::from_le_bytes(header[8..12].try_into().expect("four bytes")) != VERSION
        {
            return Err(invalid_cache("unknown object index format"));
        }
        cursor = HEADER_SIZE;
        progressed = true;
    }

    if !stopped && cursor >= HEADER_SIZE && cursor < source_len {
        let mut reader = BufReader::with_capacity(READ_PIECE, file.try_clone()?);
        reader.seek(SeekFrom::Start(cursor))?;
        let mut set_field = transaction
            .prepare_cached("INSERT OR REPLACE INTO fields(number,key) VALUES(?1,?2)")
            .map_err(sql_error)?;
        let mut find_field = transaction
            .prepare_cached("SELECT key FROM fields WHERE number=?1")
            .map_err(sql_error)?;
        let mut put_chunk = transaction
            .prepare_cached(
                "INSERT OR REPLACE INTO chunks(key,object_offset,size,location) \
                 VALUES(?1,?2,?3,?4)",
            )
            .map_err(sql_error)?;
        let mut record = [0_u8; FIELD_RECORD_SIZE as usize];
        let batch_end = source_len.min(cursor.saturating_add(UPDATE_PIECE));
        while cursor < batch_end {
            let remaining = source_len - cursor;
            if remaining == 0 {
                break;
            }
            let record_start = cursor;
            let mut tag = [0_u8; 1];
            reader.read_exact(&mut tag).map_err(|error| {
                if error.kind() == io::ErrorKind::UnexpectedEof {
                    invalid_cache("object index changed while being read")
                } else {
                    error
                }
            })?;
            let record_size = match tag[0] {
                FIELD_TAG => FIELD_RECORD_SIZE as usize,
                CHUNK_TAG => CHUNK_RECORD_SIZE as usize,
                _ => {
                    stopped = true;
                    cursor = record_start;
                    break;
                }
            };
            if remaining < record_size as u64 {
                cursor = record_start;
                incomplete_tail = true;
                break;
            }
            record[0] = tag[0];
            reader
                .read_exact(&mut record[1..record_size])
                .map_err(|error| {
                    if error.kind() == io::ErrorKind::UnexpectedEof {
                        invalid_cache("object index changed while being read")
                    } else {
                        error
                    }
                })?;
            let u32_at = |at: usize| u32::from_le_bytes(record[at..at + 4].try_into().unwrap());
            let u64_at = |at: usize| u64::from_le_bytes(record[at..at + 8].try_into().unwrap());
            if tag[0] == FIELD_TAG {
                let key = FieldKey {
                    stream: u64_at(5),
                    task: u64_at(13),
                    call: u64_at(21),
                    seq: u64_at(29),
                    phase: record[37],
                    object: u32_at(38),
                };
                set_field
                    .execute(params![i64::from(u32_at(1)), encode_key(&key).as_slice()])
                    .map_err(sql_error)?;
            } else {
                let number = i64::from(u32_at(1));
                let key: Option<Vec<u8>> = find_field
                    .query_row(params![number], |row| row.get(0))
                    .optional()
                    .map_err(sql_error)?;
                let Some(key) = key else {
                    stopped = true;
                    cursor = record_start;
                    break;
                };
                let object_offset = u64_at(5);
                let size = u32_at(13);
                let location = u64_at(17);
                object_offset
                    .checked_add(u64::from(size))
                    .ok_or_else(|| invalid_cache("object field extent overflows"))?;
                validate_record_chunk(size, location)?;
                let object_offset = ordered_u64(object_offset);
                let location = ordered_u64(location);
                put_chunk
                    .execute(params![
                        key.as_slice(),
                        object_offset.as_slice(),
                        i64::from(size),
                        location.as_slice(),
                    ])
                    .map_err(sql_error)?;
            }
            cursor = record_start + record_size as u64;
            progressed = true;
        }
        // A complete cache prefix is safe to continue from in the next bounded
        // transaction. A partial tail waits for the append to finish its record.
    }

    transaction
        .execute(
            "INSERT OR REPLACE INTO metadata(id,identity,source_len,indexed,stopped) \
             VALUES(?1,?2,?3,?4,?5)",
            params![
                STATE_ID,
                identity,
                ordered_u64(source_len).as_slice(),
                ordered_u64(cursor).as_slice(),
                if stopped { 1_i64 } else { 0_i64 },
            ],
        )
        .map_err(sql_error)?;
    if file.metadata()?.len() < source_len {
        return Err(invalid_cache("object index shrank while being indexed"));
    }
    verify_source(objects, identity, source_len)?;
    transaction.commit().map_err(sql_error).map(|()| {
        let done = stopped || cursor >= source_len || source_len < HEADER_SIZE || incomplete_tail;
        (done, progressed)
    })
}

fn validate_record_chunk(size: u32, location: u64) -> io::Result<()> {
    let offset = location & 0xffff_ffff;
    let end = offset
        .checked_add(u64::from(size))
        .ok_or_else(|| invalid_cache("object chunk extent overflows"))?;
    if size > MAX_CHUNK_SIZE || end > MAX_SEGMENT_SIZE {
        return Err(invalid_cache("object chunk exceeds its segment bounds"));
    }
    Ok(())
}

fn verify_source(objects: &Path, identity: &str, source_len: u64) -> io::Result<()> {
    let current = archive_io::open_regular(objects, Path::new(INDEX_FILE))?;
    let metadata = current.metadata()?;
    let current_identity = format!("{}:{}", metadata.dev(), metadata.ino());
    if current_identity != identity || metadata.len() < source_len {
        return Err(invalid_cache(
            "object index was replaced or shrank while being read",
        ));
    }
    Ok(())
}

fn read_exact_at(file: &File, buffer: &mut [u8], offset: u64) -> io::Result<()> {
    use std::os::unix::fs::FileExt;
    let mut done = 0;
    while done < buffer.len() {
        let read_offset = offset
            .checked_add(
                u64::try_from(done).map_err(|_| invalid_cache("index read offset overflows"))?,
            )
            .ok_or_else(|| invalid_cache("index read offset overflows"))?;
        match file.read_at(&mut buffer[done..], read_offset) {
            Ok(0) => return Err(io::ErrorKind::UnexpectedEof.into()),
            Ok(read) => done += read,
            Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
            Err(error) => return Err(error),
        }
    }
    Ok(())
}

fn encode_key(key: &FieldKey) -> [u8; 37] {
    let mut bytes = [0; 37];
    bytes[0..8].copy_from_slice(&key.stream.to_be_bytes());
    bytes[8..16].copy_from_slice(&key.task.to_be_bytes());
    bytes[16..24].copy_from_slice(&key.call.to_be_bytes());
    bytes[24..32].copy_from_slice(&key.seq.to_be_bytes());
    bytes[32] = key.phase;
    bytes[33..37].copy_from_slice(&key.object.to_be_bytes());
    bytes
}

/// Read and update the disposable index for `objects`, then query it.
/// `None` means the archive has no packed-object index.
pub(super) fn with_index<R>(
    objects: &Path,
    read: impl FnOnce(&Connection) -> io::Result<R>,
) -> io::Result<Option<R>> {
    let file = match archive_io::open_regular(objects, Path::new(INDEX_FILE)) {
        Ok(file) => file,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error),
    };
    let metadata = file.metadata()?;
    let source_len = metadata.len();
    let identity = format!("{}:{}", metadata.dev(), metadata.ino());
    let path = cache_path(objects)?;
    let handle = cached_connection(&path).map_err(|error| cache_database_error(error, &path))?;
    let mut connection = handle.lock().map_err(|_| {
        cache_database_error(io::Error::other("archive cache lock poisoned"), &path)
    })?;
    let result: io::Result<Option<R>> = (|| {
        update(objects, &mut connection, &file, &identity, source_len)?;
        let result = read(&connection)?;
        verify_source(objects, &identity, source_len)?;
        Ok(Some(result))
    })();
    match result {
        Err(error) if error.to_string().starts_with("packed-object index cache") => {
            Err(cache_database_error(error, &path))
        }
        other => other,
    }
}

#[cfg(test)]
pub(super) fn cache_file_for_test(objects: &Path) -> io::Result<PathBuf> {
    cache_path(objects)
}

#[cfg(test)]
pub(super) fn discard_cached_connection_for_test(objects: &Path) -> io::Result<()> {
    let path = cache_path(objects)?;
    let Some(connections) = CACHE_CONNECTIONS.get() else {
        return Ok(());
    };
    let removed = {
        let mut entries = connections
            .lock()
            .map_err(|_| retained_cache_error(io::Error::other("cache map lock poisoned")))?;
        entries
            .iter()
            .position(|(cached, _)| cached == &path)
            .map(|index| entries.remove(index).1)
    };
    drop(removed);
    Ok(())
}
