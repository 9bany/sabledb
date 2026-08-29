use crate::{
    metadata::{AuditLogValueMetadata, Bookkeeping, KeyPrefix, KeyType, ValueType},
    storage::DbWriteCache,
    CommonValueMetadata, FromBytes, FromU8Reader, PrimaryKeyMetadata, SableError, StorageAdapter,
    TimeUtils, ToBytes, ToU8Writer, U8ArrayBuilder, U8ArrayReader,
};
use bytes::BytesMut;

/// A single AuditLog entry.
///
/// `event` is a short tag (e.g. "Created", "Claimed", "RequeuedOnCrash") and `details`
/// is free-form, optional bytes (a comment, an agent id, an error message, ...). Both
/// fields are opaque to this layer -- callers decide what to put in them.
#[derive(Default, Clone, Debug, PartialEq, Eq)]
pub struct AuditItemValue {
    pub timestamp_ms: u64,
    pub event: BytesMut,
    pub details: BytesMut,
}

impl AuditItemValue {
    pub fn new(event: BytesMut, details: BytesMut) -> Result<Self, SableError> {
        Ok(AuditItemValue {
            timestamp_ms: TimeUtils::epoch_ms()?,
            event,
            details,
        })
    }
}

impl ToU8Writer for AuditItemValue {
    fn to_writer(&self, builder: &mut U8ArrayBuilder) {
        self.timestamp_ms.to_writer(builder);
        builder.write_message(&self.event);
        builder.write_bytes(&self.details);
    }
}

impl ToBytes for AuditItemValue {
    fn to_bytes(&self) -> BytesMut {
        let mut buffer = BytesMut::new();
        let mut builder = U8ArrayBuilder::with_buffer(&mut buffer);
        self.to_writer(&mut builder);
        buffer
    }
}

impl FromU8Reader for AuditItemValue {
    type Item = AuditItemValue;
    fn from_reader(reader: &mut U8ArrayReader) -> Option<Self::Item> {
        Some(AuditItemValue {
            timestamp_ms: u64::from_reader(reader)?,
            event: reader.read_message()?,
            details: reader.remaining()?,
        })
    }
}

impl FromBytes for AuditItemValue {
    type Item = AuditItemValue;
    fn from_bytes(bytes: &[u8]) -> Option<Self::Item> {
        let mut reader = U8ArrayReader::with_buffer(bytes);
        Self::from_reader(&mut reader)
    }
}

/// Encodes a single entry's storage key: `<prefix><audit_log_id><sequence>`.
/// `sequence` is written as a fixed-width big-endian `u64`, so RocksDB's natural
/// byte-order prefix iteration returns entries in append order without needing any
/// linked-list bookkeeping.
struct AuditItemKey {
    pub prefix: KeyPrefix,
    pub audit_log_id: u64,
    pub sequence: u64,
}

impl AuditItemKey {
    pub fn new(audit_log: &AuditLog, sequence: u64) -> Self {
        AuditItemKey {
            prefix: KeyPrefix::new(
                KeyType::AuditItem,
                audit_log.database_id(),
                audit_log.slot(),
            ),
            audit_log_id: audit_log.id(),
            sequence,
        }
    }
}

impl ToU8Writer for AuditItemKey {
    fn to_writer(&self, builder: &mut U8ArrayBuilder) {
        self.prefix.to_writer(builder);
        self.audit_log_id.to_writer(builder);
        self.sequence.to_writer(builder);
    }
}

impl ToBytes for AuditItemKey {
    fn to_bytes(&self) -> BytesMut {
        let mut buffer = BytesMut::new();
        let mut builder = U8ArrayBuilder::with_buffer(&mut buffer);
        self.to_writer(&mut builder);
        buffer
    }
}

/// The AuditLog container record: one per task-id, tracking the generated
/// `audit_log_id` (used to namespace this task's entries) and the entry count
/// (which doubles as the next sequence number).
#[derive(Default, Debug, PartialEq, Eq, Clone)]
struct AuditLog {
    pub key: PrimaryKeyMetadata,
    pub md: AuditLogValueMetadata,
}

impl AuditLog {
    pub fn id(&self) -> u64 {
        self.md.id()
    }

    pub fn count(&self) -> u64 {
        self.md.count()
    }

    pub fn incr_count(&mut self) {
        self.md.incr_count();
    }

    pub fn encode_key(&self) -> BytesMut {
        self.key.to_bytes()
    }

    pub fn encode_value(&self) -> BytesMut {
        let mut buffer = BytesMut::with_capacity(AuditLogValueMetadata::SIZE);
        let mut builder = U8ArrayBuilder::with_buffer(&mut buffer);
        self.md.to_bytes(&mut builder);
        buffer
    }

    pub fn slot(&self) -> u16 {
        self.key.slot()
    }

    pub fn database_id(&self) -> u16 {
        self.key.database_id()
    }

    /// The prefix shared by all entries belonging to this AuditLog, i.e.
    /// `<KeyType::AuditItem prefix><audit_log_id>` (no sequence).
    pub fn item_prefix(&self) -> BytesMut {
        let key_prefix = KeyPrefix::new(KeyType::AuditItem, self.database_id(), self.slot());
        let mut buffer = BytesMut::new();
        let mut builder = U8ArrayBuilder::with_buffer(&mut buffer);
        key_prefix.to_writer(&mut builder);
        self.id().to_writer(&mut builder);
        buffer
    }
}

//
// Public enumerators
//

#[derive(PartialEq, Eq, Debug)]
pub enum AuditAppendResult {
    /// An entry exists in the db for the given task-id, but for a different type
    WrongType,
    /// Returns the sequence number assigned to the new entry
    Some(u64),
}

#[derive(PartialEq, Eq, Debug)]
pub enum AuditRangeResult {
    /// An entry exists in the db for the given task-id, but for a different type
    WrongType,
    /// Returns the requested entries, in append order
    Some(Vec<AuditItemValue>),
}

// Internal enumerator
#[derive(Debug, PartialEq, Eq)]
enum GetAuditLogMetadataResult {
    /// An entry exists in the db for the given task-id, but for a different type
    WrongType,
    /// A match was found
    Some(AuditLog),
    /// No entry exists
    NotFound,
}

/// AuditLog DB wrapper. This class is specialized in reading/writing an append-only,
/// per-task audit trail. This is an internal storage-layer API -- it is not exposed as
/// a RESP command; TASK.* command handlers (not yet implemented) call it directly.
///
/// Locking strategy: this class does not lock anything and relies on the caller
/// to obtain the locks if needed
pub struct AuditDb<'a> {
    store: &'a StorageAdapter,
    db_id: u16,
    cache: Box<DbWriteCache<'a>>,
}

#[allow(dead_code)]
impl<'a> AuditDb<'a> {
    pub fn with_storage(store: &'a StorageAdapter, db_id: u16) -> Self {
        let cache = Box::new(DbWriteCache::with_storage(store));
        AuditDb {
            store,
            db_id,
            cache,
        }
    }

    /// Append a new entry to `task_id`'s AuditLog, creating the AuditLog if this is
    /// its first entry. Returns the sequence number assigned to the new entry.
    pub fn append(
        &mut self,
        task_id: &BytesMut,
        event: &BytesMut,
        details: &BytesMut,
    ) -> Result<AuditAppendResult, SableError> {
        let mut audit_log = match self.audit_log_metadata(task_id)? {
            GetAuditLogMetadataResult::WrongType => return Ok(AuditAppendResult::WrongType),
            GetAuditLogMetadataResult::NotFound => self.new_audit_log(task_id)?,
            GetAuditLogMetadataResult::Some(audit_log) => audit_log,
        };

        let sequence = audit_log.count();
        let item_key = AuditItemKey::new(&audit_log, sequence);
        let entry = AuditItemValue::new(event.clone(), details.clone())?;
        self.cache.put(&item_key.to_bytes(), entry.to_bytes())?;

        audit_log.incr_count();
        self.put_audit_log_metadata(&audit_log)?;
        self.cache.flush()?;
        Ok(AuditAppendResult::Some(sequence))
    }

    /// Delete `task_id`'s AuditLog container record. This does *not* delete the
    /// individual entries -- they are left as orphans (same as an overwritten List or
    /// Hash) and are reclaimed later by the Evictor's periodic sweep
    /// (`server::cron_thread::Cron::evict`), which is registered for
    /// `ValueType::AuditLog` / `KeyType::AuditItem`.
    pub fn delete(&mut self, task_id: &BytesMut) -> Result<(), SableError> {
        let internal_key = PrimaryKeyMetadata::new_primary_key(task_id, self.db_id);
        self.cache.delete(&internal_key)?;
        self.cache.flush()
    }

    /// Return entries for `task_id`, in append order, starting from sequence `from`
    /// (default `0`) and returning at most `limit` entries (default: 100).
    pub fn range(
        &self,
        task_id: &BytesMut,
        from: Option<u64>,
        limit: Option<usize>,
    ) -> Result<AuditRangeResult, SableError> {
        let audit_log = match self.audit_log_metadata(task_id)? {
            GetAuditLogMetadataResult::WrongType => return Ok(AuditRangeResult::WrongType),
            GetAuditLogMetadataResult::NotFound => {
                return Ok(AuditRangeResult::Some(Vec::default()))
            }
            GetAuditLogMetadataResult::Some(audit_log) => audit_log,
        };

        let from = from.unwrap_or(0);
        let limit = limit.unwrap_or(100);
        let prefix = audit_log.item_prefix();

        let mut result = Vec::<AuditItemValue>::new();
        let mut sequence = 0u64;
        let mut db_iter = self.store.create_iterator(&prefix)?;
        while db_iter.valid() {
            let Some((key, value)) = db_iter.key_value() else {
                break;
            };

            if !key.starts_with(&prefix) {
                break;
            }

            if sequence >= from {
                let entry =
                    AuditItemValue::from_bytes(value).ok_or(SableError::SerialisationError)?;
                result.push(entry);
                if result.len() >= limit {
                    break;
                }
            }
            sequence = sequence.saturating_add(1);
            db_iter.next();
        }
        Ok(AuditRangeResult::Some(result))
    }

    // ===-----------------------------
    // Private helpers
    // ===-----------------------------

    /// Load the AuditLog metadata for `task_id`
    fn audit_log_metadata(
        &self,
        task_id: &BytesMut,
    ) -> Result<GetAuditLogMetadataResult, SableError> {
        let encoded_key = PrimaryKeyMetadata::new_primary_key(task_id, self.db_id);
        let Some(value) = self.cache.get(&encoded_key)? else {
            return Ok(GetAuditLogMetadataResult::NotFound);
        };

        match self.try_decode_audit_log_value_metadata(&value)? {
            None => Ok(GetAuditLogMetadataResult::WrongType),
            Some(md) => {
                let key = PrimaryKeyMetadata::new(task_id, self.db_id);
                Ok(GetAuditLogMetadataResult::Some(AuditLog { key, md }))
            }
        }
    }

    /// Create a new AuditLog container record for `task_id`
    fn new_audit_log(&mut self, task_id: &BytesMut) -> Result<AuditLog, SableError> {
        let md = AuditLogValueMetadata::builder()
            .with_audit_log_id(self.store.generate_id())
            .build();
        let key = PrimaryKeyMetadata::new(task_id, self.db_id);
        let audit_log = AuditLog { key, md };
        self.put_audit_log_metadata(&audit_log)?;

        // Add a bookkeeping record so the orphan-eviction thread can clean up entries
        // if `task_id` is later overwritten by an unrelated type.
        let bookkeeping_record = Bookkeeping::new(self.db_id, audit_log.slot())
            .with_uid(audit_log.id())
            .with_value_type(ValueType::AuditLog)
            .to_bytes();
        self.cache.put(&bookkeeping_record, task_id.clone())?;
        Ok(audit_log)
    }

    /// Given raw bytes (read from the db) return whether it represents an
    /// `AuditLogValueMetadata`
    fn try_decode_audit_log_value_metadata(
        &self,
        value: &BytesMut,
    ) -> Result<Option<AuditLogValueMetadata>, SableError> {
        let mut reader = U8ArrayReader::with_buffer(value);
        let common_md = CommonValueMetadata::from_bytes(&mut reader)?;
        if !common_md.is_audit_log() {
            return Ok(None);
        }

        reader.rewind();
        let md = AuditLogValueMetadata::from_bytes(&mut reader)?;
        Ok(Some(md))
    }

    fn put_audit_log_metadata(&mut self, audit_log: &AuditLog) -> Result<(), SableError> {
        self.cache
            .put(&audit_log.encode_key(), audit_log.encode_value())?;
        Ok(())
    }
}

//  _    _ _   _ _____ _______      _______ ______  _____ _______ _____ _   _  _____
// | |  | | \ | |_   _|__   __|    |__   __|  ____|/ ____|__   __|_   _| \ | |/ ____|
// | |  | |  \| | | |    | |    _     | |  | |__  | (___    | |    | | |  \| | |  __|
// | |  | | . ` | | |    | |   / \    | |  |  __|  \___ \   | |    | | | . ` | | |_ |
// | |__| | |\  |_| |_   | |   \_/    | |  | |____ ____) |  | |   _| |_| |\  | |__| |
//  \____/|_| \_|_____|  |_|          |_|  |______|_____/   |_|  |_____|_| \_|\_____|
//
#[cfg(test)]
mod tests {
    use super::*;
    use crate::storage::{StorageAdapter, StorageOpenParams};
    use std::path::PathBuf;

    fn entry(event: &str, details: &str) -> (BytesMut, BytesMut) {
        (BytesMut::from(event), BytesMut::from(details))
    }

    #[test]
    fn test_append_and_range() {
        let (_deleter, db) = crate::tests::open_store();
        let mut audit_db = AuditDb::with_storage(&db, 0);

        let task_id = BytesMut::from("task-1");
        for i in 0..5 {
            let (event, details) = entry(&format!("event_{i}"), &format!("details_{i}"));
            let res = audit_db.append(&task_id, &event, &details).unwrap();
            assert_eq!(res, AuditAppendResult::Some(i));
        }

        let AuditRangeResult::Some(entries) = audit_db.range(&task_id, None, None).unwrap() else {
            panic!("Expected AuditRangeResult::Some");
        };
        assert_eq!(entries.len(), 5);
        for (i, e) in entries.iter().enumerate() {
            assert_eq!(e.event, BytesMut::from(format!("event_{i}").as_str()));
            assert_eq!(e.details, BytesMut::from(format!("details_{i}").as_str()));
        }
    }

    #[test]
    fn test_range_from_and_limit() {
        let (_deleter, db) = crate::tests::open_store();
        let mut audit_db = AuditDb::with_storage(&db, 0);

        let task_id = BytesMut::from("task-1");
        for i in 0..10 {
            let (event, details) = entry(&format!("event_{i}"), "");
            audit_db.append(&task_id, &event, &details).unwrap();
        }

        let AuditRangeResult::Some(entries) = audit_db.range(&task_id, Some(3), Some(4)).unwrap()
        else {
            panic!("Expected AuditRangeResult::Some");
        };
        assert_eq!(entries.len(), 4);
        assert_eq!(entries.first().unwrap().event, BytesMut::from("event_3"));
        assert_eq!(entries.last().unwrap().event, BytesMut::from("event_6"));
    }

    #[test]
    fn test_tasks_do_not_share_entries() {
        let (_deleter, db) = crate::tests::open_store();
        let mut audit_db = AuditDb::with_storage(&db, 0);

        let task_a = BytesMut::from("task-a");
        let task_b = BytesMut::from("task-b");

        let (event, details) = entry("Created", "");
        audit_db.append(&task_a, &event, &details).unwrap();
        let (event, details) = entry("Claimed", "agent-1");
        audit_db.append(&task_b, &event, &details).unwrap();
        audit_db.append(&task_b, &event, &details).unwrap();

        let AuditRangeResult::Some(a_entries) = audit_db.range(&task_a, None, None).unwrap() else {
            panic!("Expected AuditRangeResult::Some");
        };
        let AuditRangeResult::Some(b_entries) = audit_db.range(&task_b, None, None).unwrap() else {
            panic!("Expected AuditRangeResult::Some");
        };
        assert_eq!(a_entries.len(), 1);
        assert_eq!(b_entries.len(), 2);
    }

    #[test]
    fn test_unknown_task_returns_empty_range() {
        let (_deleter, db) = crate::tests::open_store();
        let audit_db = AuditDb::with_storage(&db, 0);

        let task_id = BytesMut::from("no-such-task");
        let AuditRangeResult::Some(entries) = audit_db.range(&task_id, None, None).unwrap() else {
            panic!("Expected AuditRangeResult::Some");
        };
        assert!(entries.is_empty());
    }

    /// AuditDb writes go through the same `DbWriteCache` -> RocksDB path as every other
    /// type, so they replicate the same way: as raw Put/Del records streamed from the
    /// primary's RocksDB change log (`StorageAdapter::storage_updates_since`) and
    /// replayed on the replica (`StorageAdapter::apply_storage_updates`) -- no
    /// AuditLog-specific replication code exists or is needed.
    /// `storage_updates_since` reads from the RocksDB WAL, so (unlike the other tests
    /// in this file) both stores here must be opened with the WAL enabled --
    /// `crate::tests::open_store()` disables it for speed.
    fn open_store_with_wal(name: &str) -> (String, StorageAdapter) {
        let database_base_dir = std::env::temp_dir()
            .to_path_buf()
            .display()
            .to_string()
            .replace('\\', "/");
        let database_fullpath = format!(
            "{}/sabledb_tests/{}_{}.db",
            database_base_dir,
            name,
            crate::TimeUtils::epoch_micros().unwrap_or(0)
        );
        let db_path = PathBuf::from(&database_fullpath);
        let _ = std::fs::create_dir_all(db_path.parent().unwrap());

        let open_params = StorageOpenParams::default()
            .set_compression(false)
            .set_cache_size(64)
            .set_path(&db_path)
            .set_wal_disabled(false);

        let mut store = StorageAdapter::default();
        store.open(open_params).unwrap();
        (database_fullpath, store)
    }

    #[test]
    fn test_audit_log_replication() {
        use crate::storage::GetChangesLimits;
        use std::rc::Rc;

        let (primary_path, primary_store) = open_store_with_wal("audit_repl_primary");
        let (replica_path, replica_store) = open_store_with_wal("audit_repl_replica");
        let limits = Rc::new(GetChangesLimits::builder().build());

        let task_id = BytesMut::from("task-repl");

        // Phase 1: append entries on the primary, replicate the resulting Puts
        {
            let mut primary_audit_db = AuditDb::with_storage(&primary_store, 0);
            for i in 0..4 {
                let (event, details) = entry(&format!("event_{i}"), "");
                primary_audit_db.append(&task_id, &event, &details).unwrap();
            }
        }

        let changes = primary_store
            .storage_updates_since(0, limits.clone())
            .unwrap();
        assert!(changes.changes_count > 0);
        replica_store.apply_storage_updates(&changes).unwrap();

        let replica_audit_db = AuditDb::with_storage(&replica_store, 0);
        let AuditRangeResult::Some(entries) = replica_audit_db.range(&task_id, None, None).unwrap()
        else {
            panic!("Expected AuditRangeResult::Some");
        };
        assert_eq!(entries.len(), 4);
        for (i, e) in entries.iter().enumerate() {
            assert_eq!(e.event, BytesMut::from(format!("event_{i}").as_str()));
        }

        // Phase 2: delete the AuditLog container on the primary, replicate the tombstone
        let next_batch_seq = changes.end_seq_number;
        {
            let mut primary_audit_db = AuditDb::with_storage(&primary_store, 0);
            primary_audit_db.delete(&task_id).unwrap();
        }

        let changes = primary_store
            .storage_updates_since(next_batch_seq, limits)
            .unwrap();
        assert!(changes.changes_count > 0);
        replica_store.apply_storage_updates(&changes).unwrap();

        let AuditRangeResult::Some(entries) = replica_audit_db.range(&task_id, None, None).unwrap()
        else {
            panic!("Expected AuditRangeResult::Some");
        };
        assert!(entries.is_empty());

        drop(primary_store);
        drop(replica_store);
        let _ = std::fs::remove_dir_all(&primary_path);
        let _ = std::fs::remove_dir_all(&replica_path);
    }

    /// Covers Task 0.1's "Done when" criterion: entries survive a SableDB restart.
    #[test]
    fn test_entries_persist_across_restart() {
        let database_base_dir = std::env::temp_dir()
            .to_path_buf()
            .display()
            .to_string()
            .replace('\\', "/");
        let database_fullpath = format!(
            "{}/sabledb_tests/audit_restart_{}.db",
            database_base_dir,
            crate::TimeUtils::epoch_micros().unwrap_or(0)
        );
        let _ = std::fs::create_dir_all(
            PathBuf::from(&database_fullpath)
                .parent()
                .unwrap()
                .to_path_buf(),
        );
        let db_path = PathBuf::from(&database_fullpath);

        let task_id = BytesMut::from("task-restart");
        {
            let open_params = StorageOpenParams::default()
                .set_compression(false)
                .set_cache_size(64)
                .set_path(&db_path)
                .set_wal_disabled(false);

            let mut store = StorageAdapter::default();
            store.open(open_params).unwrap();
            let mut audit_db = AuditDb::with_storage(&store, 0);
            for i in 0..3 {
                let (event, details) = entry(&format!("event_{i}"), "");
                audit_db.append(&task_id, &event, &details).unwrap();
            }
            // `store` (and its RocksDB handle) is dropped at the end of this scope,
            // simulating a SableDB restart.
        }

        let reopened_store = {
            let open_params = StorageOpenParams::default()
                .set_compression(false)
                .set_cache_size(64)
                .set_path(&db_path)
                .set_wal_disabled(false);
            let mut store = StorageAdapter::default();
            store.open(open_params).unwrap();
            store
        };
        let audit_db = AuditDb::with_storage(&reopened_store, 0);
        let AuditRangeResult::Some(entries) = audit_db.range(&task_id, None, None).unwrap() else {
            panic!("Expected AuditRangeResult::Some");
        };
        assert_eq!(entries.len(), 3);
        assert_eq!(entries[0].event, BytesMut::from("event_0"));
        assert_eq!(entries[2].event, BytesMut::from("event_2"));

        let _ = std::fs::remove_dir_all(&database_fullpath);
    }
}
