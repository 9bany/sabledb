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

    pub fn feed_seq(&self) -> u64 {
        self.md.feed_seq()
    }

    pub fn set_feed_seq(&mut self, feed_seq: u64) {
        self.md.set_feed_seq(feed_seq);
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

/// An AuditLog lifecycle event: its container was either created (first entry
/// appended for a task-id) or deleted.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum AuditFeedEventKind {
    Created = 0,
    Deleted = 1,
}

impl AuditFeedEventKind {
    fn from_u8(v: u8) -> Option<Self> {
        match v {
            0 => Some(Self::Created),
            1 => Some(Self::Deleted),
            _ => None,
        }
    }
}

/// One row in the AuditLog feed: `task_id`'s AuditLog was created or deleted, at
/// `timestamp_ms`. The feed is a shard-local, chronologically ordered index (see
/// `AuditFeedKey`) of these lifecycle events across *all* tasks, used to page through
/// recent activity without knowing task-ids up front (see `AuditDb::feed`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AuditFeedEntry {
    pub timestamp_ms: u64,
    pub kind: AuditFeedEventKind,
    pub task_id: BytesMut,
}

impl ToU8Writer for AuditFeedEntry {
    fn to_writer(&self, builder: &mut U8ArrayBuilder) {
        self.timestamp_ms.to_writer(builder);
        builder.write_u8(self.kind as u8);
        builder.write_bytes(&self.task_id);
    }
}

impl ToBytes for AuditFeedEntry {
    fn to_bytes(&self) -> BytesMut {
        let mut buffer = BytesMut::new();
        let mut builder = U8ArrayBuilder::with_buffer(&mut buffer);
        self.to_writer(&mut builder);
        buffer
    }
}

impl FromU8Reader for AuditFeedEntry {
    type Item = AuditFeedEntry;
    fn from_reader(reader: &mut U8ArrayReader) -> Option<Self::Item> {
        Some(AuditFeedEntry {
            timestamp_ms: u64::from_reader(reader)?,
            kind: AuditFeedEventKind::from_u8(reader.read_u8()?)?,
            task_id: reader.remaining()?,
        })
    }
}

impl FromBytes for AuditFeedEntry {
    type Item = AuditFeedEntry;
    fn from_bytes(bytes: &[u8]) -> Option<Self::Item> {
        let mut reader = U8ArrayReader::with_buffer(bytes);
        Self::from_reader(&mut reader)
    }
}

/// Encodes a feed row's storage key: `<KeyType::AuditFeedItem><db_id><feed_seq>`.
///
/// Deliberately does *not* go through `KeyPrefix`/`PrimaryKeyMetadata` -- there is no
/// per-task `slot` to partition by here: the feed spans every task-id in the database
/// and is inherently shard-local (see `AuditDb::feed`'s docs), so it does not migrate
/// with any single task's slot.
///
/// `feed_seq` comes from `StorageAdapter::generate_id()`, the same process-local
/// monotonic counter used for `audit_log_id`s (and list/hash/... ids) -- it is *not*
/// contiguous like a per-task sequence, so `AuditDb::feed`'s `from` cursor is
/// implemented via seek-to-key, not position counting.
struct AuditFeedKey {
    db_id: u16,
    feed_seq: u64,
}

impl AuditFeedKey {
    /// The prefix shared by every feed row in `db_id` (no `feed_seq`).
    fn type_prefix(db_id: u16) -> BytesMut {
        let mut buffer = BytesMut::new();
        let mut builder = U8ArrayBuilder::with_buffer(&mut buffer);
        builder.write_key_type(KeyType::AuditFeedItem);
        builder.write_u16(db_id);
        buffer
    }
}

impl ToU8Writer for AuditFeedKey {
    fn to_writer(&self, builder: &mut U8ArrayBuilder) {
        builder.write_key_type(KeyType::AuditFeedItem);
        builder.write_u16(self.db_id);
        builder.write_u64(self.feed_seq);
    }
}

impl ToBytes for AuditFeedKey {
    fn to_bytes(&self) -> BytesMut {
        let mut buffer = BytesMut::new();
        let mut builder = U8ArrayBuilder::with_buffer(&mut buffer);
        self.to_writer(&mut builder);
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

#[derive(PartialEq, Eq, Debug)]
pub enum AuditFeedResult {
    /// Returns `(feed_seq, entry)` pairs, oldest first
    Some(Vec<(u64, AuditFeedEntry)>),
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
/// per-task audit trail. It's exposed to RESP clients via `AUDIT.APPEND`/`AUDIT.RANGE`/
/// `AUDIT.FEED` (`commands/audit_commands.rs`) and `DEL` (for AuditLog keys, see
/// `delete()`'s doc below); future TASK.* command handlers would also call it directly.
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

    /// Delete `task_id`'s AuditLog container record, if `task_id` currently holds an
    /// AuditLog (a no-op otherwise -- including if it holds an unrelated type). This
    /// does *not* delete the individual entries -- they are left as orphans (same as
    /// an overwritten List or Hash) and are reclaimed later by the Evictor's periodic
    /// sweep (`server::cron_thread::Cron::evict`), which is registered for
    /// `ValueType::AuditLog` / `KeyType::AuditItem`.
    ///
    /// The feed's `Created` row for this AuditLog is replaced with a `Deleted` row
    /// (not left stale alongside it) -- see `AuditLogValueMetadata::feed_seq`'s doc.
    ///
    /// Note: the generic `DEL` RESP command routes here for keys holding an AuditLog
    /// (see `GenericCommands::del` in `commands/generic_commands.rs`), so this is not
    /// merely an internal-only path -- it is how `DEL task-id` behaves for an AuditLog
    /// key.
    pub fn delete(&mut self, task_id: &BytesMut) -> Result<(), SableError> {
        let audit_log = match self.audit_log_metadata(task_id)? {
            GetAuditLogMetadataResult::NotFound | GetAuditLogMetadataResult::WrongType => {
                return Ok(())
            }
            GetAuditLogMetadataResult::Some(audit_log) => audit_log,
        };

        let internal_key = PrimaryKeyMetadata::new_primary_key(task_id, self.db_id);
        self.cache.delete(&internal_key)?;
        self.delete_feed_entry(audit_log.feed_seq())?;
        self.push_feed_entry(task_id, AuditFeedEventKind::Deleted)?;
        self.cache.flush()
    }

    /// Return feed entries (AuditLog create/delete lifecycle events across *all*
    /// task-ids in this database), oldest first, starting at feed sequence `from`
    /// (default `0`) and returning at most `limit` entries (default: unbounded).
    ///
    /// This index is shard-local: `feed_seq` comes from a process-local counter, so
    /// entries from different SableDB nodes are not comparable or mergeable by
    /// `feed_seq`. A caller polling multiple shards should track a cursor per shard and
    /// merge results by each entry's `timestamp_ms` instead.
    pub fn feed(&self, from: Option<u64>, limit: Option<usize>) -> Result<AuditFeedResult, SableError> {
        let type_prefix = AuditFeedKey::type_prefix(self.db_id);
        let start_key = AuditFeedKey {
            db_id: self.db_id,
            feed_seq: from.unwrap_or(0),
        }
        .to_bytes();
        let limit = limit.unwrap_or(usize::MAX);

        let mut result = Vec::<(u64, AuditFeedEntry)>::new();
        let mut db_iter = self.store.create_iterator(&start_key)?;
        while db_iter.valid() {
            let Some((key, value)) = db_iter.key_value() else {
                break;
            };

            if !key.starts_with(&type_prefix) {
                break;
            }

            let mut reader = U8ArrayReader::with_buffer(key);
            reader.advance(type_prefix.len())?;
            let seq = reader.read_u64().ok_or(SableError::SerialisationError)?;

            let entry = AuditFeedEntry::from_bytes(value).ok_or(SableError::SerialisationError)?;
            result.push((seq, entry));
            if result.len() >= limit {
                break;
            }
            db_iter.next();
        }
        Ok(AuditFeedResult::Some(result))
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
        let mut audit_log = AuditLog { key, md };

        // Add a bookkeeping record so the orphan-eviction thread can clean up entries
        // if `task_id` is later overwritten by an unrelated type.
        let bookkeeping_record = Bookkeeping::new(self.db_id, audit_log.slot())
            .with_uid(audit_log.id())
            .with_value_type(ValueType::AuditLog)
            .to_bytes();
        self.cache.put(&bookkeeping_record, task_id.clone())?;

        // Record this creation in the feed, and remember where, so `delete()` can
        // replace this row (rather than leaving it stale) once the AuditLog is gone.
        let feed_seq = self.push_feed_entry(task_id, AuditFeedEventKind::Created)?;
        audit_log.set_feed_seq(feed_seq);

        self.put_audit_log_metadata(&audit_log)?;
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

    /// Append a `kind` feed row for `task_id`, timestamped now
    /// Push a `kind` feed row for `task_id`, timestamped now, and return its
    /// `feed_seq`
    fn push_feed_entry(
        &mut self,
        task_id: &BytesMut,
        kind: AuditFeedEventKind,
    ) -> Result<u64, SableError> {
        let feed_seq = self.store.generate_id();
        let key = AuditFeedKey {
            db_id: self.db_id,
            feed_seq,
        }
        .to_bytes();
        let entry = AuditFeedEntry {
            timestamp_ms: TimeUtils::epoch_ms()?,
            kind,
            task_id: task_id.clone(),
        };
        self.cache.put(&key, entry.to_bytes())?;
        Ok(feed_seq)
    }

    /// Delete the feed row at `feed_seq`, if `feed_seq != 0` (see
    /// `AuditLogValueMetadata::feed_seq`'s doc for the `0` sentinel)
    fn delete_feed_entry(&mut self, feed_seq: u64) -> Result<(), SableError> {
        if feed_seq == 0 {
            return Ok(());
        }
        let key = AuditFeedKey {
            db_id: self.db_id,
            feed_seq,
        }
        .to_bytes();
        self.cache.delete(&key)
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
    use crate::storage::{PutFlags, StorageAdapter, StorageOpenParams, StringGetResult, StringsDb};
    use crate::StringValueMetadata;
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

    #[test]
    fn test_feed_records_create_and_delete() {
        let (_deleter, db) = crate::tests::open_store();
        let mut audit_db = AuditDb::with_storage(&db, 0);

        let task_a = BytesMut::from("task-a");
        let task_b = BytesMut::from("task-b");

        // Only the *first* append for a task should push a Created feed row
        let (event, details) = entry("Created", "");
        audit_db.append(&task_a, &event, &details).unwrap();
        audit_db.append(&task_a, &event, &details).unwrap();
        audit_db.append(&task_b, &event, &details).unwrap();

        audit_db.delete(&task_a).unwrap();
        // Deleting a task with no AuditLog is a no-op and must not push a feed row
        audit_db.delete(&BytesMut::from("never-existed")).unwrap();

        // task-a's stale `Created` row is replaced (not left alongside) its `Deleted`
        // row, so the feed has 2 rows total, not 3.
        let AuditFeedResult::Some(feed) = audit_db.feed(None, None).unwrap();
        assert_eq!(feed.len(), 2);

        let (_, e0) = &feed[0];
        assert_eq!(e0.kind, AuditFeedEventKind::Created);
        assert_eq!(e0.task_id, task_b);

        let (_, e1) = &feed[1];
        assert_eq!(e1.kind, AuditFeedEventKind::Deleted);
        assert_eq!(e1.task_id, task_a);

        // feed_seq values must be strictly increasing (append order)
        assert!(feed[0].0 < feed[1].0);
    }

    #[test]
    fn test_delete_is_noop_for_wrong_type() {
        let (_deleter, db) = crate::tests::open_store();
        let mut audit_db = AuditDb::with_storage(&db, 0);

        let task_id = BytesMut::from("not-an-auditlog");
        let (event, details) = entry("Created", "");
        audit_db.append(&task_id, &event, &details).unwrap();

        // overwrite the AuditLog's primary key with an unrelated type
        let mut strings_db = StringsDb::with_storage(&db, 0);
        strings_db
            .put(
                &task_id,
                &BytesMut::from("a string value"),
                &StringValueMetadata::default(),
                PutFlags::Override,
            )
            .unwrap();

        // delete() must leave the (now unrelated) key and the feed untouched
        audit_db.delete(&task_id).unwrap();

        let StringGetResult::Some((value, _)) = strings_db.get(&task_id).unwrap() else {
            panic!("Expected the string value to still be present");
        };
        assert_eq!(value, BytesMut::from("a string value"));

        let AuditFeedResult::Some(feed) = audit_db.feed(None, None).unwrap();
        assert_eq!(feed.len(), 1);
        assert_eq!(feed[0].1.kind, AuditFeedEventKind::Created);
    }

    #[test]
    fn test_feed_from_and_limit() {
        let (_deleter, db) = crate::tests::open_store();
        let mut audit_db = AuditDb::with_storage(&db, 0);

        let (event, details) = entry("Created", "");
        for i in 0..5 {
            let task_id = BytesMut::from(format!("task-{i}").as_str());
            audit_db.append(&task_id, &event, &details).unwrap();
        }

        let AuditFeedResult::Some(all) = audit_db.feed(None, None).unwrap();
        assert_eq!(all.len(), 5);

        // Resume from the 3rd entry's own feed_seq: it (and everything after) should
        // come back, nothing before it.
        let cursor = all[2].0;
        let AuditFeedResult::Some(page) = audit_db.feed(Some(cursor), Some(2)).unwrap();
        assert_eq!(page.len(), 2);
        assert_eq!(page[0].0, all[2].0);
        assert_eq!(page[1].0, all[3].0);
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
