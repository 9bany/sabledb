use crate::{
    metadata::{CommonValueMetadata, Expiration},
    SableError, U8ArrayBuilder, U8ArrayReader,
};

/// Contains information regarding the AuditLog container metadata
#[derive(Clone, Debug, PartialEq, Eq)]
#[allow(dead_code)]
pub struct AuditLogValueMetadata {
    common: CommonValueMetadata,
    count: u64,
    /// The `feed_seq` of this AuditLog's most recent feed row (see
    /// `storage::AuditFeedKey`), or `0` if none has been recorded yet.
    /// `StorageAdapter::generate_id()` (the source of `feed_seq`) never returns `0`, so
    /// `0` is a safe sentinel for "none".
    feed_seq: u64,
}

#[derive(Default)]
pub struct AuditLogValueMetadataBuilder {
    audit_log_id: u64,
}

impl AuditLogValueMetadataBuilder {
    pub fn with_audit_log_id(mut self, audit_log_id: u64) -> Self {
        self.audit_log_id = audit_log_id;
        self
    }

    pub fn build(self) -> AuditLogValueMetadata {
        AuditLogValueMetadata {
            common: CommonValueMetadata::default()
                .set_audit_log()
                .with_uid(self.audit_log_id),
            count: 0,
            feed_seq: 0,
        }
    }
}

#[allow(dead_code)]
impl AuditLogValueMetadata {
    pub const SIZE: usize = 2 * std::mem::size_of::<u64>() + CommonValueMetadata::SIZE;

    pub fn builder() -> AuditLogValueMetadataBuilder {
        AuditLogValueMetadataBuilder::default()
    }

    pub fn new() -> Self {
        AuditLogValueMetadata {
            common: CommonValueMetadata::default().set_audit_log().with_uid(0),
            count: 0,
            feed_seq: 0,
        }
    }

    /// Serialise this object into `BytesMut`
    pub fn to_bytes(&self, builder: &mut U8ArrayBuilder) {
        self.common.to_bytes(builder);
        builder.write_u64(self.count);
        builder.write_u64(self.feed_seq);
    }

    pub fn from_bytes(reader: &mut U8ArrayReader) -> Result<Self, SableError> {
        let common = CommonValueMetadata::from_bytes(reader)?;
        let count = reader.read_u64().ok_or(SableError::SerialisationError)?;
        let feed_seq = reader.read_u64().ok_or(SableError::SerialisationError)?;
        Ok(AuditLogValueMetadata {
            common,
            count,
            feed_seq,
        })
    }

    pub fn expiration(&self) -> &Expiration {
        self.common.expiration()
    }

    pub fn expiration_mut(&mut self) -> &mut Expiration {
        self.common.expiration_mut()
    }

    pub fn id(&self) -> u64 {
        self.common.uid()
    }

    pub fn set_id(&mut self, audit_log_id: u64) {
        self.common.set_uid(audit_log_id);
    }

    pub fn count(&self) -> u64 {
        self.count
    }

    pub fn set_count(&mut self, count: u64) {
        self.count = count;
    }

    pub fn incr_count(&mut self) {
        self.count = self.count.saturating_add(1);
    }

    pub fn feed_seq(&self) -> u64 {
        self.feed_seq
    }

    pub fn set_feed_seq(&mut self, feed_seq: u64) {
        self.feed_seq = feed_seq;
    }
}

impl Default for AuditLogValueMetadata {
    fn default() -> Self {
        Self::new()
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
mod test {
    use super::*;
    use crate::{SableError, TimeUtils};

    #[test]
    fn test_packing() -> Result<(), SableError> {
        let mut md = AuditLogValueMetadata::new();
        md.expiration_mut().set_ttl_millis(30)?;
        md.set_id(42);
        md.set_count(15);
        md.set_feed_seq(99);

        let mut arr = bytes::BytesMut::with_capacity(AuditLogValueMetadata::SIZE);
        let mut builder = U8ArrayBuilder::with_buffer(&mut arr);
        md.to_bytes(&mut builder);
        assert_eq!(arr.len(), AuditLogValueMetadata::SIZE);

        // the buffer can be larger than `Metadata`
        arr.extend_from_slice(&[5, 5]);

        // Check that we can de-serialize it
        let mut reader = U8ArrayReader::with_buffer(&arr);
        let deserialized_md = AuditLogValueMetadata::from_bytes(&mut reader)?;

        // remove the deserialized part
        let _ = arr.split_to(AuditLogValueMetadata::SIZE);

        // change the source to 15
        let _ = md.expiration_mut().set_expire_timestamp_seconds(15);

        // confirm that the deserialized still has ttl value of 30
        assert_eq!(
            deserialized_md.expiration().ttl_ms,
            30,
            "Now: {}. deserialized_md = {:?}",
            TimeUtils::epoch_ms()?,
            deserialized_md,
        );
        assert!(deserialized_md.expiration().is_expired()? == false);
        assert_eq!(deserialized_md.id(), 42);
        assert_eq!(deserialized_md.count(), 15);
        assert_eq!(deserialized_md.feed_seq(), 99);
        assert_eq!(&arr[..], &[5, 5]);
        Ok(())
    }

    #[test]
    fn test_incr_count() {
        let mut md = AuditLogValueMetadata::new();
        assert_eq!(md.count(), 0);
        md.incr_count();
        md.incr_count();
        assert_eq!(md.count(), 2);
    }
}
