use crate::{
    commands::{HandleCommandResult, Strings},
    server::ClientState,
    storage::{AuditAppendResult, AuditDb, AuditFeedEventKind, AuditFeedResult, AuditRangeResult},
    BytesMutUtils, LockManager, RespBuilderV2, SableError, ValkeyCommand, ValkeyCommandName,
};
use bytes::BytesMut;
use std::rc::Rc;
use tokio::io::AsyncWriteExt;

#[allow(dead_code)]
pub struct AuditCommands {}

#[allow(dead_code)]
impl AuditCommands {
    /// Main entry point for all AuditLog commands
    pub async fn handle_command(
        client_state: Rc<ClientState>,
        command: Rc<ValkeyCommand>,
        _tx: &mut (impl AsyncWriteExt + std::marker::Unpin),
    ) -> Result<HandleCommandResult, SableError> {
        let mut response_buffer = BytesMut::with_capacity(256);
        match command.metadata().name() {
            ValkeyCommandName::AuditAppend => {
                Self::append(client_state, command, &mut response_buffer).await?;
            }
            ValkeyCommandName::AuditRange => {
                Self::range(client_state, command, &mut response_buffer).await?;
            }
            ValkeyCommandName::AuditFeed => {
                Self::feed(client_state, command, &mut response_buffer).await?;
            }
            _ => {
                return Err(SableError::InvalidArgument(format!(
                    "Non audit command {}",
                    command.main_command()
                )));
            }
        }
        Ok(HandleCommandResult::ResponseBufferUpdated(response_buffer))
    }

    /// `AUDIT.APPEND <task-id> <event> [<details>]`
    ///
    /// Append a new entry to `task-id`'s AuditLog, creating it if this is its first
    /// entry. `details` defaults to an empty string when omitted. Returns the sequence
    /// number assigned to the new entry.
    async fn append(
        client_state: Rc<ClientState>,
        command: Rc<ValkeyCommand>,
        response_buffer: &mut BytesMut,
    ) -> Result<(), SableError> {
        check_args_count!(command, 3, response_buffer);
        let builder = RespBuilderV2::default();
        if command.arg_count() > 4 {
            builder_return_syntax_error!(builder, response_buffer);
        }

        let task_id = command_arg_at!(command, 1);
        let event = command_arg_at!(command, 2);
        let empty_details = BytesMut::default();
        let details = command.arg(3).unwrap_or(&empty_details);

        let _unused = LockManager::lock(task_id, client_state.clone(), command.clone()).await?;
        let mut audit_db =
            AuditDb::with_storage(client_state.database(), client_state.database_id());
        match audit_db.append(task_id, event, details)? {
            AuditAppendResult::Some(sequence) => {
                builder.number(response_buffer, sequence, false);
            }
            AuditAppendResult::WrongType => {
                builder_return_wrong_type!(builder, response_buffer);
            }
        }
        Ok(())
    }

    /// `AUDIT.RANGE <task-id> [FROM <seq>] [LIMIT <n>]`
    ///
    /// Return entries for `task-id`, in append order, starting from sequence `FROM`
    /// (default `0`) and returning at most `LIMIT` entries (default: unbounded). Each
    /// entry is returned as `[sequence, timestamp_ms, event, details]`.
    async fn range(
        client_state: Rc<ClientState>,
        command: Rc<ValkeyCommand>,
        response_buffer: &mut BytesMut,
    ) -> Result<(), SableError> {
        check_args_count!(command, 2, response_buffer);
        let task_id = command_arg_at!(command, 1);

        let mut iter = command.args_vec().iter();
        iter.next(); // audit.range
        iter.next(); // task-id

        let mut from: Option<u64> = None;
        let mut limit: Option<usize> = None;

        let builder = RespBuilderV2::default();
        while let (Some(arg), Some(value)) = (iter.next(), iter.next()) {
            let keyword_lowercase = BytesMutUtils::to_string(arg).to_lowercase();
            match keyword_lowercase.as_str() {
                "from" => {
                    from = Some(to_number!(value, u64, response_buffer, Ok(())));
                }
                "limit" => {
                    limit = Some(to_number!(value, usize, response_buffer, Ok(())));
                }
                _ => {
                    builder_return_syntax_error!(builder, response_buffer);
                }
            }
        }

        let _unused = LockManager::lock(task_id, client_state.clone(), command.clone()).await?;
        let audit_db = AuditDb::with_storage(client_state.database(), client_state.database_id());
        match audit_db.range(task_id, from, limit)? {
            AuditRangeResult::WrongType => {
                builder_return_wrong_type!(builder, response_buffer);
            }
            AuditRangeResult::Some(items) => {
                // Entries are contiguous in sequence (never individually deleted), so
                // the i-th returned entry's sequence is simply `from + i`.
                let start_seq = from.unwrap_or(0);
                builder.add_array_len(response_buffer, items.len());
                for (i, item) in items.iter().enumerate() {
                    let seq = start_seq.saturating_add(i as u64);
                    builder.add_array_len(response_buffer, 4);
                    builder.add_number(response_buffer, seq, false);
                    builder.add_number(response_buffer, item.timestamp_ms, false);
                    builder.add_bulk_string(response_buffer, &item.event);
                    builder.add_bulk_string(response_buffer, &item.details);
                }
            }
        }
        Ok(())
    }

    /// `AUDIT.FEED [FROM <seq>] [LIMIT <n>]`
    ///
    /// Return AuditLog create/delete lifecycle events across *all* task-ids in the
    /// current database, oldest first, starting at feed sequence `FROM` (default `0`)
    /// and returning at most `LIMIT` entries (default: unbounded). Each entry is
    /// returned as `[sequence, timestamp_ms, kind, task_id]`, where `kind` is
    /// `"created"` or `"deleted"`.
    ///
    /// This index is shard-local (see `AuditDb::feed`'s docs): a caller polling a
    /// cluster should discover shards via `CLUSTER NODES`, track a cursor per shard,
    /// and merge results by `timestamp_ms` -- not by `sequence`, which is only
    /// comparable within one shard.
    async fn feed(
        client_state: Rc<ClientState>,
        command: Rc<ValkeyCommand>,
        response_buffer: &mut BytesMut,
    ) -> Result<(), SableError> {
        check_args_count!(command, 1, response_buffer);

        let mut iter = command.args_vec().iter();
        iter.next(); // audit.feed

        let mut from: Option<u64> = None;
        let mut limit: Option<usize> = None;

        let builder = RespBuilderV2::default();
        while let (Some(arg), Some(value)) = (iter.next(), iter.next()) {
            let keyword_lowercase = BytesMutUtils::to_string(arg).to_lowercase();
            match keyword_lowercase.as_str() {
                "from" => {
                    from = Some(to_number!(value, u64, response_buffer, Ok(())));
                }
                "limit" => {
                    limit = Some(to_number!(value, usize, response_buffer, Ok(())));
                }
                _ => {
                    builder_return_syntax_error!(builder, response_buffer);
                }
            }
        }

        let audit_db = AuditDb::with_storage(client_state.database(), client_state.database_id());
        let AuditFeedResult::Some(rows) = audit_db.feed(from, limit)?;
        builder.add_array_len(response_buffer, rows.len());
        for (seq, feed_entry) in &rows {
            let kind = match feed_entry.kind {
                AuditFeedEventKind::Created => "created",
                AuditFeedEventKind::Deleted => "deleted",
            };
            builder.add_array_len(response_buffer, 4);
            builder.add_number(response_buffer, *seq, false);
            builder.add_number(response_buffer, feed_entry.timestamp_ms, false);
            builder.add_bulk_string(response_buffer, kind.as_bytes());
            builder.add_bulk_string(response_buffer, &feed_entry.task_id);
        }
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
    #[allow(unused_imports)]
    use crate::{
        commands::ClientNextAction, Client, RespResponseParserV2, ResponseParseResult, ServerState,
        ValkeyObject,
    };
    use std::rc::Rc;
    use std::sync::Arc;
    use test_case::test_case;

    #[test_case(vec![
        (vec!["audit.append", "audit_append_t1", "Created"], ":0\r\n"),
        (vec!["audit.append", "audit_append_t1", "Claimed", "agent-1"], ":1\r\n"),
        (vec!["audit.append", "audit_append_t1", "Completed"], ":2\r\n"),
        (vec!["audit.append", "audit_append_t1"], "-ERR wrong number of arguments for 'audit.append' command\r\n"),
        (vec!["audit.append", "audit_append_t1", "e", "d", "extra"], "-ERR syntax error\r\n"),
        (vec!["set", "audit_append_wrongtype", "value"], "+OK\r\n"),
        (vec!["audit.append", "audit_append_wrongtype", "Created"], "-WRONGTYPE Operation against a key holding the wrong kind of value\r\n"),
        ], "audit_append"; "audit_append")]
    #[test_case(vec![
        (vec!["audit.range", "audit_range_no_such_task"], "*0\r\n"),
        (vec!["audit.range"], "-ERR wrong number of arguments for 'audit.range' command\r\n"),
        (vec!["set", "audit_range_wrongtype", "value"], "+OK\r\n"),
        (vec!["audit.range", "audit_range_wrongtype"], "-WRONGTYPE Operation against a key holding the wrong kind of value\r\n"),
        (vec!["audit.append", "audit_range_t1", "Created"], ":0\r\n"),
        (vec!["audit.range", "audit_range_t1", "from", "not_a_number"], "-ERR value is not an integer or out of range\r\n"),
        (vec!["audit.range", "audit_range_t1", "limit", "not_a_number"], "-ERR value is not an integer or out of range\r\n"),
        (vec!["audit.range", "audit_range_t1", "bogus", "1"], "-ERR syntax error\r\n"),
        ], "audit_range"; "audit_range")]
    #[test_case(vec![
        (vec!["audit.feed"], "*0\r\n"),
        (vec!["audit.feed", "from", "not_a_number"], "-ERR value is not an integer or out of range\r\n"),
        (vec!["audit.feed", "limit", "not_a_number"], "-ERR value is not an integer or out of range\r\n"),
        (vec!["audit.feed", "bogus", "1"], "-ERR syntax error\r\n"),
        ], "audit_feed"; "audit_feed")]
    fn test_audit_commands(args_vec: Vec<(Vec<&'static str>, &'static str)>, test_name: &str) {
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async move {
            let (_guard, store) = crate::tests::open_store();
            let client = Client::new(Arc::<ServerState>::default(), store, None);

            for (args, expected_value) in args_vec {
                let mut sink = crate::tests::ResponseSink::with_name(test_name).await;
                let cmd = Rc::new(ValkeyCommand::for_test(args));
                match Client::handle_command(client.inner(), cmd.clone(), &mut sink.fp)
                    .await
                    .unwrap()
                {
                    ClientNextAction::SendResponse(response_buffer) => {
                        assert_eq!(
                            BytesMutUtils::to_string(&response_buffer).as_str(),
                            expected_value
                        );
                    }
                    ClientNextAction::NoAction => {
                        assert_eq!(&sink.read_all().await, expected_value);
                    }
                    other => panic!("unexpected client next action for {:?}: {:?}", cmd, other),
                }
            }
        });
    }

    /// Content of AUDIT.RANGE's response can't be pinned down with a fixed expected
    /// string (each entry's `timestamp_ms` is real wall-clock time), so this test
    /// parses the RESP reply structurally instead.
    #[test]
    fn test_audit_range_content() {
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async move {
            let (_guard, store) = crate::tests::open_store();
            let client = Client::new(Arc::<ServerState>::default(), store, None);

            async fn run(client: &Client, args: Vec<&'static str>) -> String {
                let mut sink = crate::tests::ResponseSink::with_name("audit_range_content").await;
                let cmd = Rc::new(ValkeyCommand::for_test(args));
                match Client::handle_command(client.inner(), cmd.clone(), &mut sink.fp)
                    .await
                    .unwrap()
                {
                    ClientNextAction::SendResponse(response_buffer) => {
                        BytesMutUtils::to_string(&response_buffer)
                    }
                    ClientNextAction::NoAction => sink.read_all().await,
                    _ => panic!("unexpected client next action"),
                }
            }

            fn parse(response: &str) -> ValkeyObject {
                match RespResponseParserV2::parse_response(response.as_bytes()).unwrap() {
                    ResponseParseResult::Ok((_, obj)) => obj,
                    ResponseParseResult::NeedMoreData => panic!("expected a complete response"),
                }
            }

            run(&client, vec!["audit.append", "t1", "Created", ""]).await;
            run(&client, vec!["audit.append", "t1", "Claimed", "agent-1"]).await;
            run(&client, vec!["audit.append", "t1", "Completed", ""]).await;

            let response = run(&client, vec!["audit.range", "t1"]).await;
            let entries = parse(&response).array().unwrap();
            assert_eq!(entries.len(), 3);

            let expected = [
                (0u64, "Created", ""),
                (1u64, "Claimed", "agent-1"),
                (2u64, "Completed", ""),
            ];
            for (entry, (seq, event, details)) in entries.iter().zip(expected.iter()) {
                let fields = entry.array().unwrap();
                assert_eq!(fields.len(), 4);
                assert_eq!(fields[0].integer().unwrap(), *seq);
                assert!(fields[1].integer().unwrap() > 0); // timestamp_ms
                assert_eq!(
                    BytesMutUtils::to_string(&fields[2].string().unwrap()),
                    *event
                );
                assert_eq!(
                    BytesMutUtils::to_string(&fields[3].string().unwrap()),
                    *details
                );
            }

            // FROM / LIMIT
            let response = run(
                &client,
                vec!["audit.range", "t1", "from", "1", "limit", "1"],
            )
            .await;
            let entries = parse(&response).array().unwrap();
            assert_eq!(entries.len(), 1);
            let fields = entries[0].array().unwrap();
            assert_eq!(fields[0].integer().unwrap(), 1);
            assert_eq!(
                BytesMutUtils::to_string(&fields[2].string().unwrap()),
                "Claimed"
            );
        });
    }

    /// Same rationale as `test_audit_range_content`: AUDIT.FEED's `sequence` and
    /// `timestamp_ms` fields aren't fixed values, so this test parses the RESP reply
    /// structurally instead of comparing raw bytes.
    #[test]
    fn test_audit_feed_content() {
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async move {
            let (_guard, store) = crate::tests::open_store();
            let client = Client::new(Arc::<ServerState>::default(), store, None);

            async fn run(client: &Client, args: Vec<String>) -> String {
                let mut sink = crate::tests::ResponseSink::with_name("audit_feed_content").await;
                let cmd = Rc::new(ValkeyCommand::for_test2(args));
                match Client::handle_command(client.inner(), cmd.clone(), &mut sink.fp)
                    .await
                    .unwrap()
                {
                    ClientNextAction::SendResponse(response_buffer) => {
                        BytesMutUtils::to_string(&response_buffer)
                    }
                    ClientNextAction::NoAction => sink.read_all().await,
                    _ => panic!("unexpected client next action"),
                }
            }

            fn parse(response: &str) -> ValkeyObject {
                match RespResponseParserV2::parse_response(response.as_bytes()).unwrap() {
                    ResponseParseResult::Ok((_, obj)) => obj,
                    ResponseParseResult::NeedMoreData => panic!("expected a complete response"),
                }
            }

            fn s(args: &[&str]) -> Vec<String> {
                args.iter().map(|a| a.to_string()).collect()
            }

            // Only the first append per task should produce a feed row
            run(&client, s(&["audit.append", "task-a", "Created"])).await;
            run(&client, s(&["audit.append", "task-a", "Claimed", "agent-1"])).await;
            run(&client, s(&["audit.append", "task-b", "Created"])).await;
            // DEL on an AuditLog key routes to AuditDb::delete (see generic_commands.rs's
            // `del`), so task-a's `created` row is replaced by a `deleted` row, not left
            // stale alongside it -- the feed still has 2 rows, but task-a's now reads
            // `deleted` instead of `created`.
            run(&client, s(&["del", "task-a"])).await;

            let response = run(&client, s(&["audit.feed"])).await;
            let rows = parse(&response).array().unwrap();
            assert_eq!(rows.len(), 2);

            let row0 = rows[0].array().unwrap();
            assert!(row0[0].integer().unwrap() > 0); // sequence
            assert!(row0[1].integer().unwrap() > 0); // timestamp_ms
            assert_eq!(
                BytesMutUtils::to_string(&row0[2].string().unwrap()),
                "created"
            );
            assert_eq!(
                BytesMutUtils::to_string(&row0[3].string().unwrap()),
                "task-b"
            );

            let row1 = rows[1].array().unwrap();
            assert_eq!(
                BytesMutUtils::to_string(&row1[2].string().unwrap()),
                "deleted"
            );
            assert_eq!(
                BytesMutUtils::to_string(&row1[3].string().unwrap()),
                "task-a"
            );

            // FROM should resume exactly at the given sequence (inclusive)
            let cursor = row1[0].integer().unwrap();
            let response = run(&client, s(&["audit.feed", "from", &cursor.to_string()])).await;
            let rows = parse(&response).array().unwrap();
            assert_eq!(rows.len(), 1);
            assert_eq!(rows[0].array().unwrap()[0].integer().unwrap(), cursor);
        });
    }
}
