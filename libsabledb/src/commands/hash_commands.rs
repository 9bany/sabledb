#[allow(unused_imports)]
use crate::{
    check_args_count, check_value_type,
    client::ClientState,
    command_arg_at,
    commands::{ErrorStrings, HandleCommandResult, StringCommands},
    metadata::CommonValueMetadata,
    metadata::Encoding,
    parse_string_to_number,
    storage::{GenericDb, HashDb, HashGetResult, HashPutResult},
    types::List,
    BytesMutUtils, Expiration, LockManager, PrimaryKeyMetadata, RedisCommand, RedisCommandName,
    RespBuilderV2, SableError, StorageAdapter, StringUtils, Telemetry, TimeUtils,
};

use bytes::BytesMut;
use std::rc::Rc;

pub struct HashCommands {}

impl HashCommands {
    pub async fn handle_command(
        client_state: Rc<ClientState>,
        command: Rc<RedisCommand>,
        response_buffer: &mut BytesMut,
    ) -> Result<HandleCommandResult, SableError> {
        match command.metadata().name() {
            RedisCommandName::Hset => {
                Self::hset(client_state, command, response_buffer).await?;
            }
            RedisCommandName::Hget => {
                Self::hget(client_state, command, response_buffer).await?;
            }
            _ => {
                return Err(SableError::InvalidArgument(format!(
                    "Non hash command {}",
                    command.main_command()
                )));
            }
        }
        Ok(HandleCommandResult::Completed)
    }

    /// Sets the specified fields to their respective values in the hash stored at key.
    async fn hset(
        client_state: Rc<ClientState>,
        command: Rc<RedisCommand>,
        response_buffer: &mut BytesMut,
    ) -> Result<(), SableError> {
        check_args_count!(command, 4, response_buffer);
        let builder = RespBuilderV2::default();

        let mut iter = command.args_vec().iter();
        iter.next(); // skip "hset"
        iter.next(); // skips the key

        let mut field_values = Vec::<(&BytesMut, &BytesMut)>::new();
        // hset key <field> <value> [<field><value>..]
        loop {
            let (field, value) = (iter.next(), iter.next());
            match (field, value) {
                (Some(field), Some(value)) => {
                    field_values.push((field, value));
                }
                (None, None) => break,
                (_, _) => {
                    // either we got even field:value pairs
                    // or its an error
                    builder.error_string(
                        response_buffer,
                        "ERR wrong number of arguments for 'hset' command",
                    );
                    return Ok(());
                }
            }
        }

        if field_values.is_empty() {
            builder.error_string(
                response_buffer,
                "ERR wrong number of arguments for 'hset' command",
            );
            return Ok(());
        }

        let key = command_arg_at!(command, 1);
        // Hash write updating 2 entries + doing read, so we need to exclusive lock it
        let _unused = LockManager::lock_user_key_exclusive(key, client_state.database_id());
        let hash_db = HashDb::with_storage(client_state.database(), client_state.database_id());

        let items_put = match hash_db.put(key, &field_values)? {
            HashPutResult::Some(count) => count,
            HashPutResult::WrongType => {
                builder.error_string(response_buffer, ErrorStrings::WRONGTYPE);
                return Ok(());
            }
        };

        builder.number_usize(response_buffer, items_put);
        Ok(())
    }

    /// Returns the value associated with field in the hash stored at key.
    async fn hget(
        client_state: Rc<ClientState>,
        command: Rc<RedisCommand>,
        response_buffer: &mut BytesMut,
    ) -> Result<(), SableError> {
        check_args_count!(command, 3, response_buffer);
        let builder = RespBuilderV2::default();

        let key = command_arg_at!(command, 1);
        let field = command_arg_at!(command, 2);

        // this is a read command, lock shared here
        let _unused = LockManager::lock_user_key_shared(key, client_state.database_id());
        let hash_db = HashDb::with_storage(client_state.database(), client_state.database_id());

        let items = match hash_db.get(key, &[&field])? {
            HashGetResult::WrongType => {
                builder.error_string(response_buffer, ErrorStrings::WRONGTYPE);
                return Ok(());
            }
            HashGetResult::Some(items) => {
                // update telemetries
                Telemetry::inc_db_hit();
                items
            }
            HashGetResult::None => {
                // update telemetries
                Telemetry::inc_db_miss();
                builder.null_string(response_buffer);
                return Ok(());
            }
        };

        // we expect exactly 1 item, return it
        if let Some(Some(v)) = items.first() {
            builder.bulk_string(response_buffer, v);
        } else {
            builder.null_string(response_buffer);
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
mod test {
    use super::*;
    use crate::{
        commands::ClientNextAction, storage::StorageAdapter, Client, ServerState, StorageOpenParams,
    };
    use std::path::PathBuf;
    use std::rc::Rc;
    use std::sync::Arc;
    use std::sync::Once;
    use test_case::test_case;

    lazy_static::lazy_static! {
        static ref INIT: Once = Once::new();
    }

    async fn initialise_test() {
        INIT.call_once(|| {
            let _ = std::fs::remove_dir_all("tests/hash_commands");
            let _ = std::fs::create_dir_all("tests/hash_commands");
        });
    }

    /// Initialise the database
    async fn open_database(command_name: &str) -> StorageAdapter {
        // Cleanup the previous test folder
        initialise_test().await;

        // create random file name
        let db_file = format!("tests/hash_commands/{}.db", command_name,);
        let _ = std::fs::create_dir_all("tests/hash_commands");
        let db_path = PathBuf::from(&db_file);
        let _ = std::fs::remove_dir_all(&db_file);
        let open_params = StorageOpenParams::default()
            .set_compression(false)
            .set_cache_size(64)
            .set_path(&db_path)
            .set_wal_disabled(true);
        crate::storage_rocksdb!(open_params)
    }

    #[test_case(vec![
        (vec!["hset", "myhash", "field1", "value1"], ":1\r\n"),
        // fields already exists in hash
        (vec!["hset", "myhash", "field1", "value1", "field1", "value1"], ":0\r\n"),
        (vec!["hset", "myhash", "field1", "value1", "field2"], "-ERR wrong number of arguments for 'hset' command\r\n"),
        (vec!["hset", "myhash", "field2", "value2"], ":1\r\n"),
        (vec!["hset", "myhash"], "-ERR wrong number of arguments for 'hset' command\r\n"),
    ], "test_hset"; "test_hset")]
    #[test_case(vec![
        (vec!["hset", "myhash", "field1", "value1", "field2", "value2"], ":2\r\n"),
        (vec!["hget", "myhash", "field1"], "$6\r\nvalue1\r\n"),
        (vec!["hget", "myhash", "field2"], "$6\r\nvalue2\r\n"),
        (vec!["hget", "myhash", "nosuchfield"], "$-1\r\n"),
    ], "test_hget"; "test_hget")]
    fn test_hash_commands(
        args_vec: Vec<(Vec<&'static str>, &'static str)>,
        test_name: &str,
    ) -> Result<(), SableError> {
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async move {
            let store = open_database(test_name).await;
            let client = Client::new(Arc::<ServerState>::default(), store, None);

            for (args, expected_value) in args_vec {
                let cmd = Rc::new(RedisCommand::for_test(args));
                match Client::handle_command(client.inner(), cmd).await.unwrap() {
                    ClientNextAction::SendResponse(response_buffer) => {
                        assert_eq!(
                            BytesMutUtils::to_string(&response_buffer).as_str(),
                            expected_value
                        );
                    }
                    _ => {}
                }
            }
        });
        Ok(())
    }
}