#[allow(unused_imports)]
use crate::{
    check_args_count, check_value_type, command_arg_at,
    commands::Strings,
    commands::{HandleCommandResult, StringCommands},
    metadata::CommonValueMetadata,
    parse_string_to_number,
    server::BroadcastMessageType,
    server::ClientState,
    server::SableError,
    storage::StringsDb,
    utils::RespBuilderV2,
    BytesMutUtils, Expiration, LockManager, PrimaryKeyMetadata, StorageAdapter, StringUtils,
    Telemetry, TimeUtils, ValkeyCommand, ValkeyCommandName,
};

use bytes::BytesMut;
use std::rc::Rc;
use tokio::io::AsyncWriteExt;

/// Number of key/value pairs in the `HELLO` handshake reply
const HELLO_FIELD_COUNT: usize = 7;

/// The only RESP protocol version `SableDB` currently speaks
const RESP_PROTOCOL_VERSION: u32 = 2;

pub struct ClientCommands {}

impl ClientCommands {
    pub async fn handle_command(
        client_state: Rc<ClientState>,
        command: Rc<ValkeyCommand>,
        _tx: &mut (impl AsyncWriteExt + std::marker::Unpin),
    ) -> Result<HandleCommandResult, SableError> {
        let mut response_buffer = BytesMut::with_capacity(256);
        match command.metadata().name() {
            ValkeyCommandName::Client => {
                Self::client(client_state, command, &mut response_buffer).await?;
            }
            ValkeyCommandName::Select => {
                Self::select(client_state, command, &mut response_buffer).await?;
            }
            ValkeyCommandName::Hello => {
                Self::hello(client_state, command, &mut response_buffer).await?;
            }
            _ => {
                return Err(SableError::InvalidArgument(format!(
                    "Non client command {}",
                    command.main_command()
                )));
            }
        }
        Ok(HandleCommandResult::ResponseBufferUpdated(response_buffer))
    }

    /// Execute the `client` command
    async fn client(
        client_state: Rc<ClientState>,
        command: Rc<ValkeyCommand>,
        response_buffer: &mut BytesMut,
    ) -> Result<(), SableError> {
        check_args_count!(command, 2, response_buffer);
        let sub_command = command_arg_at_as_str!(command, 1);
        let builder = RespBuilderV2::default();
        match sub_command.as_str() {
            "setinfo" => {
                // we now expect 4 arguments command
                check_args_count!(command, 4, response_buffer);
                let attribute_name = command_arg_at_as_str!(command, 2);
                let attribute_val = command_arg_at_as_str!(command, 3);
                match attribute_name.as_str() {
                    "lib-name" | "lib-ver" => {}
                    other => {
                        builder.error_string(
                            response_buffer,
                            &format!("ERR Unrecognized option '{}'", other),
                        );
                        return Ok(());
                    }
                }

                client_state.set_attribute(&attribute_name, &attribute_val);
                builder.ok(response_buffer);
            }
            "id" => {
                builder.number::<u128>(response_buffer, client_state.id(), false);
            }
            "kill" => {
                check_args_count!(command, 4, response_buffer);
                let filter = command_arg_at_as_str!(command, 2);
                match filter.as_str() {
                    "id" => {
                        // CLIENT KILL ID client-id
                        let Ok(client_id) = command_arg_at_as_str!(command, 3).parse::<u128>()
                        else {
                            builder.error_string(
                                response_buffer,
                                "ERR client-id should be greater than 0",
                            );
                            return Ok(());
                        };
                        client_state
                            .server_inner_state()
                            .terminate_client(client_id)
                            .await?;
                        builder.ok(response_buffer);
                    }
                    other => {
                        let msg = format!("command `client kill {}` is not supported", other);
                        builder.error_string(response_buffer, msg.as_str());
                    }
                }
            }
            _ => {
                let msg = format!("command `client {}` is not supported", sub_command.as_str());
                builder.error_string(response_buffer, msg.as_str());
            }
        }
        Ok(())
    }

    /// `HELLO [protover [AUTH username password] [SETNAME clientname]]`
    ///
    /// Return the server handshake. Many clients send `HELLO` as their first
    /// command and refuse to talk to a server that does not answer it.
    ///
    /// `SableDB` currently speaks RESP2 only, so any `protover` other than `2`
    /// is rejected with `NOPROTO` - which is what a client uses to detect that
    /// it has to fall back to RESP2
    async fn hello(
        client_state: Rc<ClientState>,
        command: Rc<ValkeyCommand>,
        response_buffer: &mut BytesMut,
    ) -> Result<(), SableError> {
        let builder = RespBuilderV2::default();

        // Parse every argument before applying anything: a failing `HELLO` must
        // leave the connection exactly as it was
        let mut client_name: Option<String> = None;

        if command.arg_count() > 1 {
            let protover = command_arg_at_as_str!(command, 1);
            if protover.parse::<u32>() != Ok(RESP_PROTOCOL_VERSION) {
                builder.error_string(response_buffer, "NOPROTO unsupported protocol version");
                return Ok(());
            }

            // Walk the remaining options
            let mut index = 2usize;
            while index < command.arg_count() {
                let option = command_arg_at_as_str!(command, index);
                match option.as_str() {
                    "auth" => {
                        if index + 2 >= command.arg_count() {
                            builder.error_string(
                                response_buffer,
                                "ERR Syntax error in HELLO option 'AUTH'",
                            );
                            return Ok(());
                        }
                        // SableDB has no authentication support yet. Report the
                        // same error Valkey returns when no password is set
                        builder.error_string(
                            response_buffer,
                            "ERR Client sent AUTH, but no password is set. \
                             Did you mean AUTH <username> <password>?",
                        );
                        return Ok(());
                    }
                    "setname" => {
                        let Some(name) = command.arg(index + 1) else {
                            builder.error_string(
                                response_buffer,
                                "ERR Syntax error in HELLO option 'SETNAME'",
                            );
                            return Ok(());
                        };
                        client_name = Some(String::from_utf8_lossy(name).to_string());
                        index += 2;
                    }
                    other => {
                        builder.error_string(
                            response_buffer,
                            format!("ERR Syntax error in HELLO option '{}'", other).as_str(),
                        );
                        return Ok(());
                    }
                }
            }
        }

        // Everything parsed - commit the changes to the connection
        if let Some(name) = client_name {
            client_state.set_attribute("name", &name);
        }

        Self::write_hello_response(client_state, response_buffer);
        Ok(())
    }

    /// Build the `HELLO` handshake reply: a map of [`HELLO_FIELD_COUNT`] pairs.
    ///
    /// RESP2 has no map type, so the pairs are sent as a flat array holding
    /// twice as many elements
    fn write_hello_response(client_state: Rc<ClientState>, response_buffer: &mut BytesMut) {
        let server_state = client_state.server_inner_state();
        let mode = if server_state
            .options()
            .read()
            .expect("Failed to obtain read lock on ServerOptions")
            .get_cluster_address()
            .is_some()
        {
            "cluster"
        } else {
            "standalone"
        };
        // The wire protocol uses the legacy role names
        let role = if server_state.persistent_state().is_replica() {
            "replica"
        } else {
            "master"
        };

        let builder = RespBuilderV2::default();
        response_buffer.clear();
        builder.add_array_len(response_buffer, HELLO_FIELD_COUNT.saturating_mul(2));
        builder.add_bulk_string(response_buffer, b"server");
        builder.add_bulk_string(response_buffer, b"sabledb");
        builder.add_bulk_string(response_buffer, b"version");
        builder.add_bulk_string(response_buffer, env!("CARGO_PKG_VERSION").as_bytes());
        builder.add_bulk_string(response_buffer, b"proto");
        builder.add_number::<u32>(response_buffer, RESP_PROTOCOL_VERSION, false);
        builder.add_bulk_string(response_buffer, b"id");
        builder.add_number::<u128>(response_buffer, client_state.id(), false);
        builder.add_bulk_string(response_buffer, b"mode");
        builder.add_bulk_string(response_buffer, mode.as_bytes());
        builder.add_bulk_string(response_buffer, b"role");
        builder.add_bulk_string(response_buffer, role.as_bytes());
        builder.add_bulk_string(response_buffer, b"modules");
        builder.add_empty_array(response_buffer);
    }

    /// Select the Valkey logical database having the specified zero-based numeric index.
    /// New connections always use the database 0.
    async fn select(
        client_state: Rc<ClientState>,
        command: Rc<ValkeyCommand>,
        response_buffer: &mut BytesMut,
    ) -> Result<(), SableError> {
        check_args_count!(command, 2, response_buffer);
        let db_index = command_arg_at_as_str!(command, 1);
        let builder = RespBuilderV2::default();
        let Ok(db_index) = db_index.parse::<u16>() else {
            // parsing failed
            builder.error_string(
                response_buffer,
                "ERR value is not an integer or out of range",
            );
            return Ok(());
        };
        client_state.set_database_id(db_index);
        builder.ok(response_buffer);
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
    use crate::{commands::ClientNextAction, test_assert, Client, ServerState, Telemetry};
    use std::sync::Arc;
    use test_case::test_case;

    #[test_case(vec![
        (vec!["select", "abc"], "-ERR value is not an integer or out of range\r\n"),
        (vec!["select", "-1"], "-ERR value is not an integer or out of range\r\n"),
        (vec!["select", "67000"], "-ERR value is not an integer or out of range\r\n"),
        (vec!["select", "1"], "+OK\r\n"),
        (vec!["set", "key", "value_1"], "+OK\r\n"),
        (vec!["select", "2"], "+OK\r\n"),
        (vec!["set", "key", "value_2"], "+OK\r\n"),
        (vec!["select", "0"], "+OK\r\n"),
        (vec!["get", "key"], "$-1\r\n"),
        (vec!["select", "3"], "+OK\r\n"),
        (vec!["get", "key"], "$-1\r\n"),
        (vec!["select", "1"], "+OK\r\n"),
        (vec!["get", "key"], "$7\r\nvalue_1\r\n"),
        (vec!["select", "2"], "+OK\r\n"),
        (vec!["get", "key"], "$7\r\nvalue_2\r\n"),
        ], "select"; "select")]
    #[test_case(vec![
        (vec!["client", "setinfo", "key", "value"], "-ERR Unrecognized option 'key'\r\n"),
        (vec!["client", "setinfo", "lib-ver", "v0.0.1"], "+OK\r\n"),
        (vec!["client", "setinfo", "lib-name", "sabledb-lib"], "+OK\r\n"),
        ], "client_setinfo"; "client_setinfo")]
    #[test_case(vec![
        // SableDB speaks RESP2 only - a client uses NOPROTO to detect that it
        // has to stay on RESP2
        (vec!["hello", "3"], "-NOPROTO unsupported protocol version\r\n"),
        (vec!["hello", "4"], "-NOPROTO unsupported protocol version\r\n"),
        (vec!["hello", "0"], "-NOPROTO unsupported protocol version\r\n"),
        (vec!["hello", "abc"], "-NOPROTO unsupported protocol version\r\n"),
        // SableDB has no authentication support
        (vec!["hello", "2", "auth", "user", "pass"],
         "-ERR Client sent AUTH, but no password is set. Did you mean AUTH <username> <password>?\r\n"),
        // Malformed options
        (vec!["hello", "2", "auth", "user"], "-ERR Syntax error in HELLO option 'AUTH'\r\n"),
        (vec!["hello", "2", "setname"], "-ERR Syntax error in HELLO option 'SETNAME'\r\n"),
        (vec!["hello", "2", "nosuchopt"], "-ERR Syntax error in HELLO option 'nosuchopt'\r\n"),
        ], "hello_errors"; "hello_errors")]
    fn test_client_commands(
        args_vec: Vec<(Vec<&'static str>, &'static str)>,
        test_name: &str,
    ) -> Result<(), SableError> {
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async move {
            let (_guard, store) = crate::tests::open_store();
            let client = Client::new(Arc::<ServerState>::default(), store, None);

            for (args, expected_value) in args_vec {
                let mut sink = crate::tests::ResponseSink::with_name(test_name).await;
                let cmd = Rc::new(ValkeyCommand::for_test(args));
                match Client::handle_command(client.inner(), cmd, &mut sink.fp)
                    .await
                    .unwrap()
                {
                    ClientNextAction::NoAction => {
                        assert_eq!(sink.read_all().await.as_str(), expected_value);
                    }
                    _ => {}
                }
            }
        });
        Ok(())
    }

    /// The handshake carries a non deterministic client id, so assert on the
    /// parts that are stable rather than on the exact byte string
    fn hello_reply(args: Vec<&'static str>) -> String {
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async move {
            let (_guard, store) = crate::tests::open_store();
            let client = Client::new(Arc::<ServerState>::default(), store, None);
            let mut sink = crate::tests::ResponseSink::with_name("hello").await;
            let cmd = Rc::new(ValkeyCommand::for_test(args));
            Client::handle_command(client.inner(), cmd, &mut sink.fp)
                .await
                .unwrap();
            sink.read_all().await
        })
    }

    #[test]
    fn test_hello_returns_the_handshake() {
        let response = hello_reply(vec!["hello"]);
        // RESP2 has no map type: 7 pairs are sent as 14 array elements
        assert!(response.starts_with("*14\r\n"), "got: {:?}", response);
        assert!(
            response.contains("$6\r\nserver\r\n$7\r\nsabledb\r\n"),
            "got: {:?}",
            response
        );
        assert!(
            response.contains("$5\r\nproto\r\n:2\r\n"),
            "got: {:?}",
            response
        );
        assert!(
            response.contains("$4\r\nmode\r\n$10\r\nstandalone\r\n"),
            "got: {:?}",
            response
        );
        assert!(
            response.contains("$4\r\nrole\r\n$6\r\nmaster\r\n"),
            "got: {:?}",
            response
        );
        assert!(
            response.ends_with("$7\r\nmodules\r\n*0\r\n"),
            "got: {:?}",
            response
        );
    }

    #[test]
    fn test_hello_with_and_without_protover_agree() {
        // `HELLO` and `HELLO 2` describe the same connection, so the only part
        // that may differ between the two replies is the client id
        let bare = hello_reply(vec!["hello"]);
        let explicit = hello_reply(vec!["hello", "2"]);
        let strip_id = |reply: &str| -> String {
            let (head, tail) = reply.split_once("$2\r\nid\r\n").expect("no id field");
            let (_id, rest) = tail.split_once("\r\n").expect("truncated id");
            format!("{}{}", head, rest)
        };
        assert_eq!(strip_id(&bare), strip_id(&explicit));
    }

    #[test]
    fn test_hello_setname_is_remembered() {
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async move {
            let (_guard, store) = crate::tests::open_store();
            let client = Client::new(Arc::<ServerState>::default(), store, None);

            let mut sink = crate::tests::ResponseSink::with_name("hello").await;
            let cmd = Rc::new(ValkeyCommand::for_test(vec![
                "hello", "2", "setname", "MyApp",
            ]));
            Client::handle_command(client.inner(), cmd, &mut sink.fp)
                .await
                .unwrap();

            assert!(sink.read_all().await.starts_with("*14\r\n"));
            assert_eq!(
                client.inner().attribute(&"name".to_string()),
                Some("MyApp".to_string())
            );
        });
    }

    #[test]
    fn test_hello_failure_does_not_apply_any_option() {
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async move {
            let (_guard, store) = crate::tests::open_store();
            let client = Client::new(Arc::<ServerState>::default(), store, None);

            // SETNAME is accepted, but the option that follows it is not: the
            // whole command must be rejected without a trace
            let mut sink = crate::tests::ResponseSink::with_name("hello").await;
            let cmd = Rc::new(ValkeyCommand::for_test(vec![
                "hello",
                "2",
                "setname",
                "MyApp",
                "nosuchopt",
            ]));
            Client::handle_command(client.inner(), cmd, &mut sink.fp)
                .await
                .unwrap();

            assert_eq!(
                sink.read_all().await.as_str(),
                "-ERR Syntax error in HELLO option 'nosuchopt'\r\n"
            );
            assert_eq!(client.inner().attribute(&"name".to_string()), None);
        });
    }

    #[test]
    fn test_client_kill() -> Result<(), SableError> {
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async move {
            let (_guard, store) = crate::tests::open_store();

            let client1 = Client::new(Arc::<ServerState>::default(), store.clone(), None);
            let client2 = Client::new(Arc::<ServerState>::default(), store, None);

            let client1_id = format!("{}", client1.inner().id());
            let kill_command = Rc::new(
                ValkeyCommand::new(vec![
                    BytesMut::from("client"),
                    BytesMut::from("kill"),
                    BytesMut::from("id"),
                    BytesMutUtils::from_string(client1_id.as_str()),
                ])
                .unwrap(),
            );

            // Kill client 1
            let mut sink = crate::tests::ResponseSink::with_name("test_client_kill").await;
            match Client::handle_command(client2.inner(), kill_command, &mut sink.fp)
                .await
                .unwrap()
            {
                ClientNextAction::NoAction => {
                    assert_eq!(sink.read_all().await.as_str(), "+OK\r\n");
                }
                other => {
                    panic!("Did not expect this result! {:?}", other)
                }
            }

            // Try to use client 1
            let some_command = Rc::new(ValkeyCommand::for_test(vec!["set", "some", "value"]));
            let mut sink = crate::tests::ResponseSink::with_name("test_client_kill").await;
            match Client::handle_command(client1.inner(), some_command, &mut sink.fp)
                .await
                .unwrap()
            {
                ClientNextAction::TerminateConnection => {
                    assert_eq!(
                        sink.read_all().await.as_str(),
                        format!("-{}\r\n", Strings::SERVER_CLOSED_CONNECTION).as_str()
                    );
                }
                other => {
                    panic!("Did not expect this result! {:?}", other)
                }
            }
        });
        Ok(())
    }
}
