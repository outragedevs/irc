use super::test::{get_client_value, test_config};
use super::{Client, ClientStream, Config};
use crate::error::Result;
use futures::StreamExt;

async fn next(stream: &mut ClientStream) -> crate::proto::Message {
    stream.next().await.unwrap().unwrap()
}

#[tokio::test]
async fn capability_discovery_can_disable_configured_and_remembered_joins() -> Result<()> {
    for ending in ["376 test :End of MOTD", "422 test :No MOTD"] {
        let mut client = Client::from_config(Config {
            mock_initial_value: Some(format!(
                ":server CAP * LS :soju.im/bouncer-networks\r\n:test!user@host JOIN #remembered\r\n:server 353 test = #remembered :test\r\n:server {ending}\r\n"
            )),
            nick_password: Some("disposable-secret".into()),
            umodes: Some("+i".into()),
            channel_keys: [("#test2".into(), "disposable-key".into())].into(),
            ..test_config()
        }).await?;
        let mut stream = client.stream()?;
        assert!(matches!(
            next(&mut stream).await.command,
            crate::proto::Command::CAP(_, crate::proto::CapSubCommand::LS, _, _)
        ));
        let sender = client.sender();
        let clone = sender.clone();
        clone.set_autojoin_enabled(false);
        next(&mut stream).await;
        next(&mut stream).await;
        #[cfg(feature = "channel-lists")]
        assert!(client
            .list_channels()
            .unwrap()
            .contains(&"#remembered".to_string()));
        sender.send_join("#manual")?;
        while let Some(message) = stream.next().await {
            message?;
        }
        let sent = get_client_value(client).await;
        assert_eq!(
            sent,
            "JOIN #manual\r\nNICKSERV IDENTIFY disposable-secret\r\nMODE test +i\r\n"
        );
    }
    Ok(())
}

#[tokio::test]
async fn reenabling_applies_at_the_next_motd_without_changing_other_connections() -> Result<()> {
    let mut client = Client::from_config(Config {
        mock_initial_value: Some(
            ":server 422 test :No MOTD\r\n:server 376 test :End of MOTD\r\n".into(),
        ),
        ..test_config()
    })
    .await?;
    let mut other = Client::from_config(Config {
        mock_initial_value: Some(":server 376 test :End of MOTD\r\n".into()),
        ..test_config()
    })
    .await?;
    let sender = client.sender();
    sender.set_autojoin_enabled(false);
    let mut stream = client.stream()?;
    next(&mut stream).await;
    sender.set_autojoin_enabled(true);
    assert!(client.log_view().sent().unwrap().is_empty());
    next(&mut stream).await;
    let mut other_stream = other.stream()?;
    while let Some(message) = other_stream.next().await {
        message?;
    }
    assert_eq!(get_client_value(client).await, "JOIN #test,#test2\r\n");
    assert_eq!(get_client_value(other).await, "JOIN #test,#test2\r\n");
    Ok(())
}
