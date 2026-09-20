use irc_repartee::client::{data::Config, Client, Sender};
use tokio::io::{AsyncBufReadExt, BufReader, Lines};
use tokio::net::{TcpListener, TcpStream};
use tokio::task::JoinHandle;
use tokio::time::{timeout, Duration};

struct Wire {
    sender: Sender,
    lines: Lines<BufReader<TcpStream>>,
    task: JoinHandle<irc_repartee::error::Result<()>>,
}

impl Drop for Wire {
    fn drop(&mut self) {
        self.task.abort();
    }
}

impl Wire {
    async fn connect(threshold: u32) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let mut client = Client::from_config(Config {
            nickname: Some("test".into()),
            server: Some("127.0.0.1".into()),
            port: Some(listener.local_addr().unwrap().port()),
            use_tls: Some(false),
            flood_penalty_threshold: Some(threshold),
            ..Config::default()
        })
        .await
        .unwrap();
        let (socket, _) = listener.accept().await.unwrap();
        Self {
            sender: client.sender(),
            lines: BufReader::new(socket).lines(),
            task: tokio::spawn(client.outgoing().unwrap()),
        }
    }

    fn send(&self, text: &str) {
        self.sender.send_privmsg("#test", text).unwrap();
    }

    async fn expect(&mut self, text: &str) {
        let line = timeout(Duration::from_secs(1), self.lines.next_line())
            .await
            .unwrap()
            .unwrap()
            .unwrap();
        let message: irc_repartee::proto::Message = line.parse().unwrap();
        assert_eq!(
            message.command,
            irc_repartee::proto::Command::PRIVMSG("#test".into(), text.into())
        );
    }

    async fn expect_delayed(&mut self) {
        assert!(timeout(Duration::from_millis(120), self.lines.next_line())
            .await
            .is_err());
    }
}

#[tokio::test]
async fn flood_bypass_wakes_delayed_writer_and_restores_configured_limit() {
    let mut wire = Wire::connect(1_000).await;
    wire.send("delayed");
    wire.expect_delayed().await;
    let clone = wire.sender.clone();
    clone.set_flood_protection_enabled(false);
    wire.expect("delayed").await;
    for i in 0..12 {
        wire.send(&format!("burst {i}"));
    }
    for i in 0..12 {
        wire.expect(&format!("burst {i}")).await;
    }
    clone.set_flood_protection_enabled(true);
    wire.send("limited again");
    wire.expect_delayed().await;
    wire.sender.set_flood_protection_enabled(false);
    wire.expect("limited again").await;
}

#[tokio::test]
async fn flood_bypass_is_connection_local_and_preserves_disabled_config() {
    let mut limited = Wire::connect(1_000).await;
    let mut disabled = Wire::connect(0).await;
    disabled.sender.set_flood_protection_enabled(false);
    disabled.sender.set_flood_protection_enabled(true);
    limited.send("still limited");
    for i in 0..12 {
        disabled.send(&format!("unlimited {i}"));
    }
    for i in 0..12 {
        disabled.expect(&format!("unlimited {i}")).await;
    }
    limited.expect_delayed().await;
    limited.sender.set_flood_protection_enabled(false);
    limited.expect("still limited").await;
}
