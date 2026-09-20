//! A simple, thread-safe, and async-friendly IRC client library.
//!
//! This API provides the ability to connect to an IRC server via the
//! [`Client`] type. The [`Client`] trait that
//! [`Client`] implements provides methods for communicating with the
//! server.
//!
//! # Examples
//!
//! Using these APIs, we can connect to a server and send a one-off message (in this case,
//! identifying with the server).
//!
//! ```no_run
//! # extern crate irc_repartee;
//! use irc_repartee::client::prelude::Client;
//!
//! # #[tokio::main]
//! # async fn main() -> irc_repartee::error::Result<()> {
//! let client = Client::new("config.toml").await?;
//! client.identify()?;
//! # Ok(())
//! # }
//! ```
//!
//! We can then use functions from [`Client`] to receive messages from the
//! server in a blocking fashion and perform any desired actions in response. The following code
//! performs a simple call-and-response when the bot's name is mentioned in a channel.
//!
//! ```no_run
//! use irc_repartee::client::prelude::*;
//! use futures::*;
//!
//! # #[tokio::main]
//! # async fn main() -> irc_repartee::error::Result<()> {
//! let mut client = Client::new("config.toml").await?;
//! let mut stream = client.stream()?;
//! client.identify()?;
//!
//! while let Some(message) = stream.next().await.transpose()? {
//!     if let Command::PRIVMSG(channel, message) = message.command {
//!         if message.contains(client.current_nickname()) {
//!             client.send_privmsg(&channel, "beep boop").unwrap();
//!         }
//!     }
//! }
//! # Ok(())
//! # }
//! ```

#[cfg(feature = "ctcp")]
use chrono::prelude::*;
use futures_util::{
    future::{FusedFuture, Future},
    ready,
    stream::{FusedStream, Stream},
};
use futures_util::{
    sink::Sink as _,
    stream::{SplitSink, SplitStream, StreamExt as _},
};
use parking_lot::RwLock;
use std::{
    collections::HashMap,
    fmt,
    path::Path,
    pin::Pin,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
    task::{Context, Poll},
};
use tokio::sync::mpsc::{self, UnboundedReceiver, UnboundedSender};

use crate::{
    client::{
        conn::Connection,
        data::{Config, User},
    },
    error,
    proto::{
        mode::ModeType,
        CapSubCommand::{END, LS, REQ},
        Capability, ChannelMode, Command,
        Command::{
            ChannelMODE, AUTHENTICATE, CAP, INVITE, JOIN, KICK, KILL, NICK, NICKSERV, NOTICE, OPER,
            PART, PASS, PONG, PRIVMSG, QUIT, SAMODE, SANICK, TOPIC, USER,
        },
        Message, Mode, NegotiationVersion, Response,
    },
};

pub mod conn;
pub mod data;
mod mock;
pub mod prelude;
pub mod transport;

macro_rules! pub_state_base {
    () => {
        /// Changes the modes for the specified target.
        pub fn send_mode<S, T>(&self, target: S, modes: &[Mode<T>]) -> error::Result<()>
        where
            S: fmt::Display,
            T: ModeType,
        {
            self.send(T::mode(&target.to_string(), modes))
        }

        /// Joins the specified channel or chanlist.
        pub fn send_join<S>(&self, chanlist: S) -> error::Result<()>
        where
            S: fmt::Display,
        {
            self.send(JOIN(chanlist.to_string(), None, None))
        }

        /// Joins the specified channel or chanlist using the specified key or keylist.
        pub fn send_join_with_keys<S1, S2>(&self, chanlist: S1, keylist: S2) -> error::Result<()>
        where
            S1: fmt::Display,
            S2: fmt::Display,
        {
            self.send(JOIN(chanlist.to_string(), Some(keylist.to_string()), None))
        }

        /// Sends a notice to the specified target.
        #[allow(dead_code)]
        pub fn send_notice<S1, S2>(&self, target: S1, message: S2) -> error::Result<()>
        where
            S1: fmt::Display,
            S2: fmt::Display,
        {
            let message = message.to_string();
            for line in message.split("\r\n") {
                self.send(NOTICE(target.to_string(), line.to_string()))?
            }
            Ok(())
        }
    };
}

macro_rules! pub_sender_base {
    () => {
        /// Sends a request for a list of server capabilities for a specific IRCv3 version.
        pub fn send_cap_ls(&self, version: NegotiationVersion) -> error::Result<()> {
            self.send(Command::CAP(
                None,
                LS,
                match version {
                    NegotiationVersion::V301 => None,
                    NegotiationVersion::V302 => Some("302".to_owned()),
                },
                None,
            ))
        }

        /// Sends an IRCv3 capabilities request for the specified extensions.
        pub fn send_cap_req(&self, extensions: &[Capability]) -> error::Result<()> {
            let append = |mut s: String, c| {
                s.push_str(c);
                s.push(' ');
                s
            };
            let mut exts = extensions
                .iter()
                .map(|c| c.as_ref())
                .fold(String::new(), append);
            let len = exts.len() - 1;
            exts.truncate(len);
            self.send(CAP(None, REQ, None, Some(exts)))
        }

        /// Sends a SASL AUTHENTICATE message with the specified data.
        pub fn send_sasl<S: fmt::Display>(&self, data: S) -> error::Result<()> {
            self.send(AUTHENTICATE(data.to_string()))
        }

        /// Sends a SASL AUTHENTICATE request to use the PLAIN mechanism.
        pub fn send_sasl_plain(&self) -> error::Result<()> {
            self.send_sasl("PLAIN")
        }

        /// Sends a SASL AUTHENTICATE request to use the EXTERNAL mechanism.
        pub fn send_sasl_external(&self) -> error::Result<()> {
            self.send_sasl("EXTERNAL")
        }

        /// Sends a SASL AUTHENTICATE request to abort authentication.
        pub fn send_sasl_abort(&self) -> error::Result<()> {
            self.send_sasl("*")
        }

        /// Sends a PONG with the specified message.
        pub fn send_pong<S>(&self, msg: S) -> error::Result<()>
        where
            S: fmt::Display,
        {
            self.send(PONG(msg.to_string(), None))
        }

        /// Parts the specified channel or chanlist.
        pub fn send_part<S>(&self, chanlist: S) -> error::Result<()>
        where
            S: fmt::Display,
        {
            self.send(PART(chanlist.to_string(), None))
        }

        /// Attempts to oper up using the specified username and password.
        pub fn send_oper<S1, S2>(&self, username: S1, password: S2) -> error::Result<()>
        where
            S1: fmt::Display,
            S2: fmt::Display,
        {
            self.send(OPER(username.to_string(), password.to_string()))
        }

        /// Sends a message to the specified target. If the message contains IRC newlines (`\r\n`), it
        /// will automatically be split and sent as multiple separate `PRIVMSG`s to the specified
        /// target. If you absolutely must avoid this behavior, you can do
        /// `client.send(PRIVMSG(target, message))` directly.
        pub fn send_privmsg<S1, S2>(&self, target: S1, message: S2) -> error::Result<()>
        where
            S1: fmt::Display,
            S2: fmt::Display,
        {
            let message = message.to_string();
            for line in message.split("\r\n") {
                self.send(PRIVMSG(target.to_string(), line.to_string()))?
            }
            Ok(())
        }

        /// Sets the topic of a channel or requests the current one.
        /// If `topic` is an empty string, it won't be included in the message.
        pub fn send_topic<S1, S2>(&self, channel: S1, topic: S2) -> error::Result<()>
        where
            S1: fmt::Display,
            S2: fmt::Display,
        {
            let topic = topic.to_string();
            self.send(TOPIC(
                channel.to_string(),
                if topic.is_empty() { None } else { Some(topic) },
            ))
        }

        /// Kills the target with the provided message.
        pub fn send_kill<S1, S2>(&self, target: S1, message: S2) -> error::Result<()>
        where
            S1: fmt::Display,
            S2: fmt::Display,
        {
            self.send(KILL(target.to_string(), message.to_string()))
        }

        /// Kicks the listed nicknames from the listed channels with a comment.
        /// If `message` is an empty string, it won't be included in the message.
        pub fn send_kick<S1, S2, S3>(
            &self,
            chanlist: S1,
            nicklist: S2,
            message: S3,
        ) -> error::Result<()>
        where
            S1: fmt::Display,
            S2: fmt::Display,
            S3: fmt::Display,
        {
            let message = message.to_string();
            self.send(KICK(
                chanlist.to_string(),
                nicklist.to_string(),
                if message.is_empty() {
                    None
                } else {
                    Some(message)
                },
            ))
        }

        /// Changes the mode of the target by force.
        /// If `modeparams` is an empty string, it won't be included in the message.
        pub fn send_samode<S1, S2, S3>(
            &self,
            target: S1,
            mode: S2,
            modeparams: S3,
        ) -> error::Result<()>
        where
            S1: fmt::Display,
            S2: fmt::Display,
            S3: fmt::Display,
        {
            let modeparams = modeparams.to_string();
            self.send(SAMODE(
                target.to_string(),
                mode.to_string(),
                if modeparams.is_empty() {
                    None
                } else {
                    Some(modeparams)
                },
            ))
        }

        /// Forces a user to change from the old nickname to the new nickname.
        pub fn send_sanick<S1, S2>(&self, old_nick: S1, new_nick: S2) -> error::Result<()>
        where
            S1: fmt::Display,
            S2: fmt::Display,
        {
            self.send(SANICK(old_nick.to_string(), new_nick.to_string()))
        }

        /// Invites a user to the specified channel.
        pub fn send_invite<S1, S2>(&self, nick: S1, chan: S2) -> error::Result<()>
        where
            S1: fmt::Display,
            S2: fmt::Display,
        {
            self.send(INVITE(nick.to_string(), chan.to_string()))
        }

        /// Quits the server entirely with a message.
        /// This defaults to `Powered by Rust.` if none is specified.
        pub fn send_quit<S>(&self, msg: S) -> error::Result<()>
        where
            S: fmt::Display,
        {
            let msg = msg.to_string();
            self.send(QUIT(Some(if msg.is_empty() {
                "Powered by Rust.".to_string()
            } else {
                msg
            })))
        }

        /// Sends a CTCP-escaped message to the specified target.
        /// This requires the CTCP feature to be enabled.
        #[cfg(feature = "ctcp")]
        pub fn send_ctcp<S1, S2>(&self, target: S1, msg: S2) -> error::Result<()>
        where
            S1: fmt::Display,
            S2: fmt::Display,
        {
            let msg = msg.to_string();
            for line in msg.split("\r\n") {
                self.send(PRIVMSG(
                    target.to_string(),
                    format!("\u{001}{}\u{001}", line),
                ))?
            }
            Ok(())
        }

        /// Sends an action command to the specified target.
        /// This requires the CTCP feature to be enabled.
        #[cfg(feature = "ctcp")]
        pub fn send_action<S1, S2>(&self, target: S1, msg: S2) -> error::Result<()>
        where
            S1: fmt::Display,
            S2: fmt::Display,
        {
            self.send_ctcp(target, &format!("ACTION {}", msg.to_string())[..])
        }

        /// Sends a finger request to the specified target.
        /// This requires the CTCP feature to be enabled.
        #[cfg(feature = "ctcp")]
        pub fn send_finger<S>(&self, target: S) -> error::Result<()>
        where
            S: fmt::Display,
        {
            self.send_ctcp(target, "FINGER")
        }

        /// Sends a version request to the specified target.
        /// This requires the CTCP feature to be enabled.
        #[cfg(feature = "ctcp")]
        pub fn send_version<S>(&self, target: S) -> error::Result<()>
        where
            S: fmt::Display,
        {
            self.send_ctcp(target, "VERSION")
        }

        /// Sends a source request to the specified target.
        /// This requires the CTCP feature to be enabled.
        #[cfg(feature = "ctcp")]
        pub fn send_source<S>(&self, target: S) -> error::Result<()>
        where
            S: fmt::Display,
        {
            self.send_ctcp(target, "SOURCE")
        }

        /// Sends a user info request to the specified target.
        /// This requires the CTCP feature to be enabled.
        #[cfg(feature = "ctcp")]
        pub fn send_user_info<S>(&self, target: S) -> error::Result<()>
        where
            S: fmt::Display,
        {
            self.send_ctcp(target, "USERINFO")
        }

        /// Sends a finger request to the specified target.
        /// This requires the CTCP feature to be enabled.
        #[cfg(feature = "ctcp")]
        pub fn send_ctcp_ping<S>(&self, target: S) -> error::Result<()>
        where
            S: fmt::Display,
        {
            let time = Local::now();
            self.send_ctcp(target, &format!("PING {}", time.timestamp())[..])
        }

        /// Sends a time request to the specified target.
        /// This requires the CTCP feature to be enabled.
        #[cfg(feature = "ctcp")]
        pub fn send_time<S>(&self, target: S) -> error::Result<()>
        where
            S: fmt::Display,
        {
            self.send_ctcp(target, "TIME")
        }
    };
}

/// A stream of `Messages` received from an IRC server via an `Client`.
///
/// Interaction with this stream relies on the `futures` API, but is only expected for less
/// traditional use cases. To learn more, you can view the documentation for the
/// [`futures`](https://docs.rs/futures/) crate, or the tutorials for
/// [`tokio`](https://tokio.rs/docs/getting-started/futures/).
#[derive(Debug)]
pub struct ClientStream {
    state: Arc<ClientState>,
    stream: SplitStream<Connection>,
}

impl ClientStream {
    /// collect stream and collect all messages available.
    pub async fn collect(mut self) -> error::Result<Vec<Message>> {
        let mut output = Vec::new();

        while let Some(message) = self.next().await {
            match message {
                Ok(message) => output.push(message),
                Err(e) => return Err(e),
            }
        }

        Ok(output)
    }
}

impl FusedStream for ClientStream {
    fn is_terminated(&self) -> bool {
        false
    }
}

impl Stream for ClientStream {
    type Item = Result<Message, error::Error>;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        match ready!(Pin::new(&mut self.as_mut().stream).poll_next(cx)) {
            Some(Ok(msg)) => {
                self.state.handle_message(&msg)?;
                Poll::Ready(Some(Ok(msg)))
            }
            other => Poll::Ready(other),
        }
    }
}

/// Thread-safe internal state for an IRC server connection.
#[derive(Debug)]
struct ClientState {
    sender: Sender,
    /// The configuration used with this connection.
    config: Config,
    /// A thread-safe map of channels to the list of users in them.
    chanlists: RwLock<HashMap<String, Vec<User>>>,
    /// A thread-safe index to track the current alternative nickname being used.
    alt_nick_index: RwLock<usize>,
    /// Default ghost sequence to send if one is required but none is configured.
    default_ghost_sequence: Vec<String>,
}

impl ClientState {
    fn new(sender: Sender, config: Config) -> ClientState {
        ClientState {
            sender,
            config,
            chanlists: RwLock::new(HashMap::new()),
            alt_nick_index: RwLock::new(0),
            default_ghost_sequence: vec![String::from("GHOST")],
        }
    }

    fn config(&self) -> &Config {
        &self.config
    }

    fn send<M: Into<Message>>(&self, msg: M) -> error::Result<()> {
        let msg = msg.into();
        self.handle_sent_message(&msg)?;
        self.sender.send(msg)
    }

    /// Gets the current nickname in use.
    fn current_nickname(&self) -> &str {
        let alt_nicks = self.config().alternate_nicknames();
        let index = self.alt_nick_index.read();

        match *index {
            0 => self
                .config()
                .nickname()
                .expect("current_nickname should not be callable if nickname is not defined."),
            i => alt_nicks[i - 1].as_str(),
        }
    }

    /// Handles sent messages internally for basic client functionality.
    fn handle_sent_message(&self, msg: &Message) -> error::Result<()> {
        log::trace!("[SENT] {}", msg);

        if let PART(ref chan, _) = msg.command {
            let _ = self.chanlists.write().remove(chan);
        }

        Ok(())
    }

    /// Handles received messages internally for basic client functionality.
    fn handle_message(&self, msg: &Message) -> error::Result<()> {
        log::trace!("[RECV] {}", msg);
        match msg.command {
            JOIN(ref chan, _, _) => self.handle_join(msg.source_nickname().unwrap_or(""), chan),
            PART(ref chan, _) => self.handle_part(msg.source_nickname().unwrap_or(""), chan),
            KICK(ref chan, ref user, _) => self.handle_part(user, chan),
            QUIT(_) => self.handle_quit(msg.source_nickname().unwrap_or("")),
            NICK(ref new_nick) => {
                self.handle_nick_change(msg.source_nickname().unwrap_or(""), new_nick)
            }
            ChannelMODE(ref chan, ref modes) => self.handle_mode(chan, modes),
            PRIVMSG(ref target, ref body) => {
                if body.starts_with('\u{001}') {
                    let tokens: Vec<_> = {
                        let end = if body.ends_with('\u{001}') && body.len() > 1 {
                            body.len() - 1
                        } else {
                            body.len()
                        };
                        body[1..end].split(' ').collect()
                    };
                    if target.starts_with('#') {
                        self.handle_ctcp(target, &tokens)?
                    } else if let Some(user) = msg.source_nickname() {
                        self.handle_ctcp(user, &tokens)?
                    }
                }
            }
            Command::Response(Response::RPL_NAMREPLY, ref args) => self.handle_namreply(args),
            Command::Response(Response::RPL_ENDOFMOTD, _)
            | Command::Response(Response::ERR_NOMOTD, _) => {
                self.send_nick_password()?;
                self.send_umodes()?;

                // Batch autojoin: keyed channels first, then keyless (RFC 2812 §3.2.1)
                let config = self.config();
                let batches = Self::build_batched_joins(config.channels(), &config.channel_keys);
                for (chanlist, keylist) in &batches {
                    match keylist {
                        Some(keys) => self.send_join_with_keys(chanlist, keys)?,
                        None => self.send_join(chanlist)?,
                    }
                }

                // Re-join previously joined channels not in config
                let config_chans = config.channels();
                let rejoin: Vec<String> = self
                    .chanlists
                    .read()
                    .keys()
                    .filter(|x| !config_chans.iter().any(|c| c == *x))
                    .cloned()
                    .collect();
                if !rejoin.is_empty() {
                    let no_keys = HashMap::new();
                    let rejoin_batches = Self::build_batched_joins(&rejoin, &no_keys);
                    for (chanlist, _) in &rejoin_batches {
                        self.send_join(chanlist)?;
                    }
                }
            }
            Command::Response(Response::ERR_NICKNAMEINUSE, _)
            | Command::Response(Response::ERR_ERRONEOUSNICKNAME, _) => {
                let alt_nicks = self.config().alternate_nicknames();
                let mut index = self.alt_nick_index.write();

                if *index >= alt_nicks.len() {
                    return Err(error::Error::NoUsableNick);
                } else {
                    self.send(NICK(alt_nicks[*index].to_owned()))?;
                    *index += 1;
                }
            }
            _ => (),
        }
        Ok(())
    }

    fn send_nick_password(&self) -> error::Result<()> {
        if self.config().nick_password().is_empty() {
            Ok(())
        } else {
            let mut index = self.alt_nick_index.write();

            if self.config().should_ghost() && *index != 0 {
                let seq = match self.config().ghost_sequence() {
                    Some(seq) => seq,
                    None => &*self.default_ghost_sequence,
                };

                for s in seq {
                    self.send(NICKSERV(vec![
                        s.to_string(),
                        self.config().nickname()?.to_string(),
                        self.config().nick_password().to_string(),
                    ]))?;
                }
                *index = 0;
                self.send(NICK(self.config().nickname()?.to_owned()))?
            }

            self.send(NICKSERV(vec![
                "IDENTIFY".to_string(),
                self.config().nick_password().to_string(),
            ]))
        }
    }

    fn send_umodes(&self) -> error::Result<()> {
        if self.config().umodes().is_empty() {
            Ok(())
        } else {
            self.send_mode(
                self.current_nickname(),
                &Mode::as_user_modes(
                    self.config()
                        .umodes()
                        .split(' ')
                        .collect::<Vec<_>>()
                        .as_ref(),
                )
                .map_err(|e| error::Error::InvalidMessage {
                    string: format!(
                        "MODE {} {}",
                        self.current_nickname(),
                        self.config().umodes()
                    ),
                    cause: e,
                })?,
            )
        }
    }

    #[cfg(not(feature = "channel-lists"))]
    fn handle_join(&self, _: &str, _: &str) {}

    #[cfg(feature = "channel-lists")]
    fn handle_join(&self, src: &str, chan: &str) {
        if let Some(vec) = self.chanlists.write().get_mut(&chan.to_owned()) {
            if !src.is_empty() {
                vec.push(User::new(src))
            }
        }
    }

    #[cfg(not(feature = "channel-lists"))]
    fn handle_part(&self, _: &str, _: &str) {}

    #[cfg(feature = "channel-lists")]
    fn handle_part(&self, src: &str, chan: &str) {
        if let Some(vec) = self.chanlists.write().get_mut(&chan.to_owned()) {
            if !src.is_empty() {
                if let Some(n) = vec.iter().position(|x| x.get_nickname() == src) {
                    vec.swap_remove(n);
                }
            }
        }
    }

    #[cfg(not(feature = "channel-lists"))]
    fn handle_quit(&self, _: &str) {}

    #[cfg(feature = "channel-lists")]
    fn handle_quit(&self, src: &str) {
        if src.is_empty() {
            return;
        }

        for vec in self.chanlists.write().values_mut() {
            if let Some(p) = vec.iter().position(|x| x.get_nickname() == src) {
                vec.swap_remove(p);
            }
        }
    }

    #[cfg(not(feature = "channel-lists"))]
    fn handle_nick_change(&self, _: &str, _: &str) {}

    #[cfg(feature = "channel-lists")]
    fn handle_nick_change(&self, old_nick: &str, new_nick: &str) {
        if old_nick.is_empty() || new_nick.is_empty() {
            return;
        }

        for vec in self.chanlists.write().values_mut() {
            if let Some(n) = vec.iter().position(|x| x.get_nickname() == old_nick) {
                let new_entry = User::new(new_nick);
                vec[n] = new_entry;
            }
        }
    }

    #[cfg(not(feature = "channel-lists"))]
    fn handle_mode(&self, _: &str, _: &[Mode<ChannelMode>]) {}

    #[cfg(feature = "channel-lists")]
    fn handle_mode(&self, chan: &str, modes: &[Mode<ChannelMode>]) {
        for mode in modes {
            match *mode {
                Mode::Plus(_, Some(ref user)) | Mode::Minus(_, Some(ref user)) => {
                    if let Some(vec) = self.chanlists.write().get_mut(chan) {
                        if let Some(n) = vec.iter().position(|x| x.get_nickname() == user) {
                            vec[n].update_access_level(mode)
                        }
                    }
                }
                _ => (),
            }
        }
    }

    #[cfg(not(feature = "channel-lists"))]
    fn handle_namreply(&self, _: &[String]) {}

    #[cfg(feature = "channel-lists")]
    fn handle_namreply(&self, args: &[String]) {
        if args.len() == 4 {
            let chan = &args[2];
            for user in args[3].split(' ') {
                self.chanlists
                    .write()
                    .entry(chan.clone())
                    .or_default()
                    .push(User::new(user))
            }
        }
    }

    #[cfg(feature = "ctcp")]
    fn handle_ctcp(&self, resp: &str, tokens: &[&str]) -> error::Result<()> {
        if tokens.is_empty() {
            return Ok(());
        }
        if tokens[0].eq_ignore_ascii_case("FINGER") {
            self.send_ctcp_internal(
                resp,
                &format!(
                    "FINGER :{} ({})",
                    self.config().real_name(),
                    self.config().username()
                ),
            )
        } else if tokens[0].eq_ignore_ascii_case("VERSION") {
            self.send_ctcp_internal(resp, &format!("VERSION {}", self.config().version()))
        } else if tokens[0].eq_ignore_ascii_case("SOURCE") {
            self.send_ctcp_internal(resp, &format!("SOURCE {}", self.config().source()))
        } else if tokens[0].eq_ignore_ascii_case("PING") && tokens.len() > 1 {
            self.send_ctcp_internal(resp, &format!("PING {}", tokens[1]))
        } else if tokens[0].eq_ignore_ascii_case("TIME") {
            self.send_ctcp_internal(resp, &format!("TIME :{}", Local::now().to_rfc2822()))
        } else if tokens[0].eq_ignore_ascii_case("USERINFO") {
            self.send_ctcp_internal(resp, &format!("USERINFO :{}", self.config().user_info()))
        } else {
            Ok(())
        }
    }

    #[cfg(feature = "ctcp")]
    fn send_ctcp_internal(&self, target: &str, msg: &str) -> error::Result<()> {
        self.send_notice(target, format!("\u{001}{}\u{001}", msg))
    }

    #[cfg(not(feature = "ctcp"))]
    fn handle_ctcp(&self, _: &str, _: &[&str]) -> error::Result<()> {
        Ok(())
    }

    /// Builds batched JOIN commands from a list of channels and optional keys.
    ///
    /// Channels with keys are placed first in each batch so that positional key
    /// matching works correctly per RFC 2812 §3.2.1. Commands are split into
    /// multiple JOINs when they would exceed the 512-byte IRC line limit.
    fn build_batched_joins(
        channels: &[String],
        channel_keys: &HashMap<String, String>,
    ) -> Vec<(String, Option<String>)> {
        if channels.is_empty() {
            return Vec::new();
        }

        // Partition into keyed and keyless, preserving config order within groups
        let mut keyed: Vec<(&str, &str)> = Vec::new();
        let mut keyless: Vec<&str> = Vec::new();
        for chan in channels {
            match channel_keys.get(chan.as_str()) {
                Some(key) => keyed.push((chan, key)),
                None => keyless.push(chan),
            }
        }

        // "JOIN " = 5 bytes, "\r\n" = 2 bytes → 505 bytes for payload
        const BUDGET: usize = 512 - 7;

        let mut batches: Vec<(String, Option<String>)> = Vec::new();
        let mut batch_chans: Vec<&str> = Vec::new();
        let mut batch_keys: Vec<&str> = Vec::new();
        let mut chan_len: usize = 0;
        let mut key_len: usize = 0;

        // Returns total payload size: chanlist [+ " " + keylist]
        let payload = |cl: usize, kl: usize, has_keys: bool| -> usize {
            if has_keys {
                cl + 1 + kl
            } else {
                cl
            }
        };

        // Flush current batch
        let flush = |chans: &mut Vec<&str>,
                     keys: &mut Vec<&str>,
                     cl: &mut usize,
                     kl: &mut usize,
                     out: &mut Vec<(String, Option<String>)>| {
            if !chans.is_empty() {
                let chanlist = chans.join(",");
                let keylist = if keys.is_empty() {
                    None
                } else {
                    Some(keys.join(","))
                };
                out.push((chanlist, keylist));
                chans.clear();
                keys.clear();
                *cl = 0;
                *kl = 0;
            }
        };

        // Process keyed channels first (must precede keyless for positional keys)
        for (chan, key) in &keyed {
            let new_cl = if batch_chans.is_empty() {
                chan.len()
            } else {
                chan_len + 1 + chan.len()
            };
            let new_kl = if batch_keys.is_empty() {
                key.len()
            } else {
                key_len + 1 + key.len()
            };

            if !batch_chans.is_empty() && payload(new_cl, new_kl, true) > BUDGET {
                flush(
                    &mut batch_chans,
                    &mut batch_keys,
                    &mut chan_len,
                    &mut key_len,
                    &mut batches,
                );
                chan_len = chan.len();
                key_len = key.len();
            } else {
                chan_len = new_cl;
                key_len = new_kl;
            }
            batch_chans.push(chan);
            batch_keys.push(key);
        }

        // Append keyless channels, filling remaining space in current batch
        for chan in &keyless {
            let new_cl = if batch_chans.is_empty() {
                chan.len()
            } else {
                chan_len + 1 + chan.len()
            };
            let has_keys = !batch_keys.is_empty();

            if !batch_chans.is_empty() && payload(new_cl, key_len, has_keys) > BUDGET {
                flush(
                    &mut batch_chans,
                    &mut batch_keys,
                    &mut chan_len,
                    &mut key_len,
                    &mut batches,
                );
                chan_len = chan.len();
            } else {
                chan_len = new_cl;
            }
            batch_chans.push(chan);
        }

        // Flush remaining
        flush(
            &mut batch_chans,
            &mut batch_keys,
            &mut chan_len,
            &mut key_len,
            &mut batches,
        );

        batches
    }

    pub_state_base!();
}

/// Thread-safe sender that can be used with the client.
#[derive(Debug, Clone)]
pub struct Sender {
    tx_outgoing: UnboundedSender<Message>,
    flood_control: Arc<FloodControl>,
}

#[derive(Debug)]
struct FloodControl {
    enabled: AtomicBool,
    waker: futures_util::task::AtomicWaker,
}

impl FloodControl {
    fn new() -> Self {
        Self {
            enabled: AtomicBool::new(true),
            waker: futures_util::task::AtomicWaker::new(),
        }
    }
}

impl Sender {
    #[doc = "Enable the configured flood limit, or bypass it and wake a delayed writer. Shared by all senders on this connection; enabling preserves a configured zero limit."]
    pub fn set_flood_protection_enabled(&self, enabled: bool) {
        self.flood_control.enabled.store(enabled, Ordering::Release);
        self.flood_control.waker.wake();
    }

    /// Send a single message to the unbounded queue.
    pub fn send<M: Into<Message>>(&self, msg: M) -> error::Result<()> {
        Ok(self.tx_outgoing.send(msg.into())?)
    }

    pub_state_base!();
    pub_sender_base!();
}

/// Future to handle outgoing messages with IRC flood protection.
///
/// Implements a penalty-based throttle modeled after IRCd (RFC 2813 §5.8). Each outgoing
/// message incurs a penalty based on both its byte length and command type, matching the
/// server's own flood detection formula. When accumulated penalty exceeds a configurable
/// threshold (default 10s), messages are delayed until the penalty drains below it.
/// Penalty drains in real-time at 1ms per 1ms elapsed.
///
/// Total penalty per message: `(1 + message_bytes / 100) * 1000 + command_penalty_ms`
#[derive(Debug)]
pub struct Outgoing {
    sink: SplitSink<Connection, Message>,
    stream: UnboundedReceiver<Message>,
    /// Priority lane for messages the throttle must not delay.
    ///
    /// Internal PINGs use this lane so paste bursts in the regular queue cannot
    /// starve the pinger long enough to trip `ping_timeout`.
    priority_stream: UnboundedReceiver<Message>,
    priority_buffered: Option<Message>,
    buffered: Option<Message>,
    /// Accumulated penalty in milliseconds.
    penalty: u64,
    /// Threshold above which messages are delayed. 0 = disabled.
    penalty_threshold: u64,
    flood_control: Arc<FloodControl>,
    /// Last time penalty was drained.
    last_penalty_check: tokio::time::Instant,
    /// Active delay future for throttling.
    delay: Option<Pin<Box<tokio::time::Sleep>>>,
}

impl Outgoing {
    /// Returns the penalty cost in milliseconds for a given IRC command.
    ///
    /// Values mirror the IRCd penalty model (RFC 2813 §5.8). The server-side
    /// implementation charges `(1 + message_bytes / 100)` seconds as a base
    /// cost per message, plus a command-specific penalty. We replicate this
    /// client-side to stay under the server's flood threshold.
    ///
    /// The total penalty for a message is: `base_penalty(len) + command_penalty`
    fn command_penalty(command: &Command) -> u64 {
        match command {
            // Connection control — never throttled client-side. The server
            // does charge 1-2s for PONG, but delaying pong replies risks
            // ping timeout disconnects, so we exempt these.
            Command::PONG(..) | Command::QUIT(..) | Command::PASS(..) => 0,

            // CAP negotiation — must not be throttled during registration
            Command::CAP(..) | Command::AUTHENTICATE(..) => 0,

            // NICK changes incur 3s on IRCd
            Command::NICK(..) => 3000,

            // PART is expensive on IRCd (4s)
            Command::PART(..) => 4000,

            // WHO, NAMES, LIST without args are catastrophic on IRCd (10s).
            // With args they're 2s. We can't distinguish no-arg vs arg here
            // since the Option is always present in the enum, so we check
            // whether the argument is None/empty.
            Command::WHO(ref mask, _) => match mask {
                None => 10_000,
                Some(m) if m.is_empty() => 10_000,
                _ => 2000,
            },
            Command::LIST(ref mask, _) | Command::NAMES(ref mask, _) => match mask {
                None => 10_000,
                Some(m) if m.is_empty() => 10_000,
                _ => 2000,
            },

            // Other expensive server queries
            Command::WHOIS(..) | Command::WHOWAS(..) => 3000,
            Command::LINKS(..) | Command::STATS(..) => 3000,
            Command::LUSERS(..) | Command::TRACE(..) => 2000,
            Command::USERS(..) | Command::MOTD(..) | Command::INFO(..) => 5000,

            // PRIVMSG/NOTICE: IRCd charges 1s per target. We approximate
            // with a flat 2s since most client sends target a single entity.
            Command::PRIVMSG(..) | Command::NOTICE(..) => 2000,

            // JOIN, KICK, INVITE, MODE, TOPIC, AWAY, and all others: 2s
            _ => 2000,
        }
    }

    /// Returns the base penalty in milliseconds derived from message length.
    ///
    /// Mirrors the IRCd formula: `(1 + message_bytes / 100)` seconds.
    /// This ensures long messages incur proportionally higher penalties,
    /// matching the server's own flood calculation.
    fn length_penalty(message: &Message) -> u64 {
        let len = message.to_string().len() as u64;
        (1 + len / 100) * 1000
    }

    /// Drains accumulated penalty based on elapsed real time.
    fn drain_penalty(&mut self) {
        let now = tokio::time::Instant::now();
        let elapsed = now.duration_since(self.last_penalty_check).as_millis() as u64;
        self.penalty = self.penalty.saturating_sub(elapsed);
        self.last_penalty_check = now;
    }

    fn try_start_send(
        &mut self,
        cx: &mut Context<'_>,
        message: Message,
    ) -> Poll<Result<(), error::Error>> {
        debug_assert!(self.buffered.is_none());

        match Pin::new(&mut self.sink).poll_ready(cx)? {
            Poll::Ready(()) => Poll::Ready(Pin::new(&mut self.sink).start_send(message)),
            Poll::Pending => {
                self.buffered = Some(message);
                Poll::Pending
            }
        }
    }

    fn try_start_send_priority(
        &mut self,
        cx: &mut Context<'_>,
        message: Message,
    ) -> Poll<Result<(), error::Error>> {
        debug_assert!(self.priority_buffered.is_none());

        match Pin::new(&mut self.sink).poll_ready(cx)? {
            Poll::Ready(()) => Poll::Ready(Pin::new(&mut self.sink).start_send(message)),
            Poll::Pending => {
                self.priority_buffered = Some(message);
                Poll::Pending
            }
        }
    }

    fn poll_priority_message(&mut self, cx: &mut Context<'_>) -> Poll<Result<bool, error::Error>> {
        if let Some(message) = self.priority_buffered.take() {
            ready!(self.try_start_send_priority(cx, message))?;
            ready!(Pin::new(&mut self.sink).poll_flush(cx))?;
            return Poll::Ready(Ok(true));
        }

        match self.priority_stream.poll_recv(cx) {
            Poll::Ready(Some(message)) => {
                ready!(self.try_start_send_priority(cx, message))?;
                ready!(Pin::new(&mut self.sink).poll_flush(cx))?;
                Poll::Ready(Ok(true))
            }
            Poll::Ready(None) | Poll::Pending => Poll::Ready(Ok(false)),
        }
    }
}

impl FusedFuture for Outgoing {
    fn is_terminated(&self) -> bool {
        // NB: outgoing stream never terminates.
        // TODO: should it terminate if rx_outgoing is terminated?
        false
    }
}

impl Future for Outgoing {
    type Output = error::Result<()>;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let this = &mut *self;
        this.flood_control.waker.register(cx.waker());
        if !this.flood_control.enabled.load(Ordering::Acquire) {
            this.delay = None;
            this.penalty = 0;
            this.last_penalty_check = tokio::time::Instant::now();
        }

        if ready!(this.poll_priority_message(cx))? {
            cx.waker().wake_by_ref();
            return Poll::Pending;
        }

        // If we're waiting on a throttle delay, poll it first.
        if let Some(ref mut delay) = this.delay {
            ready!(delay.as_mut().poll(cx));
            this.delay = None;
            this.drain_penalty();
        }

        // Send the message that was buffered during the delay, then flush
        // it to TCP immediately. Without this flush, messages accumulate
        // in the codec buffer across multiple delay cycles and burst all
        // at once when the stream finally goes idle — causing Excess Flood.
        if let Some(message) = this.buffered.take() {
            ready!(this.try_start_send(cx, message))?;
            ready!(Pin::new(&mut this.sink).poll_flush(cx))?;
        }

        if ready!(this.poll_priority_message(cx))? {
            cx.waker().wake_by_ref();
            return Poll::Pending;
        }

        loop {
            match this.stream.poll_recv(cx) {
                Poll::Ready(Some(message)) => {
                    // Apply penalty-based throttle if enabled.
                    if this.penalty_threshold > 0
                        && this.flood_control.enabled.load(Ordering::Acquire)
                    {
                        let cmd_cost = Self::command_penalty(&message.command);
                        if cmd_cost > 0 {
                            let len_cost = Self::length_penalty(&message);
                            let cost = len_cost + cmd_cost;
                            this.drain_penalty();
                            this.penalty += cost;

                            if this.penalty > this.penalty_threshold {
                                let excess = this.penalty - this.penalty_threshold;
                                log::debug!(
                                    "Flood penalty {}ms exceeds threshold {}ms, delaying {}ms.",
                                    this.penalty,
                                    this.penalty_threshold,
                                    excess,
                                );
                                this.delay = Some(Box::pin(tokio::time::sleep(
                                    std::time::Duration::from_millis(excess),
                                )));
                                // Buffer the message and return Pending so the delay runs.
                                this.buffered = Some(message);
                                // Register waker with the delay future.
                                if let Some(ref mut delay) = this.delay {
                                    let _ = delay.as_mut().poll(cx);
                                }
                                // Flush any messages already in the codec buffer before
                                // sleeping. Without this, a non-delayed message sent
                                // earlier in this poll cycle would stay buffered until
                                // the delay expires.
                                ready!(Pin::new(&mut this.sink).poll_flush(cx))?;
                                return Poll::Pending;
                            }
                        }
                    }
                    ready!(this.try_start_send(cx, message))?
                }
                Poll::Ready(None) => {
                    ready!(Pin::new(&mut this.sink).poll_flush(cx))?;
                    return Poll::Ready(Ok(()));
                }
                Poll::Pending => {
                    ready!(Pin::new(&mut this.sink).poll_flush(cx))?;
                    return Poll::Pending;
                }
            }
        }
    }
}

/// The canonical implementation of a connection to an IRC server.
///
/// For a full example usage, see [`crate::client`].
#[derive(Debug)]
pub struct Client {
    /// The internal, thread-safe server state.
    state: Arc<ClientState>,
    incoming: Option<SplitStream<Connection>>,
    outgoing: Option<Outgoing>,
    sender: Sender,
    /// The local socket address of the TCP connection, if available.
    local_addr: Option<std::net::SocketAddr>,
    /// Handle to the spawned outgoing message task.
    /// Stored by `stream()` so callers can abort it on disconnect
    /// to prevent CLOSE-WAIT socket leaks.
    pub outgoing_handle: Option<tokio::task::JoinHandle<()>>,
    #[cfg(test)]
    /// A view of the logs for a mock connection.
    view: Option<self::transport::LogView>,
}

impl Client {
    /// Creates a new `Client` from the configuration at the specified path, connecting
    /// immediately. This function is short-hand for loading the configuration and then calling
    /// `Client::from_config` and consequently inherits its behaviors.
    ///
    /// # Example
    /// ```no_run
    /// # use irc_repartee::client::prelude::*;
    /// # #[tokio::main]
    /// # async fn main() -> irc_repartee::error::Result<()> {
    /// let client = Client::new("config.toml").await?;
    /// # Ok(())
    /// # }
    /// ```
    pub async fn new<P: AsRef<Path>>(config: P) -> error::Result<Client> {
        Client::from_config(Config::load(config)?).await
    }

    /// Creates a `Future` of an `Client` from the specified configuration and on the event loop
    /// corresponding to the given handle. This can be used to set up a number of `Clients` on a
    /// single, shared event loop. It can also be used to take more control over execution and error
    /// handling. Connection will not occur until the event loop is run.
    pub async fn from_config(config: Config) -> error::Result<Client> {
        let (tx_outgoing, rx_outgoing) = mpsc::unbounded_channel();
        let (tx_priority_outgoing, rx_priority_outgoing) = mpsc::unbounded_channel();
        let conn = Connection::new(&config, tx_priority_outgoing).await?;

        let local_addr = conn.local_addr();

        #[cfg(test)]
        let view = conn.log_view();

        let (sink, incoming) = conn.split();

        let flood_control = Arc::new(FloodControl::new());
        let sender = Sender {
            tx_outgoing,
            flood_control: flood_control.clone(),
        };
        let penalty_threshold = config.flood_penalty_threshold() as u64;

        Ok(Client {
            sender: sender.clone(),
            state: Arc::new(ClientState::new(sender, config)),
            incoming: Some(incoming),
            outgoing: Some(Outgoing {
                sink,
                stream: rx_outgoing,
                priority_stream: rx_priority_outgoing,
                priority_buffered: None,
                buffered: None,
                penalty: 0,
                penalty_threshold,
                flood_control,
                last_penalty_check: tokio::time::Instant::now(),
                delay: None,
            }),
            local_addr,
            outgoing_handle: None,
            #[cfg(test)]
            view,
        })
    }

    /// Gets the log view from the internal transport. Only used for unit testing.
    #[cfg(test)]
    fn log_view(&self) -> &self::transport::LogView {
        self.view
            .as_ref()
            .expect("there should be a log during testing")
    }

    /// Take the outgoing future in order to drive it yourself.
    ///
    /// Must be called before `stream` if you intend to drive this future
    /// yourself.
    pub fn outgoing(&mut self) -> Option<Outgoing> {
        self.outgoing.take()
    }

    /// Get access to a thread-safe sender that can be used with the client.
    pub fn sender(&self) -> Sender {
        self.sender.clone()
    }

    /// Abort the spawned outgoing message handler task.
    ///
    /// Call this when the connection is being torn down to prevent
    /// CLOSE-WAIT socket leaks.  The `Pinger` inside `Outgoing` holds a
    /// `tx_outgoing` clone that keeps the write half of the TCP socket
    /// alive even after all external `Sender` clones are dropped.
    pub fn abort_outgoing(&mut self) {
        if let Some(handle) = self.outgoing_handle.take() {
            handle.abort();
        }
    }

    /// Gets the configuration being used with this `Client`.
    fn config(&self) -> &Config {
        &self.state.config
    }

    /// Gets a stream of incoming messages from the `Client`'s connection. This is only necessary
    /// when trying to set up more complex clients, and requires use of the `futures` crate. Most
    /// You can find some examples of setups using `stream` in the
    /// [GitHub repository](https://github.com/aatxe/irc/tree/stable/examples).
    ///
    /// **Note**: The stream can only be returned once. Subsequent attempts will cause a panic.
    // FIXME: when impl traits stabilize, we should change this return type.
    pub fn stream(&mut self) -> error::Result<ClientStream> {
        let stream = self
            .incoming
            .take()
            .ok_or(error::Error::StreamAlreadyConfigured)?;

        // Spawn the outgoing message handler as an independent task so that
        // sent messages are flushed immediately, rather than waiting for the
        // incoming stream to be polled.  The JoinHandle is stored so callers
        // can abort it on disconnect — the Pinger inside Outgoing holds a
        // tx_outgoing clone that would otherwise keep the channel open and
        // the write half of the TLS socket alive (CLOSE-WAIT leak).
        if let Some(outgoing) = self.outgoing.take() {
            self.outgoing_handle = Some(tokio::spawn(async move {
                if let Err(e) = outgoing.await {
                    log::error!("error in outgoing message handler: {}", e);
                }
            }));
        }

        Ok(ClientStream {
            state: Arc::clone(&self.state),
            stream,
        })
    }

    /// Gets a list of currently joined channels. This will be `None` if tracking is disabled
    /// altogether by disabling the `channel-lists` feature.
    #[cfg(feature = "channel-lists")]
    pub fn list_channels(&self) -> Option<Vec<String>> {
        Some(
            self.state
                .chanlists
                .read()
                .keys()
                .map(|k| k.to_owned())
                .collect(),
        )
    }

    /// Always returns `None` since `channel-lists` feature is disabled.
    #[cfg(not(feature = "channel-lists"))]
    pub fn list_channels(&self) -> Option<Vec<String>> {
        None
    }

    /// Gets a list of [`User`]s in the specified channel. If the
    /// specified channel hasn't been joined or the `channel-lists` feature is disabled, this function
    /// will return `None`.
    ///
    /// For best results, be sure to request `multi-prefix` support from the server. This will allow
    /// for more accurate tracking of user rank (e.g. oper, half-op, etc.).
    /// # Requesting multi-prefix support
    /// ```no_run
    /// # use irc_repartee::client::prelude::*;
    /// use irc_repartee::proto::caps::Capability;
    ///
    /// # #[tokio::main]
    /// # async fn main() -> irc_repartee::error::Result<()> {
    /// # let client = Client::new("config.toml").await?;
    /// client.send_cap_req(&[Capability::MultiPrefix])?;
    /// client.identify()?;
    /// # Ok(())
    /// # }
    /// ```
    #[cfg(feature = "channel-lists")]
    pub fn list_users(&self, chan: &str) -> Option<Vec<User>> {
        self.state.chanlists.read().get(&chan.to_owned()).cloned()
    }

    /// Always returns `None` since `channel-lists` feature is disabled.
    #[cfg(not(feature = "channel-lists"))]
    pub fn list_users(&self, _: &str) -> Option<Vec<User>> {
        None
    }

    /// Gets the current nickname in use. This may be the primary username set in the configuration,
    /// or it could be any of the alternative nicknames listed as well. As a result, this is the
    /// preferred way to refer to the client's nickname.
    pub fn current_nickname(&self) -> &str {
        self.state.current_nickname()
    }

    /// Returns the local socket address of the underlying TCP connection.
    ///
    /// This is useful for determining the client's own IP address as seen by the
    /// local network stack, for example when implementing DCC or CTCP.
    ///
    /// Returns `None` for mock connections or if the address could not be determined.
    pub fn local_addr(&self) -> Option<std::net::SocketAddr> {
        self.local_addr
    }

    /// Sends a [`Command`] as this `Client`. This is the
    /// core primitive for sending messages to the server.
    ///
    /// # Example
    /// ```no_run
    /// # use irc_repartee::client::prelude::*;
    /// # #[tokio::main]
    /// # async fn main() {
    /// # let client = Client::new("config.toml").await.unwrap();
    /// client.send(Command::NICK("example".to_owned())).unwrap();
    /// client.send(Command::USER("user".to_owned(), "0".to_owned(), "name".to_owned())).unwrap();
    /// # }
    /// ```
    pub fn send<M: Into<Message>>(&self, msg: M) -> error::Result<()> {
        self.state.send(msg)
    }

    /// Sends a CAP END, NICK and USER to identify.
    pub fn identify(&self) -> error::Result<()> {
        // Send a CAP END to signify that we're IRCv3-compliant (and to end negotiations!).
        self.send(CAP(None, END, None, None))?;
        if self.config().password() != "" {
            self.send(PASS(self.config().password().to_owned()))?;
        }
        self.send(NICK(self.config().nickname()?.to_owned()))?;
        self.send(USER(
            self.config().username().to_owned(),
            "0".to_owned(),
            self.config().real_name().to_owned(),
        ))?;
        Ok(())
    }

    pub_state_base!();
    pub_sender_base!();
}

#[cfg(test)]
mod test {
    use std::{collections::HashMap, default::Default, time::Duration};

    use super::{Client, ClientState, Outgoing};
    #[cfg(feature = "channel-lists")]
    use crate::client::data::User;
    use crate::{
        client::data::Config,
        error::Error,
        proto::{
            command::Command::{Raw, PING, PONG, PRIVMSG},
            ChannelMode, IrcCodec, Message, Mode, UserMode,
        },
    };
    use anyhow::Result;
    use futures::prelude::*;
    use tokio::{
        net::TcpListener,
        sync::{mpsc::UnboundedSender, oneshot},
    };
    use tokio_util::codec::Framed;

    pub fn test_config() -> Config {
        Config {
            owners: vec!["test".to_string()],
            nickname: Some("test".to_string()),
            alt_nicks: vec!["test2".to_string()],
            server: Some("irc.test.net".to_string()),
            channels: vec!["#test".to_string(), "#test2".to_string()],
            user_info: Some("Testing.".to_string()),
            use_mock_connection: true,
            flood_penalty_threshold: Some(0),
            ..Default::default()
        }
    }

    pub async fn get_client_value(client: Client) -> String {
        // We yield here to allow the spawned outgoing task to flush messages.
        tokio::time::sleep(Duration::from_millis(100)).await;
        client
            .log_view()
            .sent()
            .unwrap()
            .iter()
            .fold(String::new(), |mut acc, msg| {
                // NOTE: we have to sanitize here because sanitization happens in IrcCodec after the
                // messages are converted into strings, but our transport logger catches messages before
                // they ever reach that point.
                acc.push_str(&IrcCodec::sanitize(msg.to_string()));
                acc
            })
    }

    fn test_outgoing(
        penalty_threshold: u64,
    ) -> Result<(
        Outgoing,
        UnboundedSender<Message>,
        UnboundedSender<Message>,
        super::transport::LogView,
    )> {
        let config = test_config();
        let (tx_outgoing, rx_outgoing) = tokio::sync::mpsc::unbounded_channel();
        let (tx_priority_outgoing, rx_priority_outgoing) = tokio::sync::mpsc::unbounded_channel();
        let (tx_pinger, _rx_pinger) = tokio::sync::mpsc::unbounded_channel();
        let framed = Framed::new(
            super::mock::MockStream::empty(),
            IrcCodec::new(config.encoding())?,
        );
        let conn = super::conn::Connection::Mock(super::transport::Logged::wrap(
            super::transport::Transport::new(&config, framed, tx_pinger),
        ));
        let view = conn
            .log_view()
            .expect("mock connection should expose a log view");
        let (sink, _incoming) = conn.split();

        Ok((
            Outgoing {
                sink,
                stream: rx_outgoing,
                priority_stream: rx_priority_outgoing,
                priority_buffered: None,
                buffered: None,
                penalty: 0,
                penalty_threshold,
                flood_control: std::sync::Arc::new(super::FloodControl::new()),
                last_penalty_check: tokio::time::Instant::now(),
                delay: None,
            },
            tx_outgoing,
            tx_priority_outgoing,
            view,
        ))
    }

    async fn wait_for_sent_command<F>(
        view: &super::transport::LogView,
        mut predicate: F,
    ) -> Result<Message>
    where
        F: FnMut(&Message) -> bool,
    {
        tokio::time::timeout(Duration::from_millis(100), async {
            loop {
                if let Some(message) = view.sent()?.iter().find(|msg| predicate(msg)).cloned() {
                    return Ok(message);
                }

                tokio::time::sleep(Duration::from_millis(5)).await;
            }
        })
        .await?
    }

    #[tokio::test]
    async fn priority_message_skips_throttle_delay() -> Result<()> {
        let (outgoing, tx_outgoing, tx_priority_outgoing, view) = test_outgoing(10_000)?;
        let handle = tokio::spawn(outgoing);
        let payload = "x".repeat(350);

        tx_outgoing.send(PRIVMSG("#test".to_owned(), payload.clone()).into())?;
        tx_outgoing.send(PRIVMSG("#test".to_owned(), payload).into())?;
        tokio::time::sleep(Duration::from_millis(20)).await;

        tx_priority_outgoing.send(PING("priority".to_owned(), None).into())?;
        wait_for_sent_command(&view, |msg| matches!(&msg.command, PING(..))).await?;

        handle.abort();
        Ok(())
    }

    #[tokio::test]
    async fn paste_burst_does_not_starve_ping() -> Result<()> {
        let listener = TcpListener::bind(("127.0.0.1", 0)).await?;
        let port = listener.local_addr()?.port();
        let (tx_ping_seen, rx_ping_seen) = oneshot::channel();

        let server = tokio::spawn(async move {
            let (socket, _) = listener.accept().await?;
            let mut framed = Framed::new(socket, IrcCodec::new("UTF-8")?);
            framed
                .send(Message::new(
                    Some("irc.test.net"),
                    "376",
                    vec!["test", "End of /MOTD command."],
                )?)
                .await?;

            let mut tx_ping_seen = Some(tx_ping_seen);
            while let Some(message) = framed.next().await {
                let message = message?;
                if let PING(ref data, _) = message.command {
                    if let Some(tx_ping_seen) = tx_ping_seen.take() {
                        let _ = tx_ping_seen.send(message.to_string());
                    }
                    framed.send(PONG(data.to_owned(), None).into()).await?;
                }
            }

            Ok::<(), anyhow::Error>(())
        });

        let mut config = test_config();
        config.server = Some("127.0.0.1".to_owned());
        config.port = Some(port);
        config.use_tls = Some(false);
        config.use_mock_connection = false;
        config.channels = vec![];
        config.ping_time = Some(1);
        config.ping_timeout = Some(2);
        config.flood_penalty_threshold = Some(10_000);

        let mut client = Client::from_config(config).await?;
        let sender = client.sender();
        let mut stream = client.stream()?;
        let reader = tokio::spawn(async move {
            while stream.next().await.transpose()?.is_some() {}
            Ok::<(), Error>(())
        });

        let payload = "x".repeat(350);
        for _ in 0..50 {
            sender.send_privmsg("#test", &payload)?;
        }

        let ping = tokio::time::timeout(Duration::from_secs(3), rx_ping_seen).await??;
        assert!(ping.starts_with("PING "));
        assert!(
            !reader.is_finished(),
            "stream ended before PING was answered"
        );

        reader.abort();
        client.abort_outgoing();
        server.abort();
        Ok(())
    }

    #[tokio::test]
    async fn stream() -> Result<()> {
        let exp = "PRIVMSG test :Hi!\r\nPRIVMSG test :This is a test!\r\n\
                   :test!test@test JOIN #test\r\n";

        let mut client = Client::from_config(Config {
            mock_initial_value: Some(exp.to_owned()),
            ..test_config()
        })
        .await?;

        client.stream()?.collect().await?;
        // assert_eq!(&messages[..], exp);
        Ok(())
    }

    #[tokio::test]
    async fn handle_message() -> Result<()> {
        let value = ":irc.test.net 376 test :End of /MOTD command.\r\n";
        let mut client = Client::from_config(Config {
            mock_initial_value: Some(value.to_owned()),
            ..test_config()
        })
        .await?;
        client.stream()?.collect().await?;
        assert_eq!(&get_client_value(client).await[..], "JOIN #test,#test2\r\n");
        Ok(())
    }

    #[tokio::test]
    async fn handle_end_motd_with_nick_password() -> Result<()> {
        let value = ":irc.test.net 376 test :End of /MOTD command.\r\n";
        let mut client = Client::from_config(Config {
            mock_initial_value: Some(value.to_owned()),
            nick_password: Some("password".to_string()),
            channels: vec!["#test".to_string(), "#test2".to_string()],
            ..test_config()
        })
        .await?;
        client.stream()?.collect().await?;
        assert_eq!(
            &get_client_value(client).await[..],
            "NICKSERV IDENTIFY password\r\nJOIN #test,#test2\r\n"
        );
        Ok(())
    }

    #[tokio::test]
    async fn handle_end_motd_with_chan_keys() -> Result<()> {
        let value = ":irc.test.net 376 test :End of /MOTD command\r\n";
        let mut client = Client::from_config(Config {
            mock_initial_value: Some(value.to_owned()),
            nickname: Some("test".to_string()),
            channels: vec!["#test".to_string(), "#test2".to_string()],
            channel_keys: {
                let mut map = HashMap::new();
                map.insert("#test2".to_string(), "password".to_string());
                map
            },
            ..test_config()
        })
        .await?;
        client.stream()?.collect().await?;
        assert_eq!(
            &get_client_value(client).await[..],
            "JOIN #test2,#test password\r\n"
        );
        Ok(())
    }

    #[tokio::test]
    async fn handle_end_motd_with_ghost() -> Result<()> {
        let value = ":irc.test.net 433 * test :Nickname is already in use.\r\n\
                     :irc.test.net 376 test2 :End of /MOTD command.\r\n";
        let mut client = Client::from_config(Config {
            mock_initial_value: Some(value.to_owned()),
            nickname: Some("test".to_string()),
            alt_nicks: vec!["test2".to_string()],
            nick_password: Some("password".to_string()),
            channels: vec!["#test".to_string(), "#test2".to_string()],
            should_ghost: true,
            ..test_config()
        })
        .await?;
        client.stream()?.collect().await?;
        assert_eq!(
            &get_client_value(client).await[..],
            "NICK test2\r\nNICKSERV GHOST test password\r\n\
             NICK test\r\nNICKSERV IDENTIFY password\r\nJOIN #test,#test2\r\n"
        );
        Ok(())
    }

    #[tokio::test]
    async fn handle_end_motd_with_ghost_seq() -> Result<()> {
        let value = ":irc.test.net 433 * test :Nickname is already in use.\r\n\
                     :irc.test.net 376 test2 :End of /MOTD command.\r\n";
        let mut client = Client::from_config(Config {
            mock_initial_value: Some(value.to_owned()),
            nickname: Some("test".to_string()),
            alt_nicks: vec!["test2".to_string()],
            nick_password: Some("password".to_string()),
            channels: vec!["#test".to_string(), "#test2".to_string()],
            should_ghost: true,
            ghost_sequence: Some(vec!["RECOVER".to_string(), "RELEASE".to_string()]),
            ..test_config()
        })
        .await?;
        client.stream()?.collect().await?;
        assert_eq!(
            &get_client_value(client).await[..],
            "NICK test2\r\nNICKSERV RECOVER test password\
             \r\nNICKSERV RELEASE test password\r\nNICK test\r\nNICKSERV IDENTIFY password\
             \r\nJOIN #test,#test2\r\n"
        );
        Ok(())
    }

    #[tokio::test]
    async fn handle_end_motd_with_umodes() -> Result<()> {
        let value = ":irc.test.net 376 test :End of /MOTD command.\r\n";
        let mut client = Client::from_config(Config {
            mock_initial_value: Some(value.to_owned()),
            nickname: Some("test".to_string()),
            umodes: Some("+B".to_string()),
            channels: vec!["#test".to_string(), "#test2".to_string()],
            ..test_config()
        })
        .await?;
        client.stream()?.collect().await?;
        assert_eq!(
            &get_client_value(client).await[..],
            "MODE test +B\r\nJOIN #test,#test2\r\n"
        );
        Ok(())
    }

    #[tokio::test]
    async fn nickname_in_use() -> Result<()> {
        let value = ":irc.test.net 433 * test :Nickname is already in use.\r\n";
        let mut client = Client::from_config(Config {
            mock_initial_value: Some(value.to_owned()),
            ..test_config()
        })
        .await?;
        client.stream()?.collect().await?;
        assert_eq!(&get_client_value(client).await[..], "NICK test2\r\n");
        Ok(())
    }

    #[tokio::test]
    async fn ran_out_of_nicknames() -> Result<()> {
        let value = ":irc.test.net 433 * test :Nickname is already in use.\r\n\
                     :irc.test.net 433 * test2 :Nickname is already in use.\r\n";
        let mut client = Client::from_config(Config {
            mock_initial_value: Some(value.to_owned()),
            ..test_config()
        })
        .await?;
        let res = client.stream()?.try_collect::<Vec<_>>().await;
        if let Err(Error::NoUsableNick) = res {
        } else {
            panic!("expected error when no valid nicks were specified")
        }
        Ok(())
    }

    #[tokio::test]
    async fn send() -> Result<()> {
        let mut client = Client::from_config(test_config()).await?;
        assert!(client
            .send(PRIVMSG("#test".to_string(), "Hi there!".to_string()))
            .is_ok());
        client.stream()?.collect().await?;
        assert_eq!(
            &get_client_value(client).await[..],
            "PRIVMSG #test :Hi there!\r\n"
        );
        Ok(())
    }

    #[tokio::test]
    async fn send_no_newline_injection() -> Result<()> {
        let mut client = Client::from_config(test_config()).await?;
        assert!(client
            .send(PRIVMSG(
                "#test".to_string(),
                "Hi there!\r\nJOIN #bad".to_string()
            ))
            .is_ok());
        client.stream()?.collect().await?;
        assert_eq!(
            &get_client_value(client).await[..],
            "PRIVMSG #test :Hi there!\r\n"
        );
        Ok(())
    }

    #[tokio::test]
    async fn send_raw_is_really_raw() -> Result<()> {
        let mut client = Client::from_config(test_config()).await?;
        assert!(client
            .send(Raw("PASS".to_owned(), vec!["password".to_owned()]))
            .is_ok());
        assert!(client
            .send(Raw("NICK".to_owned(), vec!["test".to_owned()]))
            .is_ok());
        client.stream()?.collect().await?;
        assert_eq!(
            &get_client_value(client).await[..],
            "PASS password\r\nNICK test\r\n"
        );
        Ok(())
    }

    #[tokio::test]
    #[cfg(feature = "channel-lists")]
    async fn channel_tracking_names() -> Result<()> {
        let value = ":irc.test.net 353 test = #test :test ~owner &admin\r\n";
        let mut client = Client::from_config(Config {
            mock_initial_value: Some(value.to_owned()),
            ..test_config()
        })
        .await?;
        client.stream()?.collect().await?;
        assert_eq!(client.list_channels().unwrap(), vec!["#test".to_owned()]);
        Ok(())
    }

    #[tokio::test]
    #[cfg(feature = "channel-lists")]
    async fn channel_tracking_names_part() -> Result<()> {
        use crate::proto::command::Command::PART;

        let value = ":irc.test.net 353 test = #test :test ~owner &admin\r\n";
        let mut client = Client::from_config(Config {
            mock_initial_value: Some(value.to_owned()),
            ..test_config()
        })
        .await?;

        client.stream()?.collect().await?;

        assert_eq!(client.list_channels(), Some(vec!["#test".to_owned()]));
        // we ignore the result, as soon as we queue an outgoing message we
        // update client state, regardless if the queue is available or not.
        let _ = client.send(PART("#test".to_string(), None));
        assert_eq!(client.list_channels(), Some(vec![]));
        Ok(())
    }

    #[tokio::test]
    #[cfg(feature = "channel-lists")]
    async fn user_tracking_names() -> Result<()> {
        let value = ":irc.test.net 353 test = #test :test ~owner &admin\r\n";
        let mut client = Client::from_config(Config {
            mock_initial_value: Some(value.to_owned()),
            ..test_config()
        })
        .await?;
        client.stream()?.collect().await?;
        assert_eq!(
            client.list_users("#test").unwrap(),
            vec![User::new("test"), User::new("~owner"), User::new("&admin")]
        );
        Ok(())
    }

    #[tokio::test]
    #[cfg(feature = "channel-lists")]
    async fn user_tracking_names_join() -> Result<()> {
        let value = ":irc.test.net 353 test = #test :test ~owner &admin\r\n\
                     :test2!test@test JOIN #test\r\n";
        let mut client = Client::from_config(Config {
            mock_initial_value: Some(value.to_owned()),
            ..test_config()
        })
        .await?;
        client.stream()?.collect().await?;
        assert_eq!(
            client.list_users("#test").unwrap(),
            vec![
                User::new("test"),
                User::new("~owner"),
                User::new("&admin"),
                User::new("test2"),
            ]
        );
        Ok(())
    }

    #[tokio::test]
    #[cfg(feature = "channel-lists")]
    async fn user_tracking_names_kick() -> Result<()> {
        let value = ":irc.test.net 353 test = #test :test ~owner &admin\r\n\
                     :owner!test@test KICK #test test\r\n";
        let mut client = Client::from_config(Config {
            mock_initial_value: Some(value.to_owned()),
            ..test_config()
        })
        .await?;
        client.stream()?.collect().await?;
        assert_eq!(
            client.list_users("#test").unwrap(),
            vec![User::new("&admin"), User::new("~owner"),]
        );
        Ok(())
    }

    #[tokio::test]
    #[cfg(feature = "channel-lists")]
    async fn user_tracking_names_part() -> Result<()> {
        let value = ":irc.test.net 353 test = #test :test ~owner &admin\r\n\
                     :owner!test@test PART #test\r\n";
        let mut client = Client::from_config(Config {
            mock_initial_value: Some(value.to_owned()),
            ..test_config()
        })
        .await?;
        client.stream()?.collect().await?;
        assert_eq!(
            client.list_users("#test").unwrap(),
            vec![User::new("test"), User::new("&admin")]
        );
        Ok(())
    }

    #[tokio::test]
    #[cfg(feature = "channel-lists")]
    async fn user_tracking_names_mode() -> Result<()> {
        let value = ":irc.test.net 353 test = #test :+test ~owner &admin\r\n\
                     :test!test@test MODE #test +o test\r\n";
        let mut client = Client::from_config(Config {
            mock_initial_value: Some(value.to_owned()),
            ..test_config()
        })
        .await?;
        client.stream()?.collect().await?;
        assert_eq!(
            client.list_users("#test").unwrap(),
            vec![User::new("@test"), User::new("~owner"), User::new("&admin")]
        );
        let mut exp = User::new("@test");
        exp.update_access_level(&Mode::Plus(ChannelMode::Voice, None));
        assert_eq!(
            client.list_users("#test").unwrap()[0].highest_access_level(),
            exp.highest_access_level()
        );
        // The following tests if the maintained user contains the same entries as what is expected
        // but ignores the ordering of these entries.
        let mut levels = client.list_users("#test").unwrap()[0].access_levels();
        levels.retain(|l| exp.access_levels().contains(l));
        assert_eq!(levels.len(), exp.access_levels().len());
        Ok(())
    }

    #[tokio::test]
    #[cfg(not(feature = "channel-lists"))]
    async fn no_user_tracking() -> Result<()> {
        let value = ":irc.test.net 353 test = #test :test ~owner &admin\r\n";
        let mut client = Client::from_config(Config {
            mock_initial_value: Some(value.to_owned()),
            ..test_config()
        })
        .await?;
        client.stream()?.collect().await?;
        assert!(client.list_users("#test").is_none());
        Ok(())
    }

    #[tokio::test]
    async fn handle_single_soh() -> Result<()> {
        let value = ":test!test@test PRIVMSG #test :\u{001}\r\n";
        let mut client = Client::from_config(Config {
            mock_initial_value: Some(value.to_owned()),
            nickname: Some("test".to_string()),
            channels: vec!["#test".to_string(), "#test2".to_string()],
            ..test_config()
        })
        .await?;
        client.stream()?.collect().await?;
        Ok(())
    }

    #[tokio::test]
    #[cfg(feature = "ctcp")]
    async fn finger_response() -> Result<()> {
        let value = ":test!test@test PRIVMSG test :\u{001}FINGER\u{001}\r\n";
        let mut client = Client::from_config(Config {
            mock_initial_value: Some(value.to_owned()),
            ..test_config()
        })
        .await?;
        client.stream()?.collect().await?;
        assert_eq!(
            &get_client_value(client).await[..],
            "NOTICE test :\u{001}FINGER :test (test)\u{001}\r\n"
        );
        Ok(())
    }

    #[tokio::test]
    #[cfg(feature = "ctcp")]
    async fn version_response() -> Result<()> {
        let value = ":test!test@test PRIVMSG test :\u{001}VERSION\u{001}\r\n";
        let mut client = Client::from_config(Config {
            mock_initial_value: Some(value.to_owned()),
            ..test_config()
        })
        .await?;
        client.stream()?.collect().await?;
        assert_eq!(
            &get_client_value(client).await[..],
            &format!(
                "NOTICE test :\u{001}VERSION {}\u{001}\r\n",
                crate::VERSION_STR,
            )
        );
        Ok(())
    }

    #[tokio::test]
    #[cfg(feature = "ctcp")]
    async fn source_response() -> Result<()> {
        let value = ":test!test@test PRIVMSG test :\u{001}SOURCE\u{001}\r\n";
        let mut client = Client::from_config(Config {
            mock_initial_value: Some(value.to_owned()),
            ..test_config()
        })
        .await?;
        client.stream()?.collect().await?;
        assert_eq!(
            &get_client_value(client).await[..],
            "NOTICE test :\u{001}SOURCE https://github.com/aatxe/irc\u{001}\r\n"
        );
        Ok(())
    }

    #[tokio::test]
    #[cfg(feature = "ctcp")]
    async fn ctcp_ping_response() -> Result<()> {
        let value = ":test!test@test PRIVMSG test :\u{001}PING test\u{001}\r\n";
        let mut client = Client::from_config(Config {
            mock_initial_value: Some(value.to_owned()),
            ..test_config()
        })
        .await?;
        client.stream()?.collect().await?;
        assert_eq!(
            &get_client_value(client).await[..],
            "NOTICE test :\u{001}PING test\u{001}\r\n"
        );
        Ok(())
    }

    #[tokio::test]
    #[cfg(feature = "ctcp")]
    async fn time_response() -> Result<()> {
        let value = ":test!test@test PRIVMSG test :\u{001}TIME\u{001}\r\n";
        let mut client = Client::from_config(Config {
            mock_initial_value: Some(value.to_owned()),
            ..test_config()
        })
        .await?;
        client.stream()?.collect().await?;
        let val = get_client_value(client).await;
        assert!(val.starts_with("NOTICE test :\u{001}TIME :"));
        assert!(val.ends_with("\u{001}\r\n"));
        Ok(())
    }

    #[tokio::test]
    #[cfg(feature = "ctcp")]
    async fn user_info_response() -> Result<()> {
        let value = ":test!test@test PRIVMSG test :\u{001}USERINFO\u{001}\r\n";
        let mut client = Client::from_config(Config {
            mock_initial_value: Some(value.to_owned()),
            ..test_config()
        })
        .await?;
        client.stream()?.collect().await?;
        assert_eq!(
            &get_client_value(client).await[..],
            "NOTICE test :\u{001}USERINFO :Testing.\u{001}\
             \r\n"
        );
        Ok(())
    }

    #[tokio::test]
    #[cfg(feature = "ctcp")]
    async fn ctcp_ping_no_timestamp() -> Result<()> {
        let value = ":test!test@test PRIVMSG test \u{001}PING\u{001}\r\n";
        let mut client = Client::from_config(Config {
            mock_initial_value: Some(value.to_owned()),
            ..test_config()
        })
        .await?;
        client.stream()?.collect().await?;
        assert_eq!(&get_client_value(client).await[..], "");
        Ok(())
    }

    #[tokio::test]
    async fn identify() -> Result<()> {
        let mut client = Client::from_config(test_config()).await?;
        client.identify()?;
        client.stream()?.collect().await?;
        assert_eq!(
            &get_client_value(client).await[..],
            "CAP END\r\nNICK test\r\n\
             USER test 0 * test\r\n"
        );
        Ok(())
    }

    #[tokio::test]
    async fn identify_with_password() -> Result<()> {
        let mut client = Client::from_config(Config {
            nickname: Some("test".to_string()),
            password: Some("password".to_string()),
            ..test_config()
        })
        .await?;
        client.identify()?;
        client.stream()?.collect().await?;
        assert_eq!(
            &get_client_value(client).await[..],
            "CAP END\r\nPASS password\r\nNICK test\r\n\
             USER test 0 * test\r\n"
        );
        Ok(())
    }

    #[tokio::test]
    async fn send_pong() -> Result<()> {
        let mut client = Client::from_config(test_config()).await?;
        client.send_pong("irc.test.net")?;
        client.stream()?.collect().await?;
        assert_eq!(&get_client_value(client).await[..], "PONG irc.test.net\r\n");
        Ok(())
    }

    #[tokio::test]
    async fn send_join() -> Result<()> {
        let mut client = Client::from_config(test_config()).await?;
        client.send_join("#test,#test2,#test3")?;
        client.stream()?.collect().await?;
        assert_eq!(
            &get_client_value(client).await[..],
            "JOIN #test,#test2,#test3\r\n"
        );
        Ok(())
    }

    #[tokio::test]
    async fn send_part() -> Result<()> {
        let mut client = Client::from_config(test_config()).await?;
        client.send_part("#test")?;
        client.stream()?.collect().await?;
        assert_eq!(&get_client_value(client).await[..], "PART #test\r\n");
        Ok(())
    }

    #[tokio::test]
    async fn send_oper() -> Result<()> {
        let mut client = Client::from_config(test_config()).await?;
        client.send_oper("test", "test")?;
        client.stream()?.collect().await?;
        assert_eq!(&get_client_value(client).await[..], "OPER test test\r\n");
        Ok(())
    }

    #[tokio::test]
    async fn send_privmsg() -> Result<()> {
        let mut client = Client::from_config(test_config()).await?;
        client.send_privmsg("#test", "Hi, everybody!")?;
        client.stream()?.collect().await?;
        assert_eq!(
            &get_client_value(client).await[..],
            "PRIVMSG #test :Hi, everybody!\r\n"
        );
        Ok(())
    }

    #[tokio::test]
    async fn send_notice() -> Result<()> {
        let mut client = Client::from_config(test_config()).await?;
        client.send_notice("#test", "Hi, everybody!")?;
        client.stream()?.collect().await?;
        assert_eq!(
            &get_client_value(client).await[..],
            "NOTICE #test :Hi, everybody!\r\n"
        );
        Ok(())
    }

    #[tokio::test]
    async fn send_topic_no_topic() -> Result<()> {
        let mut client = Client::from_config(test_config()).await?;
        client.send_topic("#test", "")?;
        client.stream()?.collect().await?;
        assert_eq!(&get_client_value(client).await[..], "TOPIC #test\r\n");
        Ok(())
    }

    #[tokio::test]
    async fn send_topic() -> Result<()> {
        let mut client = Client::from_config(test_config()).await?;
        client.send_topic("#test", "Testing stuff.")?;
        client.stream()?.collect().await?;
        assert_eq!(
            &get_client_value(client).await[..],
            "TOPIC #test :Testing stuff.\r\n"
        );
        Ok(())
    }

    #[tokio::test]
    async fn send_kill() -> Result<()> {
        let mut client = Client::from_config(test_config()).await?;
        client.send_kill("test", "Testing kills.")?;
        client.stream()?.collect().await?;
        assert_eq!(
            &get_client_value(client).await[..],
            "KILL test :Testing kills.\r\n"
        );
        Ok(())
    }

    #[tokio::test]
    async fn send_kick_no_message() -> Result<()> {
        let mut client = Client::from_config(test_config()).await?;
        client.send_kick("#test", "test", "")?;
        client.stream()?.collect().await?;
        assert_eq!(&get_client_value(client).await[..], "KICK #test test\r\n");
        Ok(())
    }

    #[tokio::test]
    async fn send_kick() -> Result<()> {
        let mut client = Client::from_config(test_config()).await?;
        client.send_kick("#test", "test", "Testing kicks.")?;
        client.stream()?.collect().await?;
        assert_eq!(
            &get_client_value(client).await[..],
            "KICK #test test :Testing kicks.\r\n"
        );
        Ok(())
    }

    #[tokio::test]
    async fn send_mode_no_modeparams() -> Result<()> {
        let mut client = Client::from_config(test_config()).await?;
        client.send_mode("#test", &[Mode::Plus(ChannelMode::InviteOnly, None)])?;
        client.stream()?.collect().await?;
        assert_eq!(&get_client_value(client).await[..], "MODE #test +i\r\n");
        Ok(())
    }

    #[tokio::test]
    async fn send_mode() -> Result<()> {
        let mut client = Client::from_config(test_config()).await?;
        client.send_mode(
            "#test",
            &[
                Mode::Plus(ChannelMode::Oper, Some("test".to_owned())),
                Mode::Minus(ChannelMode::Oper, Some("test2".to_owned())),
            ],
        )?;
        client.stream()?.collect().await?;
        assert_eq!(
            &get_client_value(client).await[..],
            "MODE #test +o-o test test2\r\n"
        );
        Ok(())
    }

    #[tokio::test]
    async fn send_umode() -> Result<()> {
        let mut client = Client::from_config(test_config()).await?;
        client.send_mode(
            "test",
            &[
                Mode::Plus(UserMode::Invisible, None),
                Mode::Plus(UserMode::MaskedHost, None),
            ],
        )?;
        client.stream()?.collect().await?;
        assert_eq!(&get_client_value(client).await[..], "MODE test +i+x\r\n");
        Ok(())
    }

    #[tokio::test]
    async fn send_samode_no_modeparams() -> Result<()> {
        let mut client = Client::from_config(test_config()).await?;
        client.send_samode("#test", "+i", "")?;
        client.stream()?.collect().await?;
        assert_eq!(&get_client_value(client).await[..], "SAMODE #test +i\r\n");
        Ok(())
    }

    #[tokio::test]
    async fn send_samode() -> Result<()> {
        let mut client = Client::from_config(test_config()).await?;
        client.send_samode("#test", "+o", "test")?;
        client.stream()?.collect().await?;
        assert_eq!(
            &get_client_value(client).await[..],
            "SAMODE #test +o test\r\n"
        );
        Ok(())
    }

    #[tokio::test]
    async fn send_sanick() -> Result<()> {
        let mut client = Client::from_config(test_config()).await?;
        client.send_sanick("test", "test2")?;
        client.stream()?.collect().await?;
        assert_eq!(&get_client_value(client).await[..], "SANICK test test2\r\n");
        Ok(())
    }

    #[tokio::test]
    async fn send_invite() -> Result<()> {
        let mut client = Client::from_config(test_config()).await?;
        client.send_invite("test", "#test")?;
        client.stream()?.collect().await?;
        assert_eq!(&get_client_value(client).await[..], "INVITE test #test\r\n");
        Ok(())
    }

    #[tokio::test]
    #[cfg(feature = "ctcp")]
    async fn send_ctcp() -> Result<()> {
        let mut client = Client::from_config(test_config()).await?;
        client.send_ctcp("test", "LINE1\r\nLINE2\r\nLINE3")?;
        client.stream()?.collect().await?;
        assert_eq!(
            &get_client_value(client).await[..],
            "PRIVMSG test \u{001}LINE1\u{001}\r\nPRIVMSG test \u{001}LINE2\u{001}\r\nPRIVMSG test \u{001}LINE3\u{001}\r\n"
        );
        Ok(())
    }

    #[tokio::test]
    #[cfg(feature = "ctcp")]
    async fn send_action() -> Result<()> {
        let mut client = Client::from_config(test_config()).await?;
        client.send_action("test", "tests.")?;
        client.stream()?.collect().await?;
        assert_eq!(
            &get_client_value(client).await[..],
            "PRIVMSG test :\u{001}ACTION tests.\u{001}\r\n"
        );
        Ok(())
    }

    #[tokio::test]
    #[cfg(feature = "ctcp")]
    async fn send_finger() -> Result<()> {
        let mut client = Client::from_config(test_config()).await?;
        client.send_finger("test")?;
        client.stream()?.collect().await?;
        assert_eq!(
            &get_client_value(client).await[..],
            "PRIVMSG test \u{001}FINGER\u{001}\r\n"
        );
        Ok(())
    }

    #[tokio::test]
    #[cfg(feature = "ctcp")]
    async fn send_version() -> Result<()> {
        let mut client = Client::from_config(test_config()).await?;
        client.send_version("test")?;
        client.stream()?.collect().await?;
        assert_eq!(
            &get_client_value(client).await[..],
            "PRIVMSG test \u{001}VERSION\u{001}\r\n"
        );
        Ok(())
    }

    #[tokio::test]
    #[cfg(feature = "ctcp")]
    async fn send_source() -> Result<()> {
        let mut client = Client::from_config(test_config()).await?;
        client.send_source("test")?;
        client.stream()?.collect().await?;
        assert_eq!(
            &get_client_value(client).await[..],
            "PRIVMSG test \u{001}SOURCE\u{001}\r\n"
        );
        Ok(())
    }

    #[tokio::test]
    #[cfg(feature = "ctcp")]
    async fn send_user_info() -> Result<()> {
        let mut client = Client::from_config(test_config()).await?;
        client.send_user_info("test")?;
        client.stream()?.collect().await?;
        assert_eq!(
            &get_client_value(client).await[..],
            "PRIVMSG test \u{001}USERINFO\u{001}\r\n"
        );
        Ok(())
    }

    #[tokio::test]
    #[cfg(feature = "ctcp")]
    async fn send_ctcp_ping() -> Result<()> {
        let mut client = Client::from_config(test_config()).await?;
        client.send_ctcp_ping("test")?;
        client.stream()?.collect().await?;
        let val = get_client_value(client).await;
        println!("{}", val);
        assert!(val.starts_with("PRIVMSG test :\u{001}PING "));
        assert!(val.ends_with("\u{001}\r\n"));
        Ok(())
    }

    #[tokio::test]
    #[cfg(feature = "ctcp")]
    async fn send_time() -> Result<()> {
        let mut client = Client::from_config(test_config()).await?;
        client.send_time("test")?;
        client.stream()?.collect().await?;
        assert_eq!(
            &get_client_value(client).await[..],
            "PRIVMSG test \u{001}TIME\u{001}\r\n"
        );
        Ok(())
    }

    #[tokio::test]
    async fn local_addr_is_none_for_mock() -> Result<()> {
        let client = Client::from_config(test_config()).await?;
        assert_eq!(client.local_addr(), None);
        Ok(())
    }

    #[test]
    fn batch_joins_all_keyless() {
        let chans: Vec<String> = vec!["#a".into(), "#b".into(), "#c".into()];
        let keys = HashMap::new();
        let batches = ClientState::build_batched_joins(&chans, &keys);
        assert_eq!(batches.len(), 1);
        assert_eq!(batches[0].0, "#a,#b,#c");
        assert!(batches[0].1.is_none());
    }

    #[test]
    fn batch_joins_keyed_first() {
        let chans: Vec<String> = vec!["#plain".into(), "#secret".into(), "#open".into()];
        let mut keys = HashMap::new();
        keys.insert("#secret".to_string(), "pass".to_string());
        let batches = ClientState::build_batched_joins(&chans, &keys);
        assert_eq!(batches.len(), 1);
        assert_eq!(batches[0].0, "#secret,#plain,#open");
        assert_eq!(batches[0].1.as_deref(), Some("pass"));
    }

    #[test]
    fn batch_joins_multiple_keys() {
        let chans: Vec<String> = vec!["#a".into(), "#b".into(), "#c".into(), "#d".into()];
        let mut keys = HashMap::new();
        keys.insert("#b".to_string(), "kb".to_string());
        keys.insert("#d".to_string(), "kd".to_string());
        let batches = ClientState::build_batched_joins(&chans, &keys);
        assert_eq!(batches.len(), 1);
        // Keyed channels first (preserving config order: #b before #d), then keyless
        assert_eq!(batches[0].0, "#b,#d,#a,#c");
        assert_eq!(batches[0].1.as_deref(), Some("kb,kd"));
    }

    #[test]
    fn batch_joins_empty() {
        let chans: Vec<String> = Vec::new();
        let keys = HashMap::new();
        let batches = ClientState::build_batched_joins(&chans, &keys);
        assert!(batches.is_empty());
    }

    #[test]
    fn batch_joins_respects_line_limit() {
        // Create channels that exceed 512-byte line limit when combined
        // "JOIN " (5) + channels + "\r\n" (2) must be <= 512, so payload <= 505
        // Each channel is ~50 chars, so ~10 channels per batch
        let chans: Vec<String> = (0..15)
            .map(|i| format!("#channel-with-a-long-name-for-testing-{:02}", i))
            .collect();
        let keys = HashMap::new();
        let batches = ClientState::build_batched_joins(&chans, &keys);
        assert!(batches.len() > 1, "should split into multiple batches");
        for (chanlist, keylist) in &batches {
            // "JOIN " + chanlist + "\r\n" must fit in 512
            let line_len = 5 + chanlist.len() + 2;
            assert!(line_len <= 512, "batch line too long: {} bytes", line_len);
            assert!(keylist.is_none());
        }
        // All channels should be present
        let all_chans: Vec<&str> = batches.iter().flat_map(|(cl, _)| cl.split(',')).collect();
        assert_eq!(all_chans.len(), 15);
    }

    #[test]
    fn batch_joins_keyed_with_line_limit() {
        // Keyed channels that exceed the limit with their keys
        let chans: Vec<String> = (0..15)
            .map(|i| format!("#keyed-channel-long-name-{:02}", i))
            .collect();
        let keys: HashMap<String, String> = chans
            .iter()
            .map(|c| (c.clone(), "a-somewhat-long-key-value".to_string()))
            .collect();
        let batches = ClientState::build_batched_joins(&chans, &keys);
        assert!(batches.len() > 1, "should split into multiple batches");
        for (ref chanlist, ref keylist) in &batches {
            let kl = keylist.as_ref().expect("all keyed");
            // "JOIN " + chanlist + " " + keylist + "\r\n" must fit in 512
            let line_len: usize = 5 + chanlist.len() + 1 + kl.len() + 2;
            assert!(line_len <= 512, "batch line too long: {} bytes", line_len);
        }
    }
}
