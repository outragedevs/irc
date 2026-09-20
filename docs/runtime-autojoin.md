# Runtime autojoin control

`Sender::set_autojoin_enabled(bool)` controls configured-channel autojoin and
remembered-channel rejoin when the incoming stream processes `RPL_ENDOFMOTD`
(376) or `ERR_NOMOTD` (422). The default is enabled. All sender clones from one
client share the setting; other clients retain their own state.

A consumer that discovers a bouncer in CAP LS can disable autojoin before it
ends capability negotiation. This prevents the library from creating upstream
membership on a bouncer that already manages the user's channels. The caller
must still identify its endpoint and handle its own connection/history state;
this library method does not detect bouncers or classify incoming history.

The switch is sampled when processing the MOTD-ending message. Disabling does
not remove JOINs already queued. Enabling does not send anything immediately;
it affects the next MOTD-ending message. Explicit `send_join` and
`send_join_with_keys` calls remain available. NickServ identification and user
mode setup are unaffected.

`src/client/autojoin_tests.rs` covers CAP discovery followed by disabling from a
sender clone, both MOTD endings, keyed configured channels, remembered channels,
explicit JOIN, preserved NickServ/user modes, re-enabling and separate clients.
The Makefile runs the Rust TLS/channel-list feature combination and the default
features. These are library transport/mock-stream tests, not completed Repartee
bouncer integration. The downstream consumer still needs to adopt the released
API before legacy-selector autojoin suppression can be claimed.
