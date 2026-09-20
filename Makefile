.PHONY: clippy test package
FEATURES = tls-rust,channel-lists,toml_config,encoding
clippy:
	cargo clippy -p irc-repartee --all-targets --no-default-features --features $(FEATURES)
test:
	cargo test -p irc-repartee --no-default-features --features $(FEATURES)
	cargo test -p irc-repartee
package:
	cargo package -p irc-repartee
