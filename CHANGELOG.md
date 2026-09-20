## 1.5.2

- Add connection-local runtime autojoin control so bouncer clients can disable automatic joins after capability discovery.

- Add connection-local runtime flood protection control on sender clones.
- Wake delayed outgoing messages when protection is disabled; restore the original configured threshold when enabled.
- Add TCP integration coverage for queued delivery, re-enabling, connection isolation, and configured-zero behavior.

# Changelog

## 1.5.1

- Fix: PINGs from the internal Pinger now flow through a priority lane that bypasses outgoing flood-penalty throttling. Previously, a large client-initiated paste burst could enqueue enough PRIVMSGs ahead of a queued PING to expire `ping_timeout` before the PING reached the sink, causing a self-inflicted disconnect that surfaced as `EOF From client` on the server side.
- No public API changes; downstream consumers do not need code changes. Bumping the dependency version is sufficient.
