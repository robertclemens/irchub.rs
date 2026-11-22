# Walkthroughs

Three short recordings, each with the same steps as screenshots and every command. All names are generic (admin, hub1, hub2, bot1, #demo) and everything runs on 127.0.0.1. Hidden prompts (passwords, passphrases) are typed but not shown.

1. **[Set up two hubs, link them, add a bot](setup.md)**: keys, two hubs, link, bot
2. **[The hub console over SSH](console.md)**: SSH login, sample commands, full-screen view
3. **[Commanding a bot from irssi](irssi.md)**: script, key, /botcmd

The commands, wizards and console are the same for C and Rust; only where the built binaries live differs. Hubs and bots of either language mix freely.

| | C | Rust |
|---|---|---|
| hub, keygen | `irchub/bin/irchub`, `irchub/bin/keygen` | `irchub.rs/target/release/irchub`, `irchub.rs/target/release/keygen` |
| bot | `ircbot/ircbot` | `ircbot.rs/target/release/ircbot` |
| irssi script | `ircbot/utils/ircbot_irssi_auth.pl` | `ircbot.rs/utils/ircbot_irssi_auth.pl` |
