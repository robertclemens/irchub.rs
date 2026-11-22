# The hub console over SSH

Each hub serves an SSH console on its own port. Only admins log in, with the SSH key `keygen` made. There is no password and no system account.

![The hub console over SSH (recording)](console.svg)

The same steps as screenshots:

## 1. Check the hub's SSH host key

Compare this fingerprint with the one ssh shows on the first login.

```
irchub/bin/keygen --ssh-fingerprint hub1/hub_public.b64
```

![Check the hub's SSH host key](console-00.svg)

## 2. Log in with the admin's SSH key

Any SSH client works (OpenSSH, PuTTY, phone apps). The console has an output pane, a live network tree, a status bar and the input line. Scripts can use `TERM=dumb ssh -tt …` for a plain line mode with one `[ok #N]` / `[err #N]` per command.

```
ssh -i admin/20261122105812_admin_ed25519 -o IdentitiesOnly=yes -p 8001 admin@127.0.0.1
```

![Log in with the admin's SSH key](console-01.svg)

## 3. Help

`help <group>` lists a group's commands; `help <group> <command>` explains one.

```
> help
```

![Help](console-02.svg)

## 4. Hub list

```
> hub list
```

![Hub list](console-03.svg)

## 5. Bot list

```
> bot list
```

![Bot list](console-04.svg)

## 6. Bot show bot1

```
> bot show bot1
```

![Bot show bot1](console-05.svg)

## 7. Channel show #demo

```
> channel show #demo
```

![Channel show #demo](console-06.svg)

## 8. User show admin

```
> user show admin
```

![User show admin](console-07.svg)

## 9. Views: Alt+1 … Alt+5

`Alt+1` console, `Alt+2` raw log, `Alt+3` network, `Alt+4` upgrades, `Alt+5` stats.

```
Alt+3
> quit
```

![Views: Alt+1 … Alt+5](console-08.svg)

← [Set up two hubs, link them, add a bot](setup.md) · [all walkthroughs](README.md) · [Commanding a bot from irssi](irssi.md) →
