# shellsight

**Know what a shell snippet will do before you run it.**

An AI (or a forum post, or a colleague) hands you a block of shell commands for your
server. Which lines only *look* at things, and which ones *change* things or could break
the machine? Paste the block into `shellsight` and every command gets a label:

| Level     | Meaning |
|-----------|---------|
| `READ`    | Only reads or prints information. |
| `UNKNOWN` | Not in shellsight's list. Check it yourself. |
| `EXEC`    | Runs a program or script whose contents shellsight can't see. |
| `WRITE`   | Changes files, packages, services, users or other system state. |
| `DANGER`  | Destructive or high risk: wipes data, formats disks, runs code from the internet, reboots, locks you out. |

```text
$ shellsight
--- paste below ---
sudo apt update && sudo apt install -y nginx
curl -fsSL https://get.docker.com | sudo sh
ssh root@host 'systemctl status nginx; docker ps'
git status; git reset --hard origin/main
^D

WRITE   sudo apt update
        -> installs/removes/updates packages (as root)
WRITE   sudo apt install -y nginx
        -> installs/removes/updates packages (as root)
READ    curl -fsSL https://get.docker.com
        -> fetches a URL and prints it
DANGER  | sudo sh
        -> executes code downloaded from the internet (as root)
READ    ssh root@host 'systemctl status nginx; docker ps'
        -> runs the command(s) below on remote host root@host
    READ    systemctl status nginx
            -> reads systemctl state
    READ    docker ps
            -> reads docker state
READ    git status
        -> reads the repository
DANGER  git reset --hard origin/main
        -> git reset --hard discards uncommitted work

Summary: 2 DANGER, 2 WRITE, 0 EXEC, 0 UNKNOWN, 5 READ
Verdict: DANGER - Contains destructive or high-risk commands. Do NOT run this blindly.
```

## Privacy

- **Nothing is executed.** shellsight only reads the text; it never runs any command.
- **Nothing leaves your machine.** No network access, no telemetry, no logs, no files written.
- **No dependencies.** One Python file using only the standard library, so you can read
  all of it before trusting it.

## Install

Needs Python 3.8 or newer, which ships with almost every Linux distribution. It also runs
on macOS, Windows and WSL.

```sh
# Option 1: just grab the file (read it first, it's one file)
git clone https://github.com/tomgutgar/shellsight
python3 shellsight/shellsight.py

# Option 2: install it as a command
pipx install git+https://github.com/tomgutgar/shellsight
shellsight
```

## Usage

```sh
shellsight                      # interactive: paste a block, then Ctrl-D (Ctrl-Z Enter on Windows)
shellsight -c 'rm -rf "$DIR/"'  # analyze a string
shellsight install.sh           # analyze a script file
xclip -o | shellsight           # analyze from a pipe (here: your clipboard)
shellsight --no-color           # plain output (NO_COLOR is also respected)
```

Exit codes make it usable in scripts: `0` read-only, `1` unknown/exec, `2` write (also
used for bad arguments), `3` danger.

## What it understands

- Pipes, `&&`, `||`, `;`, subshells, line continuations, comments and quoting.
- Redirections: `> file` (overwrite), `>> file` (append), writes to `/dev/sdX` and to
  critical files like `/etc/passwd`, `/etc/fstab` or `/etc/sudoers`. `2>/dev/null` is harmless.
- Code hidden inside other code: `$(...)`, backticks, `<(...)`, `bash -c '...'`,
  `sudo sh -c`, `su -c`, `eval`, `ssh host 'cmd'`, `watch`, `xargs`, `find -exec`, and
  heredocs fed to `bash`, `ssh` or a database client.
- Wrappers like `sudo`, `env`, `nohup`, `timeout`, `nice` (it marks commands run as root).
- `curl ... | sh`, `bash <(curl ...)` and `sh -c "$(curl ...)"`.
- Commands whose risk depends on the arguments: `rm -rf` on `/`, `~`, `*` or an
  `"$VAR/"` that may be empty; `sed -i`; `git reset --hard` / `push --force` / `clean -f`;
  `systemctl status` vs `restart`; `apt list` vs `install`; `docker ps` vs `run`;
  `crontab -l` vs `-r`; `iptables -L` vs `-F`; `dd of=/dev/sda`; inline SQL
  (`SELECT` vs `UPDATE` vs `DROP`) for `mysql`, `psql`, `sqlite3`; `redis-cli FLUSHALL`; and more.

## Limits

shellsight is a quick second opinion, not a sandbox or a guarantee.

- It reads text; it can't know what a variable contains at runtime or what a script
  file does (it tells you to check those).
- `READ` means "no known side effects", not "safe": reading a secret and sending it
  somewhere is still possible with "read" commands.
- Rules cover common Linux tools. Anything else shows up as `UNKNOWN` rather than
  being guessed as safe.

When in doubt, run unfamiliar commands on a test machine or container first.

## Contributing

Found a command that gets the wrong label? Open an issue with the snippet, or add a case
to `test_shellsight.py` and the rule to `shellsight.py`. Tests use only the standard library:

```sh
python3 -m unittest -v
```

## License

[MIT](LICENSE)
