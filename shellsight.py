#!/usr/bin/env python3
"""shellsight: see what a shell snippet reads, writes or executes before you run it.

Pure static analysis with the Python standard library only. Nothing you paste is
executed, stored or sent anywhere.
"""
import argparse
import os
import re
import sys

__version__ = "0.1.0"

READ, UNKNOWN, EXEC, WRITE, DANGER = "READ", "UNKNOWN", "EXEC", "WRITE", "DANGER"
RANK = {READ: 0, UNKNOWN: 1, EXEC: 2, WRITE: 3, DANGER: 4}

# --------------------------------------------------------------------------- tokenizer

OPS = ("&>>", "<<<", "<<-", ">>", "<<", "&&", "||", ";;", ">&", "<&", "&>", ">|", "|&",
       "<>", ">", "<", "|", "&", ";", "(", ")")
REDIRECTS = {">", ">>", ">|", "&>", "&>>", ">&", "<", "<>", "<&", "<<<"}
PIPES = {"|", "|&"}
CONTINUE_OPS = {"|", "|&", "&&", "||"}
HEREDOC_DELIM = re.compile(r"[ \t]*(['\"]?)([^\s'\"<>|&;()]+)\1")


def _skip_double(text, i):
    """i is just past an opening '"'. Return the index of the closing '"'."""
    while i < len(text):
        c = text[i]
        if c == "\\":
            i += 2
            continue
        if text.startswith("$(", i):
            i = _balanced(text, i + 2)
        elif c == "`":
            i = _skip_backtick(text, i + 1)
        elif c == '"':
            return i
        i += 1
    return len(text)


def _skip_backtick(text, i):
    """i is just past an opening '`'. Return the index of the closing '`'."""
    while i < len(text):
        if text[i] == "\\":
            i += 2
            continue
        if text[i] == "`":
            return i
        i += 1
    return len(text)


def _balanced(text, i):
    """i is just past an opening '('. Return the index of the matching ')'."""
    depth = 1
    while i < len(text):
        c = text[i]
        if c == "\\":
            i += 2
            continue
        if c == "'":
            i = text.find("'", i + 1)
            if i < 0:
                return len(text)
        elif c == '"':
            i = _skip_double(text, i + 1)
        elif c == "(":
            depth += 1
        elif c == ")":
            depth -= 1
            if depth == 0:
                return i
        i += 1
    return len(text)


def _subs_in_double(s):
    """Command substitutions inside a double-quoted string."""
    subs, i = [], 0
    while i < len(s):
        if s[i] == "\\":
            i += 2
            continue
        if s.startswith("$((", i):
            i = _balanced(s, i + 2)
        elif s.startswith("$(", i):
            j = _balanced(s, i + 2)
            subs.append(s[i + 2:j])
            i = j
        elif s[i] == "`":
            j = _skip_backtick(s, i + 1)
            subs.append(s[i + 1:j])
            i = j
        i += 1
    return subs


def _read_heredoc(text, i, delim):
    """Read heredoc lines from i. Return (body, index of the newline after the delimiter)."""
    lines = []
    while i < len(text):
        j = text.find("\n", i)
        j = len(text) if j < 0 else j
        line = text[i:j]
        if line.strip() == delim:
            return "\n".join(lines), j
        lines.append(line)
        i = j + 1
    return "\n".join(lines), len(text)


def tokenize(text):
    """Split shell text into tokens: ["w", word], ["op", op], ["sub", code], ["heredoc", body]."""
    toks, pending = [], []
    word, has_word = [], False
    i, n = 0, len(text)

    def flush():
        nonlocal word, has_word
        if has_word:
            toks.append(["w", "".join(word)])
        word, has_word = [], False

    while i < n:
        c = text[i]
        if c == "\\":
            if not text.startswith("\n", i + 1):
                word.append(text[i + 1:i + 2])
                has_word = True
            i += 2
        elif c == "'":
            j = text.find("'", i + 1)
            j = n if j < 0 else j
            word.append(text[i + 1:j])
            has_word, i = True, j + 1
        elif c == '"':
            j = _skip_double(text, i + 1)
            inner = text[i + 1:j]
            toks.extend(["sub", s] for s in _subs_in_double(inner))
            word.append(inner)
            has_word, i = True, j + 1
        elif text.startswith("$((", i):
            j = _balanced(text, i + 2)
            word.append(text[i:j + 1])
            has_word, i = True, j + 1
        elif text.startswith("$(", i) or (c in "<>" and text.startswith("(", i + 1) and not has_word):
            j = _balanced(text, i + 2)
            toks.append(["sub", text[i + 2:j]])
            word.append(text[i:j + 1])
            has_word, i = True, j + 1
        elif c == "`":
            j = _skip_backtick(text, i + 1)
            toks.append(["sub", text[i + 1:j]])
            word.append(text[i:j + 1])
            has_word, i = True, j + 1
        elif text.startswith("$'", i):
            j = i + 2
            while j < n and text[j] != "'":
                j += 2 if text[j] == "\\" else 1
            word.append(text[i + 2:j])
            has_word, i = True, j + 1
        elif c == "#" and not has_word:
            j = text.find("\n", i)
            i = n if j < 0 else j
        elif c in " \t\r":
            flush()
            i += 1
        elif c == "\n":
            flush()
            for ref, delim in pending:
                ref[1], i = _read_heredoc(text, i + 1, delim)
            pending = []
            if not (toks and toks[-1][0] == "op" and toks[-1][1] in CONTINUE_OPS):
                toks.append(["op", "\n"])
            i += 1
        elif c in "<>&|;()":
            op = next(o for o in OPS if text.startswith(o, i))
            if op[0] in "<>" and "".join(word).isdigit():  # file descriptor, e.g. 2>
                word, has_word = [], False
            flush()
            i += len(op)
            m = HEREDOC_DELIM.match(text, i) if op in ("<<", "<<-") else None
            if m:
                ref = ["heredoc", ""]
                toks.append(ref)
                pending.append((ref, m.group(2)))
                i = m.end()
            else:
                toks.append(["op", op])
        else:
            word.append(c)
            has_word = True
            i += 1
    flush()
    return toks


def split_commands(toks):
    """Group tokens into simple commands (dicts with words, redirs, heredocs, subs, piped_from)."""
    def new(piped_from=None):
        return {"words": [], "redirs": [], "heredocs": [], "subs": [], "piped_from": piped_from}

    def filled(c):
        return any(c[k] for k in ("words", "redirs", "heredocs", "subs"))

    cmds, cur, expect, parens = [], new(), None, 0
    for k, (kind, val) in enumerate(toks):
        if kind == "sub":
            cur["subs"].append(val)
            continue
        if expect:
            if kind == "w":
                cur["redirs"].append((expect, val))
                expect = None
                continue
            expect = None
        if kind == "w":
            cur["words"].append(val)
        elif kind == "heredoc":
            cur["heredocs"].append(val)
        elif val in REDIRECTS:
            expect = val
        elif val == "(" and len(cur["words"]) == 1 and toks[k + 1:k + 2] == [["op", ")"]]:
            cur = new()  # "name() {" function definition header; the body is analyzed normally
            parens += 1
        else:
            if val == "(":
                parens += 1
            elif val == ")":
                if parens == 0:  # "pattern)" in a case statement
                    cur = new()
                parens = max(parens - 1, 0)
            if filled(cur):
                cmds.append(cur)
            cur = new(cur["words"][0] if val in PIPES and cur["words"] else None)
    if filled(cur):
        cmds.append(cur)
    return cmds


# --------------------------------------------------------------------------- knowledge

def _set(s):
    return set(s.split())


KEYWORDS = _set("if then else elif fi do done while until { } ! esac coproc")
LOOP_HEADERS = _set("for select case")
ASSIGN = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*(\[[^]]*\])?\+?=")

READ_CMDS = _set("""
ls ll dir vdir cat tac less more most head tail grep egrep fgrep zgrep rg ag ack wc sort uniq cut
paste tr column fold fmt nl comm join diff diff3 sdiff cmp colordiff file stat du df free uptime w
who whoami id groups users last lastb lastlog uname arch pwd echo printf cal printenv which whereis
type hash locate mlocate plocate ps pstree top htop atop btop pgrep pidof lsof ss netstat ping ping6
traceroute tracepath mtr dig nslookup host whois dmesg lsblk blkid lscpu lsusb lspci lsmod lshw lsns
lsattr lsipc lslocks lslogins findmnt history test [ [[ true false : sleep yes seq basename dirname
realpath readlink md5sum sha1sum sha224sum sha256sum sha384sum sha512sum b2sum cksum sum base64
base32 xxd hexdump od strings tree jq yq nproc getent ldd vmstat iostat mpstat pidstat sar nmon
iotop iftop nethogs man info apropos whatis tldr cd pushd popd dirs export unset alias unalias set
shopt read local declare typeset readonly trap ulimit umask exit return break continue wait shift
getopts let jobs fg bg disown logname tty locale zcat bzcat xzcat zstdcat zless zmore numfmt expr bc
dc factor shuf apt-cache dpkg-query systemd-analyze lsb_release neofetch fastfetch inxi sensors
tput clear stty namei ssh-keyscan look rev lvs vgs pvs lvdisplay vgdisplay pvdisplay
lvscan vgscan pvscan
""")

WRITE_CMDS = {
    "rmdir": "removes directories", "unlink": "deletes a file",
    "mv": "moves/renames files (can overwrite)", "cp": "copies files (can overwrite)",
    "mkdir": "creates directories", "touch": "creates files / changes timestamps",
    "ln": "creates links (-f overwrites)", "chmod": "changes permissions", "chown": "changes owner",
    "chgrp": "changes group", "truncate": "changes file size (can empty files)",
    "install": "copies files and sets permissions", "rsync": "syncs files (can overwrite/delete)",
    "scp": "copies files over SSH", "sftp": "transfers files over SSH", "patch": "modifies files",
    "split": "creates files", "csplit": "creates files", "mkfifo": "creates a pipe file",
    "mknod": "creates a device file", "setfacl": "changes file ACLs", "chattr": "changes file attributes",
    "fallocate": "allocates file space", "kill": "sends signals / stops processes",
    "pkill": "stops processes", "killall": "stops processes",
    "useradd": "creates a user", "userdel": "deletes a user", "usermod": "changes a user",
    "adduser": "creates a user", "deluser": "deletes a user", "groupadd": "creates a group",
    "groupdel": "deletes a group", "groupmod": "changes a group", "gpasswd": "changes group members",
    "passwd": "changes a password", "chpasswd": "changes passwords", "chsh": "changes login shell",
    "chfn": "changes user info", "chage": "changes password expiry", "visudo": "edits sudoers",
    "vipw": "edits the user database", "vigr": "edits the group database",
    "umount": "unmounts filesystems", "swapon": "enables swap", "swapoff": "disables swap",
    "modprobe": "loads/unloads kernel modules", "rmmod": "unloads a kernel module",
    "insmod": "loads a kernel module", "depmod": "rebuilds module index",
    "update-grub": "rebuilds the bootloader config", "grub-install": "installs the bootloader",
    "grub-mkconfig": "rebuilds the bootloader config", "update-initramfs": "rebuilds the initramfs",
    "mkinitcpio": "rebuilds the initramfs", "dracut": "rebuilds the initramfs",
    "ldconfig": "rebuilds the library cache", "update-alternatives": "changes default programs",
    "locale-gen": "generates locales", "ssh-keygen": "creates/changes SSH keys",
    "ssh-copy-id": "adds your key to a remote server", "certbot": "changes certificates / web config",
    "a2enmod": "changes Apache config", "a2dismod": "changes Apache config",
    "a2ensite": "changes Apache config", "a2dissite": "changes Apache config",
    "logrotate": "rotates log files", "zip": "creates an archive", "sync": "flushes disk caches",
    "fsck": "checks/repairs a filesystem", "e2fsck": "checks/repairs a filesystem",
    "resize2fs": "resizes a filesystem", "tune2fs": "changes filesystem settings",
    "lvcreate": "creates a logical volume", "lvextend": "resizes a logical volume",
    "lvresize": "resizes a logical volume", "vgcreate": "creates a volume group",
    "vgextend": "changes a volume group", "pvcreate": "initialises a disk for LVM",
    "losetup": "attaches loop devices",
}
for _ed in "vi vim nvim nano emacs ed pico joe micro mcedit sudoedit".split():
    WRITE_CMDS[_ed] = "opens an editor (can modify files)"

DANGER_CMDS = {
    "fdisk": "edits disk partitions", "sfdisk": "edits disk partitions", "gdisk": "edits disk partitions",
    "cfdisk": "edits disk partitions", "sgdisk": "edits disk partitions", "parted": "edits disk partitions",
    "wipefs": "erases filesystem signatures", "mkswap": "formats a swap area",
    "shred": "irreversibly overwrites files", "reboot": "reboots the machine",
    "shutdown": "shuts down / reboots the machine", "poweroff": "powers off the machine",
    "halt": "halts the machine", "telinit": "changes runlevel (can reboot/halt)",
    "lvremove": "deletes a logical volume", "vgremove": "deletes a volume group",
    "pvremove": "wipes LVM metadata", "lvreduce": "shrinks a volume (data loss if wrong)",
    "blkdiscard": "discards all data on a device", "cryptsetup": "manages disk encryption",
}

SHELLS = _set("sh bash dash zsh ksh mksh fish ash tcsh csh busybox")
INTERPRETERS = _set("""python python2 python3 pypy pypy3 perl ruby node nodejs deno bun php lua luajit
Rscript tclsh groovy julia""")
DB_CLIENTS = _set("mysql mariadb psql sqlite3")
BUILD_TOOLS = _set("""make cmake ninja meson gradle mvn ant just task npx bunx uvx ansible
ansible-playbook vagrant""")

WRAPPERS = {  # name: (options that take a value, positional args before the real command)
    "sudo": ("-u -g -C -D -h -p -r -t -U -T --user --group --chdir --host --prompt --role "
             "--type --other-user --close-from --command-timeout", 0),
    "doas": ("-u -C", 0), "pkexec": ("--user", 0),
    "run0": ("-u --user -D --chdir --setenv --unit --property --description --slice --nice", 0),
    "env": ("-u -C --unset --chdir", 0), "nohup": ("", 0), "nice": ("-n --adjustment", 0),
    "ionice": ("-c -n -p -P -u --class --classdata", 0), "time": ("-f -o --format --output", 0),
    "timeout": ("-s -k --signal --kill-after", 1), "stdbuf": ("-i -o -e", 0), "builtin": ("", 0),
    "command": ("", 0), "exec": ("-a", 0), "setsid": ("", 0), "taskset": ("", 1),
    "chroot": ("--userspec --groups", 1), "flock": ("-w -E --timeout --conflict-exit-code", 1),
    "strace": ("-e -o -p -s -u -P", 0), "ltrace": ("-e -o -p -s -u", 0), "unbuffer": ("", 0),
    "watch": ("-n -d --interval --differences", 0), "proxychains": ("-f", 0),
    "proxychains4": ("-f", 0), "torsocks": ("", 0), "firejail": ("", 0),
    "xargs": ("-a -d -E -e -I -i -L -l -n -P -s --arg-file --delimiter --eof --replace "
              "--max-lines --max-args --max-procs --max-chars --process-slot-var", 0),
}
ROOT_WRAPPERS = _set("sudo doas pkexec run0")

PKG = "installs/removes/updates packages"
# name: (read subcommands, exec subcommands, danger subcommands, reason for anything else)
SUBCMDS = {
    "systemctl": ("status show list-units list-unit-files list-timers list-sockets list-dependencies "
                  "list-jobs list-machines is-active is-enabled is-failed is-system-running cat "
                  "get-default help", "", "poweroff reboot halt kexec rescue emergency isolate",
                  "changes services (start/stop/enable...)"),
    "apt": ("list search show policy depends rdepends madison changelog showsrc", "", "", PKG),
    "apt-get": ("check changelog", "", "", PKG),
    "aptitude": ("search show why why-not", "", "", PKG),
    "dnf": ("list search info provides repolist check-update history repoquery deplist", "", "", PKG),
    "yum": ("list search info provides repolist check-update history deplist", "", "", PKG),
    "zypper": ("search se info if list-updates lu packages pa repos lr patches", "", "", PKG),
    "apk": ("info search list policy dot stats", "", "", PKG),
    "snap": ("list find info version connections services changes", "run", "", "installs/changes snaps"),
    "flatpak": ("list info search remotes remote-ls history ps", "run", "", "installs/changes flatpaks"),
    "brew": ("list ls info search outdated doctor config deps leaves", "", "", PKG),
    "pip": ("list show freeze check search help config", "", "", "installs/removes Python packages"),
    "pipx": ("list", "run", "", "installs/removes Python apps"),
    "npm": ("ls list view info outdated search help config whoami ping doctor",
            "run run-script test start exec x", "", "installs/removes/publishes npm packages"),
    "pnpm": ("ls list view info outdated help why", "run test start exec dlx", "",
             "installs/removes npm packages"),
    "yarn": ("list info outdated help why", "run test start dlx", "", "installs/removes npm packages"),
    "cargo": ("search tree metadata help", "run test bench", "", "builds/installs Rust crates"),
    "gem": ("list search info query specification help", "", "", "installs/removes Ruby gems"),
    "docker": ("ps images inspect logs version info stats top port history search events diff",
               "run exec start", "", "changes containers/images/volumes"),
    "kubectl": ("get describe logs explain top version api-resources api-versions cluster-info diff "
                "auth", "exec run port-forward attach debug", "delete drain", "changes cluster resources"),
    "helm": ("list ls status get history search show template version lint env", "", "uninstall delete",
             "installs/changes cluster releases"),
    "zfs": ("list get status iostat history holds", "", "destroy", "changes ZFS datasets"),
    "zpool": ("list get status iostat history events", "", "destroy labelclear", "changes ZFS pools"),
    "nmcli": ("general g monitor", "", "", "changes network settings (can cut your connection)"),
    "hostnamectl": ("status", "", "", "changes the hostname"),
    "timedatectl": ("status show list-timezones timesync-status show-timesync", "", "",
                    "changes date/time settings"),
    "localectl": ("status list-locales list-keymaps", "", "", "changes locale settings"),
    "terraform": ("plan show output validate version providers graph state console", "", "destroy",
                  "changes real infrastructure"),
    "ufw": ("status show app", "", "disable reset", "changes the firewall (can cut your SSH access)"),
    "firewall-cmd": ("--state --list-all --list-all-zones --get-zones --get-active-zones "
                     "--list-services --list-ports --get-default-zone", "", "--panic-on",
                     "changes the firewall (can cut your SSH access)"),
    "nft": ("list", "", "flush", "changes the firewall (can cut your SSH access)"),
}
SUBCMDS = {k: tuple(_set(x) for x in v[:3]) + (v[3],) for k, v in SUBCMDS.items()}
for _alias, _orig in (("pip3", "pip"), ("podman", "docker"), ("nerdctl", "docker"),
                      ("oc", "kubectl"), ("microdnf", "dnf")):
    SUBCMDS[_alias] = SUBCMDS[_orig]

DEVICE = re.compile(r"^/dev/(sd|hd|vd|xvd|nvme|mmcblk|md|dm-|mapper/|disk/|loop)")
CRITICAL_FILES = re.compile(r"^/(etc/(passwd|shadow|group|gshadow|sudoers|fstab|hosts|ssh/sshd_config"
                            r"|pam\.d/.*|default/grub)|boot/.*)$")
CRITICAL_DIRS = _set("/ /* ~ ~/ ~/* $HOME $HOME/ ${HOME} . .. ./ * .* /etc /usr /var /boot /home /root "
                     "/bin /sbin /lib /lib64 /opt /srv /dev /proc /sys")
HARMLESS_TARGETS = re.compile(r"^(/dev/(null|stdout|stderr|tty|zero)|/dev/fd/\d+|&?\d+|-)$")


# --------------------------------------------------------------------------- helpers

def critical_path(p):
    """True for paths where a recursive change would wreck the system, home or cwd."""
    if p in CRITICAL_DIRS or p.rstrip("/") in CRITICAL_DIRS:
        return True
    # top-level dirs (/var, /tmp/*) and "$VAR/" which becomes "/" when VAR is empty
    return bool(re.match(r"^/[^/]+/?\*?$", p) or re.match(r"^\$\{?\w+\}?/\*?$", p))


def positionals(args):
    return [a for a in args if not a.startswith("-") or a == "-"]


def short_flags(args):
    """All single-letter flags, e.g. ['-rf', '-v'] -> 'rfv'."""
    return "".join(a[1:] for a in args if a.startswith("-") and not a.startswith("--") and a != "-")


def has(args, *names):
    """True if any option is present. Short flags also match inside clusters (-sd, -d'x')."""
    for a in args:
        for n in names:
            if a == n or a.startswith(n + "="):
                return True
            # ponytail: a cluster with an attached value (-H'x-data') can false-positive; safe side
            if len(n) == 2 and a.startswith("-") and not a.startswith("--") and n[1] in a[1:]:
                return True
    return False


def opt(args, *names):
    """Value of an exact option: '-e VALUE', '--execute VALUE' or '--execute=VALUE'."""
    for k, a in enumerate(args):
        for n in names:
            if a == n:
                return args[k + 1] if k + 1 < len(args) else ""
            if n.startswith("--") and a.startswith(n + "="):
                return a.split("=", 1)[1]
    return None


def flag_value(args, short, long_=None):
    """Like opt() but also finds short flags inside clusters: -XPOST, -qO-."""
    v = opt(args, long_) if long_ else None
    if v is not None:
        return v
    for k, a in enumerate(args):
        if a.startswith("-") and not a.startswith("--") and short in a[1:]:
            rest = a[a.index(short, 1) + 1:]
            return rest or (args[k + 1] if k + 1 < len(args) else "")
    return None


SQL_READ_START = re.compile(r"^\s*(SELECT|SHOW|DESCRIBE|DESC|EXPLAIN|\\d\w*|\\l|\\dt|\\conninfo)\b", re.I)
SQL_SIDE_EFFECTS = re.compile(r"\b(INTO|PROGRAM|PG_TERMINATE_BACKEND|PG_CANCEL_BACKEND|PG_RELOAD_CONF|"
                              r"LO_EXPORT|LO_IMPORT|SLEEP|BENCHMARK|NEXTVAL|SETVAL|FOR\s+UPDATE)\b", re.I)


def sql_level(sql):
    """Default-deny: only plain SELECT/SHOW/DESCRIBE/EXPLAIN statements count as read-only."""
    if re.search(r"\b(DROP|TRUNCATE)\b", sql, re.I):
        return DANGER, "runs SQL that drops/truncates data"
    statements = [s for s in sql.split(";") if s.strip()]
    if statements and all(SQL_READ_START.match(s) for s in statements) and not SQL_SIDE_EFFECTS.search(sql):
        return READ, "runs read-only SQL"
    return WRITE, "runs SQL that can modify the database or server"


def worst(findings):
    return max((f[0] for f in findings), key=RANK.get, default=READ)


# --------------------------------------------------------------------------- rules

def rule_rm(args):
    recursive = "r" in short_flags(args).lower() or has(args, "--recursive")
    if has(args, "--no-preserve-root") or (recursive and any(critical_path(t) for t in positionals(args))):
        return DANGER, "recursively deletes a critical path (system dir, home or wildcard)"
    if recursive:
        return WRITE, "deletes files and directories recursively (no undo)"
    return WRITE, "deletes files (no undo)"


def rule_perm(name):
    def rule(args):
        recursive = "R" in short_flags(args) or has(args, "--recursive")
        if recursive and any(critical_path(t) for t in positionals(args)[1:]):
            return DANGER, "recursively changes ownership/permissions of a critical path"
        return WRITE, WRITE_CMDS[name]
    return rule


def rule_tee(args):
    critical = [t for t in positionals(args) if CRITICAL_FILES.match(t) or DEVICE.match(t)]
    append = "a" in short_flags(args) or has(args, "--append")
    if critical and not append:
        return DANGER, "overwrites critical system file %s" % critical[0]
    targets = [t for t in positionals(args) if not HARMLESS_TARGETS.match(t)]
    if not targets:
        return READ, "passes its input through"
    return WRITE, "%s %s" % ("appends to" if append else "overwrites", " ".join(targets))


SED_WRITE_OR_EXEC = re.compile(r"(^|[;{}\n]|\d|\$)\s*[wWe](\s|$)|/[gpiImM0-9]*(w\s+\S|e\s*($|[;}]))")


def rule_sed(args):
    if re.search("i", short_flags(args)) or has(args, "--in-place"):
        return WRITE, "edits files in place"
    if any(SED_WRITE_OR_EXEC.search(a) for a in args if not a.startswith("-")):
        return WRITE, "the sed script writes files or runs commands (w/e)"
    return READ, "transforms text and prints it"


def rule_awk(args):
    if has(args, "--inplace") or flag_value(args, "i", "--include") == "inplace":
        return WRITE, "edits files in place"
    if any("system(" in a or re.search(r"\bprintf?\b[^;]*>\s*\S|\|\s*(\"|getline)", a) for a in args):
        return EXEC, "the awk program runs commands or writes files"
    if flag_value(args, "f", "--file"):
        return EXEC, "runs an awk program from a file (not checked)"
    return READ, "processes text and prints it"


def rule_curl(args):
    method = (flag_value(args, "X", "--request") or "").upper()
    if method in ("POST", "PUT", "DELETE", "PATCH") or has(
            args, "-d", "--data", "--data-raw", "--data-binary", "--data-urlencode", "-F", "--form",
            "-T", "--upload-file", "--json"):
        return WRITE, "sends data to a remote server (may change things there)"
    if has(args, "--output", "--remote-name", "--remote-name-all", "--dump-header", "--cookie-jar",
           "--trace", "--trace-ascii", "--stderr") or re.search("[oODc]", short_flags(args)):
        return WRITE, "downloads/saves to a file"
    return READ, "fetches a URL and prints it"


def rule_wget(args):
    if has(args, "--post-data", "--post-file", "--method"):
        return WRITE, "sends data to a remote server (may change things there)"
    if has(args, "--spider") or flag_value(args, "O", "--output-document") == "-":
        return READ, "fetches a URL and prints it"
    return WRITE, "downloads a file"


def rule_tar(args):
    first = args[0].lstrip("-") if args and not args[0].startswith("--") else ""
    letters = first + short_flags(args[1:])
    if "x" in letters or has(args, "--extract", "--get"):
        return WRITE, "extracts files (can overwrite)"
    if re.search("[cruA]", letters) or has(args, "--create", "--append", "--update", "--delete"):
        return WRITE, "creates/changes an archive"
    return READ, "lists an archive"


def rule_unzip(args):
    if re.search("[lvtZp]", short_flags(args)):
        return READ, "lists/tests an archive"
    return WRITE, "extracts files (can overwrite)"


def rule_compress(args):
    if re.search("[clt]", short_flags(args)) or has(args, "--stdout", "--list", "--test"):
        return READ, "prints or tests compressed data"
    return WRITE, "compresses/decompresses in place (replaces the original file)"


def rule_dd(args):
    out = next((a[3:] for a in args if a.startswith("of=")), None)
    if out is None or HARMLESS_TARGETS.match(out):
        return READ, "copies raw data to stdout"
    if DEVICE.match(out):
        return DANGER, "writes raw data to a disk device (can destroy all data on it)"
    return WRITE, "writes " + out


GIT_READ = _set("status log diff show blame grep ls-files ls-remote ls-tree rev-parse rev-list describe "
                "reflog shortlog whatchanged cat-file help version count-objects show-ref for-each-ref")


def rule_git(args):
    i = 0
    while i < len(args) and args[i].startswith("-"):
        i += 2 if args[i] in ("-C", "-c", "--git-dir", "--work-tree", "--namespace") else 1
    sub, rest = (args[i], args[i + 1:]) if i < len(args) else ("", [])
    flags, pos = short_flags(rest), positionals(rest)
    if sub == "reset" and has(rest, "--hard"):
        return DANGER, "git reset --hard discards uncommitted work"
    if sub == "clean" and ("f" in flags or has(rest, "--force")):
        return DANGER, "git clean -f permanently deletes untracked files"
    if sub == "push" and ("f" in flags or has(rest, "--force", "--force-with-lease", "--mirror", "--delete")):
        return DANGER, "force push can overwrite remote history"
    if sub in ("filter-branch", "filter-repo"):
        return DANGER, "rewrites repository history"
    if sub == "branch":
        if "D" in flags:
            return DANGER, "force-deletes a branch (unmerged work can be lost)"
        read_long = ("--list", "--contains", "--no-contains", "--all", "--remotes", "--verbose",
                     "--merged", "--no-merged", "--sort", "--format", "--show-current", "--color")
        changes = [a for a in rest if a.startswith("--") and not has([a], *read_long)]
        if set(flags) - set("alrv") or changes or (pos and not has(rest, *read_long)):
            return WRITE, "creates/renames/deletes branches"
        return READ, "lists branches"
    if sub == "tag":
        if pos and "l" not in flags and not has(rest, "--list"):
            return WRITE, "creates/deletes tags"
        return READ, "lists tags"
    if sub == "remote":
        if not pos or pos[0] in ("show", "get-url"):
            return READ, "shows remotes"
        return WRITE, "changes remotes"
    if sub == "stash":
        if pos and pos[0] in ("list", "show"):
            return READ, "shows stashes"
        return WRITE, "changes the stash"
    if sub == "reflog" and pos[:1] in (["expire"], ["delete"]):
        return DANGER, "deletes reflog entries (removes your undo history)"
    if sub == "config":
        if any(a.startswith(("--unset", "--add", "--replace", "--rename", "--remove", "--edit"))
               for a in rest) or "e" in flags:
            return WRITE, "changes git config"
        if any(a.startswith("--get") for a in rest) or has(rest, "--list", "-l") or len(pos) == 1:
            return READ, "reads git config"
        return WRITE, "changes git config"
    if sub in GIT_READ or not sub:
        return READ, "reads the repository"
    return WRITE, "changes the git repository (git %s)" % sub


def rule_subcmd(name):
    read, execs, danger, why = SUBCMDS[name]

    def rule(args):
        pos = [a.split("=")[0] for a in args] if name == "firewall-cmd" else positionals(args)
        if name in ("docker", "podman", "nerdctl") and pos[:1] == ["compose"]:
            sub = pos[1] if len(pos) > 1 else ""
            if sub in ("ps", "logs", "config", "ls", "images", "top", "version", ""):
                return READ, "reads compose state"
            if sub in ("up", "run", "exec", "start"):
                return EXEC, "starts containers (runs their code)"
            return WRITE, "changes compose services"
        sub = pos[0] if pos else ""
        if sub == "config" and pos[1:2] not in ([], ["get"], ["list"], ["ls"], ["show"], ["debug"]):
            return WRITE, "changes %s config" % name
        if any(p in danger for p in pos[:2]):
            return DANGER, "%s %s (high impact)" % (name, " ".join(pos[:2]))
        if not sub:
            return READ, "shows status/help"
        if sub in read or (name == "firewall-cmd" and all(p in read for p in pos)):
            return READ, "reads %s state" % name
        if sub in execs:
            return EXEC, "runs code (%s %s)" % (name, sub)
        return WRITE, why
    return rule


def rule_pacman(args):
    first = next((a for a in args if a.startswith("-") and not a.startswith("--")), "")
    if not re.search("[yu]", first[2:]) and (first.startswith(("-Q", "-F")) or (
            first.startswith("-S") and re.search("[silg]", first[2:]))):
        return READ, "queries packages"
    return WRITE, PKG


def rule_dpkg(args):
    if re.search("[iPra]", short_flags(args)) or has(
            args, "--install", "--remove", "--purge", "--configure", "--unpack", "--add-architecture",
            "--remove-architecture", "--set-selections", "--clear-selections", "--update-avail",
            "--merge-avail", "--clear-avail", "--forget-old-unavail"):
        return WRITE, PKG
    return READ, "queries packages"


def rule_rpm(args):
    f = short_flags(args)
    if f.startswith(("q", "V")) or has(args, "--query", "--verify"):
        return READ, "queries packages"
    return WRITE, PKG


def rule_service(args):
    pos = positionals(args)
    if not pos or "status" in pos or has(args, "--status-all"):
        return READ, "shows service status"
    return WRITE, "starts/stops/restarts a service"


def rule_ip(args):
    # ip [options] OBJECT COMMAND ... ; objects and commands may be abbreviated (ip r a ...)
    pos = positionals(args)
    if len(pos) < 2 or pos[1] in _set("show sh s list ls lst l get g monitor help"):
        return READ, "shows network settings"
    if pos[0].startswith("net") and pos[1] in ("exec", "e"):
        return EXEC, "runs a command inside a network namespace (not checked)"
    return WRITE, "changes network settings (can cut your connection)"


def rule_crontab(args):
    f = short_flags(args)
    if "r" in f:
        return DANGER, "removes your whole crontab"
    if "l" in f:
        return READ, "lists cron jobs"
    return WRITE, "replaces/edits cron jobs"


def rule_iptables(args):
    f = short_flags(args)
    if re.search("[FXP]", f) or has(args, "--flush", "--delete-chain", "--policy"):
        return DANGER, "flushes firewall rules / changes policy (can lock you out)"
    if re.search("[LS]", f) or has(args, "--list", "--list-rules"):
        return READ, "lists firewall rules"
    return WRITE, "changes the firewall (can cut your SSH access)"


def rule_find(args):
    if has(args, "-delete"):
        root = positionals(args)[:1]
        if root and critical_path(root[0]) and root[0] not in (".", "./"):
            return DANGER, "deletes every match under a critical path"
        return WRITE, "deletes every matching file"
    if has(args, "-fprint", "-fprint0", "-fprintf", "-fls"):
        return WRITE, "writes results to a file"
    return READ, "searches files"


def rule_sysctl(args):
    if re.search("[wp]", short_flags(args)) or has(args, "--system", "--write", "--load") or any(
            "=" in a for a in positionals(args)):
        return WRITE, "changes kernel parameters"
    return READ, "reads kernel parameters"


def rule_nginx(args):
    if re.search("[tTvV]", short_flags(args)):
        return READ, "tests/shows nginx config"
    return WRITE, "starts/stops/reloads nginx"


def rule_journalctl(args):
    if any(a.startswith("--vacuum") or a in ("--rotate", "--flush") for a in args):
        return WRITE, "deletes/rotates journal logs"
    return READ, "reads logs"


def rule_redis(args):
    rest = list(args)
    while rest and rest[0].startswith("-"):
        if rest.pop(0) in ("-h", "-p", "-a", "-n", "-u", "--user", "--pass") and rest:
            rest.pop(0)
    cmd = rest[0].upper() if rest else ""
    if not cmd:
        return EXEC, "opens a Redis shell (can modify data)"
    if cmd in ("FLUSHALL", "FLUSHDB", "SHUTDOWN"):
        return DANGER, "wipes Redis data / stops the server"
    if cmd in _set("GET MGET KEYS SCAN INFO PING TTL PTTL EXISTS TYPE HGET HGETALL HKEYS LRANGE LLEN "
                   "SMEMBERS SCARD ZRANGE ZCARD DBSIZE MONITOR STRLEN"):
        return READ, "reads Redis data"
    return WRITE, "changes Redis data"


RULES = {
    "rm": rule_rm, "tee": rule_tee, "sed": rule_sed, "gsed": rule_sed, "curl": rule_curl,
    "wget": rule_wget, "tar": rule_tar, "unzip": rule_unzip, "dd": rule_dd, "git": rule_git,
    "pacman": rule_pacman, "yay": rule_pacman, "paru": rule_pacman, "dpkg": rule_dpkg, "rpm": rule_rpm,
    "service": rule_service, "ip": rule_ip, "crontab": rule_crontab, "sysctl": rule_sysctl,
    "iptables": rule_iptables, "ip6tables": rule_iptables, "nginx": rule_nginx,
    "journalctl": rule_journalctl, "redis-cli": rule_redis,
    "hostname": lambda a: (WRITE, "changes the hostname") if positionals(a) else (READ, "shows the hostname"),
    "date": lambda a: (WRITE, "changes the system clock") if has(a, "-s", "--set") else (READ, "shows the date"),
    "mount": lambda a: (WRITE, "mounts filesystems") if positionals(a) or has(a, "-a", "--all") else (
        READ, "lists mounts"),
    "sort": lambda a: (WRITE, "writes the sorted output to a file") if has(a, "-o", "--output") else (
        READ, "sorts text and prints it"),
    "uniq": lambda a: (WRITE, "writes output to %s" % positionals(a)[1]) if len(positionals(a)) > 1 else (
        READ, "filters text and prints it"),
    "xxd": lambda a: (WRITE, "writes output to %s" % positionals(a)[1]) if len(positionals(a)) > 1 else (
        READ, "prints a hex dump"),
    "yq": lambda a: (WRITE, "edits files in place") if has(a, "-i", "--inplace") else (
        READ, "processes YAML and prints it"),
    "history": lambda a: (WRITE, "changes/clears shell history") if re.search("[cwdanr]", short_flags(a)) else (
        READ, "shows shell history"),
    "dmesg": lambda a: (WRITE, "clears/changes the kernel log") if re.search("[cCDEn]", short_flags(a)) or has(
        a, "--clear", "--read-clear", "--console-off", "--console-on", "--console-level") else (
        READ, "reads the kernel log"),
    "tcpdump": lambda a: (WRITE, "writes captured packets to a file") if has(a, "-w") else (
        READ, "captures and prints network packets"),
    "docker-compose": lambda a: rule_subcmd("docker")(["compose"] + a),
}
for _n in ("awk", "gawk", "mawk", "nawk"):
    RULES[_n] = rule_awk
for _n in ("chmod", "chown", "chgrp"):
    RULES[_n] = rule_perm(_n)
for _n in "gzip gunzip bzip2 bunzip2 xz unxz zstd unzstd lz4 lzma unlzma compress uncompress".split():
    RULES[_n] = rule_compress
for _n in SUBCMDS:
    RULES[_n] = rule_subcmd(_n)


# --------------------------------------------------------------------------- analysis

MAX_DEPTH = 12


def analyze(text, depth=0):
    """Analyze shell text. Return rows: (level, command, reason, depth)."""
    if depth > MAX_DEPTH:
        return [(UNKNOWN, text[:60], "nested too deep to analyze", depth)]
    rows = []
    for cmd in split_commands(tokenize(text)):
        rows.extend(classify(cmd, depth))
    return rows


def classify(cmd, depth):
    nested = []
    for sub in cmd["subs"]:
        nested.extend(analyze(sub, depth + 1))
    findings = [f for f in (redirect_finding(op, t) for op, t in cmd["redirs"]) if f]
    words = list(cmd["words"])
    while words and (words[0] in KEYWORDS or ASSIGN.match(words[0])):
        words.pop(0)
    if words and words[0] in LOOP_HEADERS:
        words = []
    if words and words[0] == "function":
        words = words[words.index("{") + 1:] if "{" in words else []
    if words:
        findings.extend(inspect(words, cmd, depth, nested))
    elif any(ASSIGN.match(w) for w in cmd["words"]):
        findings.append((READ, "sets a shell variable (not persistent)"))
    if not findings:
        return nested
    shown = " ".join(_quote(w) for w in cmd["words"])
    shown += "".join(" %s %s" % (op, t) for op, t in cmd["redirs"])
    shown += " <<heredoc" * len(cmd["heredocs"])
    if cmd["piped_from"]:
        shown = "| " + shown
    level = worst(findings)
    reasons = [why for lvl, why in findings if lvl == level or lvl != READ]
    return [(level, shown.strip(), "; ".join(dict.fromkeys(reasons)), depth)] + nested


def _quote(w):
    if w.startswith(("$(", "`", "<(", ">(")) or not re.search(r"[\s;&|<>()'\"]", w) and w:
        return w
    return "'%s'" % w


def redirect_finding(op, target):
    if op in ("<", "<<<", "<&") or HARMLESS_TARGETS.match(target):
        return None
    if DEVICE.match(target):
        return DANGER, "writes raw data to disk device %s" % target
    if CRITICAL_FILES.match(target):
        if op in (">>", "&>>"):
            return WRITE, "appends to critical system file %s" % target
        return DANGER, "overwrites critical system file %s" % target
    if op in (">>", "&>>"):
        return WRITE, "appends to %s" % target
    return WRITE, "overwrites %s" % target


def inspect(words, cmd, depth, nested, root=False):
    """Classify one command (keywords/assignments already stripped). May append nested rows."""
    findings = _inspect(words, cmd, depth, nested)
    if root:
        findings = [(lvl, why + " (as root)" if RANK[lvl] >= RANK[EXEC] else why) for lvl, why in findings]
    return findings


def _child_level(nested, depth, floor=READ):
    child = [r[0] for r in nested if r[3] == depth + 1]
    return max(child + [floor], key=RANK.get)


def _inspect(words, cmd, depth, nested):
    raw, args = words[0], words[1:]
    if raw.startswith(("$(", "`")):
        if re.search(r"\b(curl|wget)\b", raw):
            return [(DANGER, "runs code downloaded from the internet")]
        return [(EXEC, "runs the output of a command substitution as a command")]
    if "$" in raw:
        return [(UNKNOWN, "command name comes from a variable; can't tell what it runs")]
    name = os.path.basename(raw)

    if name in WRAPPERS:
        return _inspect_wrapper(name, args, cmd, depth, nested)
    if len(args) == 1 and args[0] in ("--version", "--help", "-V"):
        return [(READ, "shows version/help")]
    if name == "su":
        code = opt(args, "-c", "--command")
        if code:
            nested.extend(analyze(code, depth + 1))
            return [(_child_level(nested, depth), "runs the command(s) below as another user")]
        return [(EXEC, "opens a shell as another user (root by default)")]
    if name == "trap" and positionals(args)[:1] and positionals(args)[0] != "-":
        nested.extend(analyze(positionals(args)[0], depth + 1))
        return [(_child_level(nested, depth), "runs the code below when the shell exits / gets a signal")]
    if name == "eval":
        nested.extend(analyze(" ".join(args), depth + 1))
        return [(_child_level(nested, depth, EXEC), "evaluates the code below")]
    if name in ("source", "."):
        target = (args or ["?"])[0]
        if target.startswith("<("):
            return [(DANGER, _downloaded(target, "runs code produced by a command"))]
        return [(EXEC, "runs script %s in the current shell (contents not checked)" % target)]
    if name == "ssh":
        return _inspect_ssh(args, cmd, depth, nested)
    if name in SHELLS:
        return _inspect_shell(name, args, cmd, depth, nested)
    if name in INTERPRETERS or re.match(r"^(python|pypy|perl|ruby|php|node)[\d.]*$", name):
        return _inspect_interpreter(name, args, cmd)
    if name in DB_CLIENTS:
        return _inspect_db(name, args, cmd)
    if name == "find":
        found = [rule_find(args)]
        for flag in ("-exec", "-execdir", "-ok", "-okdir"):
            if flag in args:
                inner = args[args.index(flag) + 1:]
                end = next((k for k, a in enumerate(inner) if a in (";", "+")), len(inner))
                if inner[:end]:
                    sub = inspect(inner[:end], dict(cmd, heredocs=[], redirs=[]), depth, nested)
                    found += [(lvl, why + " (for each found file)") for lvl, why in sub]
        return found
    if name in RULES:
        return [RULES[name](args)]
    if name.startswith("mkfs"):
        return [(DANGER, "formats a filesystem (erases everything on it)")]
    if name in DANGER_CMDS:
        return [(DANGER, DANGER_CMDS[name])]
    if name == "init" and positionals(args)[:1] in (["0"], ["6"]):
        return [(DANGER, "halts/reboots the machine")]
    if name in WRITE_CMDS:
        return [(WRITE, WRITE_CMDS[name])]
    if name in READ_CMDS:
        return [(READ, "only reads / prints information")]
    if name in BUILD_TOOLS:
        return [(EXEC, "runs a build/automation tool (what it does depends on its config)")]
    if "/" in raw:
        return [(EXEC, "runs local program/script %s (contents not checked)" % raw)]
    return [(UNKNOWN, "not in shellsight's list; check `man %s` before running" % name)]


def _inspect_wrapper(name, args, cmd, depth, nested):
    if name == "command" and args[:1] in (["-v"], ["-V"]):
        return [(READ, "looks up a command")]
    takes_value, skip = WRAPPERS[name]
    takes_value, rest = set(takes_value.split()), list(args)
    while rest and rest[0].startswith("-"):
        a = rest.pop(0)
        if a == "--":
            break
        if a in takes_value and rest:
            rest.pop(0)
    while name == "env" and rest and ASSIGN.match(rest[0]):
        rest.pop(0)
    rest = rest[skip:]
    root = name in ROOT_WRAPPERS
    if not rest:
        if root and "l" in short_flags(args):
            return [(READ, "lists your sudo rights")]
        if root and re.search("[is]", short_flags(args)):
            return [(EXEC, "opens a root shell")]
        if name == "chroot":
            return [(EXEC, "opens a shell inside the chroot")]
        return [(READ, "%s with no command" % name)]
    if name == "watch":  # watch joins its args and runs them through sh -c
        nested.extend(analyze(" ".join(rest), depth + 1))
        return [(_child_level(nested, depth), "runs the command below repeatedly")]
    found = inspect(rest, cmd, depth, nested, root)
    if name == "xargs":
        found = [(lvl, why + " (for each input item)") for lvl, why in found]
    return found


def _downloaded(source, default):
    if re.search(r"\b(curl|wget|fetch|aria2c)\b", source or ""):
        return "executes code downloaded from the internet"
    return default


def _from_stdin(cmd):
    src = cmd["piped_from"]
    return _downloaded(src, "executes code piped from %s" % src)


def _shell_positionals(args):
    """Positionals of sh/bash, skipping values of -o/+o/-O/+O (bash -euo pipefail -c ...)."""
    pos, k = [], 0
    while k < len(args):
        a = args[k]
        if a[:1] in "-+" and len(a) > 1 and not a.startswith("--"):
            k += 2 if a[-1] in "oO" else 1
            continue
        if not a.startswith("--"):
            pos.append(a)
        k += 1
    return pos


def _inspect_shell(name, args, cmd, depth, nested):
    pos = _shell_positionals(args)
    if "c" in short_flags(args) and pos:
        nested.extend(analyze(pos[0], depth + 1))
        return [(_child_level(nested, depth), "runs the command(s) below")]
    here = [t for op, t in cmd["redirs"] if op == "<<<"] + cmd["heredocs"]
    if here:
        for body in here:
            nested.extend(analyze(body, depth + 1))
        return [(_child_level(nested, depth), "runs the heredoc script below")]
    if pos and pos[0].startswith("<("):
        return [(DANGER, _downloaded(pos[0], "runs code produced by a command"))]
    if pos and pos[0] != "-":
        return [(EXEC, "runs script %s (contents not checked; run shellsight on it)" % pos[0])]
    if cmd["piped_from"]:
        return [(DANGER, _from_stdin(cmd))]
    if any(op == "<" for op, _ in cmd["redirs"]):
        return [(EXEC, "runs a script from a file (contents not checked)")]
    return [(EXEC, "starts a new shell")]


def _inspect_interpreter(name, args, cmd):
    inline = any(a in ("-c", "-e", "-r", "--eval") or
                 (a.startswith("-") and not a.startswith("--") and a[-1] in "ce") for a in args)
    if inline:
        if name.startswith("perl") and "i" in short_flags(args):
            return [(WRITE, "edits files in place with Perl")]
        return [(EXEC, "runs inline %s code (not analyzed)" % name)]
    mod = opt(args, "-m")
    if mod is not None:
        if mod == "pip":
            return [rule_subcmd("pip")(args[args.index("-m") + 2:])]
        if mod in ("json.tool", "site", "this", "timeit"):
            return [(READ, "runs Python module %s" % mod)]
        return [(EXEC, "runs Python module %s" % mod)]
    pos = positionals(args)
    if pos and pos[0].startswith("<("):
        return [(DANGER, _downloaded(pos[0], "runs code produced by a command"))]
    if pos and pos[0] != "-":
        return [(EXEC, "runs %s script %s (contents not checked)" % (name, pos[0]))]
    if cmd["piped_from"]:
        return [(DANGER, _from_stdin(cmd))]
    if cmd["heredocs"]:
        return [(EXEC, "runs inline %s code from a heredoc (not analyzed)" % name)]
    return [(EXEC, "starts an interactive %s session" % name)]


def _inspect_db(name, args, cmd):
    sql = None
    if name in ("mysql", "mariadb"):
        # exact -e/--execute or attached -e"SQL"; not a cluster scan, since -pSecret could contain an "e"
        sql = opt(args, "-e", "--execute")
        if sql is None:
            sql = next((a[2:] for a in args if a.startswith("-e") and len(a) > 2), None)
    elif name == "psql":
        sql = flag_value(args, "c", "--command")
    elif len(positionals(args)) >= 2:
        sql = " ".join(positionals(args)[1:])
    here = [t for op, t in cmd["redirs"] if op == "<<<"] + cmd["heredocs"]
    if sql is None and here:
        sql = "\n".join(here)
    if sql is not None:
        return [sql_level(sql)]
    if any(op == "<" for op, _ in cmd["redirs"]) or (name == "psql" and opt(args, "-f", "--file")):
        return [(EXEC, "runs SQL from a file (not checked)")]
    if cmd["piped_from"]:
        return [(EXEC, "runs SQL piped from %s (not checked)" % cmd["piped_from"])]
    return [(EXEC, "opens a database shell (can modify data)")]


def _inspect_ssh(args, cmd, depth, nested):
    takes_value = _set("-b -c -D -E -e -F -I -i -J -L -l -m -O -o -p -Q -R -S -W -w")
    rest = list(args)
    while rest and rest[0].startswith("-"):
        if rest.pop(0) in takes_value and rest:
            rest.pop(0)
    if len(rest) > 1:
        nested.extend(analyze(" ".join(rest[1:]), depth + 1))
        return [(_child_level(nested, depth), "runs the command(s) below on remote host %s" % rest[0])]
    if cmd["heredocs"]:
        for body in cmd["heredocs"]:
            nested.extend(analyze(body, depth + 1))
        return [(_child_level(nested, depth), "runs the heredoc below on a remote host")]
    if cmd["piped_from"]:
        return [(DANGER, "sends piped input to a remote shell")]
    return [(EXEC, "opens a remote shell")]


# --------------------------------------------------------------------------- output

COLORS = {READ: "32", UNKNOWN: "35", EXEC: "36", WRITE: "33", DANGER: "1;31"}
VERDICTS = {
    READ: "Read-only: these commands only read or print information.",
    UNKNOWN: "Some commands are unknown to shellsight. Check what they do before running.",
    EXEC: "Runs programs or scripts whose contents shellsight can't see. Check what they do.",
    WRITE: "Changes files or system state. Make sure you understand every WRITE line.",
    DANGER: "Contains destructive or high-risk commands. Do NOT run this blindly.",
}


def render(rows, color):
    if not rows:
        return "No commands found."

    def paint(code, s):
        return "\033[%sm%s\033[0m" % (code, s) if color else s

    out = []
    for level, shown, reason, depth in rows:
        pad = "    " * depth
        out.append("%s%s %s" % (pad, paint(COLORS[level], "%-7s" % level), shown))
        out.append("%s        %s" % (pad, paint("2", "-> " + reason)))
    top = worst(rows)
    counts = ["%d %s" % (sum(r[0] == lvl for r in rows), lvl) for lvl in sorted(RANK, key=RANK.get, reverse=True)]
    out += ["", "Summary: " + ", ".join(counts), paint(COLORS[top], "Verdict: %s - %s" % (top, VERDICTS[top]))]
    return "\n".join(out)


def exit_code(rows):
    """0 read-only, 1 unknown/exec, 2 write, 3 danger."""
    return {READ: 0, UNKNOWN: 1, EXEC: 1, WRITE: 2, DANGER: 3}[worst(rows)]


def main(argv=None):
    p = argparse.ArgumentParser(
        prog="shellsight",
        description="Check what a shell snippet reads, writes or executes before you run it. "
                    "Nothing is executed or sent anywhere.",
        epilog="Exit codes: 0 read-only, 1 unknown/exec, 2 write, 3 danger.")
    p.add_argument("files", nargs="*", help="shell scripts to analyze (default: stdin / interactive)")
    p.add_argument("-c", dest="code", help="analyze this command string")
    p.add_argument("--no-color", action="store_true", help="disable colors (also: NO_COLOR env var)")
    p.add_argument("--version", action="version", version="shellsight " + __version__)
    a = p.parse_args(argv)
    for stream in (sys.stdin, sys.stdout):  # pasted emoji / bad bytes must never crash the tool
        if hasattr(stream, "reconfigure"):
            stream.reconfigure(errors="replace")
    color = (sys.stdout.isatty() and not a.no_color and "NO_COLOR" not in os.environ
             and os.environ.get("TERM") != "dumb")

    if a.code is not None:
        texts = [a.code]
    elif a.files:
        texts = []
        for f in a.files:
            try:
                with open(f, encoding="utf-8", errors="replace") as fh:
                    texts.append(fh.read())
            except OSError as e:
                p.error("cannot read %s: %s" % (f, e.strerror))
    elif not sys.stdin.isatty():
        texts = [sys.stdin.read()]
    else:
        return interactive(color)
    rows = [r for t in texts for r in analyze(t)]
    print(render(rows, color))
    return exit_code(rows)


def interactive(color):
    eof = "Ctrl-Z then Enter" if os.name == "nt" else "Ctrl-D"
    print("shellsight %s - paste a shell block, then press %s on an empty line. Ctrl-C quits.\n"
          "Nothing is executed or sent anywhere." % (__version__, eof))
    try:
        while True:
            print("\n--- paste below ---")
            text = sys.stdin.read()
            if not text.strip():
                return 0
            print()
            print(render(analyze(text), color))
    except KeyboardInterrupt:
        print()
        return 0


if __name__ == "__main__":
    sys.exit(main())
