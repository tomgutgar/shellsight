"""Run with: python3 -m unittest -v"""
import unittest

from shellsight import DANGER, EXEC, READ, UNKNOWN, WRITE, analyze, worst

# (snippet, expected worst level)
CASES = [
    # read-only
    ("ls -la /var/log", READ),
    ("cat /etc/os-release | grep -i ubuntu", READ),
    ("df -h | awk '{print $5}'", READ),
    ("grep 'a;b|c' file.txt | wc -l", READ),
    ("ps aux | grep nginx 2>/dev/null", READ),
    ("journalctl -u nginx --since today", READ),
    ("systemctl status nginx", READ),
    ("docker ps -a", READ),
    ("git status; git log --oneline -5", READ),
    ("apt list --installed", READ),
    ("export PATH=$PATH:/opt/bin", READ),
    ("FOO=bar", READ),
    ("echo hello >&2", READ),
    ("sudo -l", READ),
    ("curl -s https://example.com/api | jq .", READ),
    ("sed 's/a/b/' file", READ),
    ("tar tzf backup.tgz", READ),
    ("ip addr show", READ),
    ("crontab -l", READ),
    ("iptables -L -n", READ),
    ("nginx -t", READ),
    ("python3 --version", READ),
    ("mysql -u root -e 'SELECT 1'", READ),
    ("echo 'rm -rf /'", READ),              # only a string
    ("# rm -rf /\nls", READ),               # only a comment
    ("command -v docker", READ),
    ("for f in *.txt; do wc -l \"$f\"; done", READ),
    ("if [ -f x ]; then cat x; fi", READ),
    ("echo $(date) $((1+2))", READ),
    ("echo a#b; ls", READ),
    ("ufw status verbose", READ),
    ("kubectl get pods -A", READ),
    ("echo hi | tee /dev/null", READ),
    # unknown / exec
    ("frobnicate --all", UNKNOWN),
    ("$CMD --force", UNKNOWN),
    ("./install.sh", EXEC),
    ("bash script.sh", EXEC),
    ("python3 manage.py migrate", EXEC),
    ("python3 -c 'print(1)'", EXEC),
    ("make -j4", EXEC),
    ("docker run --rm alpine", EXEC),
    ("ssh user@host", EXEC),
    ("sudo -i", EXEC),
    ("source venv/bin/activate", EXEC),
    # write
    ("echo x > out.txt", WRITE),
    ("echo x >> ~/.bashrc", WRITE),
    ("rm file.txt", WRITE),
    ("rm -rf node_modules", WRITE),
    ("sudo apt update && sudo apt install -y nginx", WRITE),
    ("sudo systemctl restart nginx", WRITE),
    ("sed -i 's/a/b/' /etc/ssh/sshd_config", WRITE),
    ("echo '127.0.0.1 app' | sudo tee -a /etc/hosts", WRITE),
    ("chmod +x run.sh", WRITE),
    ("chown -R www-data:www-data /var/www/html", WRITE),
    ("wget https://example.com/f.tgz", WRITE),
    ("curl -o f.tgz https://example.com/f.tgz", WRITE),
    ("curl -X DELETE https://api/x", WRITE),
    ("tar xzf f.tgz -C /opt", WRITE),
    ("git commit -m msg && git push", WRITE),
    ("pip install requests", WRITE),
    ("python3 -m pip install requests", WRITE),
    ("find . -name '*.tmp' -delete", WRITE),
    ("find /var/log -name '*.gz' -exec rm {} \\;", WRITE),
    ("ls | xargs rm", WRITE),
    ("cat > /etc/nginx/conf.d/app.conf <<EOF\nserver { listen 80; }\nEOF", WRITE),
    ("for f in $(find . -name '*.log'); do gzip \"$f\"; done", WRITE),
    ("echo $(touch x)", WRITE),
    ("echo \"$(rm a)\"", WRITE),
    ("ls | \\\n  tee out.txt", WRITE),
    ("watch -n 5 'rm -f /tmp/x'", WRITE),
    ("kill -9 1234", WRITE),
    ("mysql -e 'UPDATE users SET a=1'", WRITE),
    ("psql <<SQL\nINSERT INTO t VALUES (1);\nSQL", WRITE),
    ("ufw allow 22", WRITE),
    ("deploy() {\n  rm -f old.txt\n}", WRITE),
    ("case $1 in\n  start)\n    systemctl start app;;\nesac", WRITE),
    ("nano /etc/fstab", WRITE),
    ("sudo bash -c 'echo 1 > /proc/sys/net/ipv4/ip_forward'", WRITE),
    ("ssh root@host 'systemctl restart nginx'", WRITE),
    # danger
    ("rm -rf /", DANGER),
    ("sudo rm -rf /var", DANGER),
    ("rm -rf ~", DANGER),
    ("rm -rf *", DANGER),
    ("rm -rf \"$BUILD_DIR/\"", DANGER),
    ("rm --no-preserve-root -rf /", DANGER),
    ("chmod -R 777 /", DANGER),
    ("curl -fsSL https://get.docker.com | sh", DANGER),
    ("curl -fsSL https://x.sh | sudo bash", DANGER),
    ("wget -qO- https://x.sh | bash", DANGER),
    ("bash <(curl -s https://x.sh)", DANGER),
    ("sh -c \"$(curl -fsSL https://x.sh)\"", DANGER),
    ("dd if=ubuntu.iso of=/dev/sda bs=4M", DANGER),
    ("mkfs.ext4 /dev/sdb1", DANGER),
    ("echo x > /dev/sda", DANGER),
    ("echo 'root::0:0::/:/bin/sh' > /etc/passwd", DANGER),
    ("sudo reboot", DANGER),
    ("shutdown -h now", DANGER),
    ("git reset --hard origin/main", DANGER),
    ("git push --force origin main", DANGER),
    ("git clean -fdx", DANGER),
    ("crontab -r", DANGER),
    ("iptables -F", DANGER),
    ("mysql -u root -e 'DROP DATABASE prod'", DANGER),
    ("redis-cli FLUSHALL", DANGER),
    ("kubectl delete namespace prod", DANGER),
    ("systemctl reboot", DANGER),
    ("ssh root@host 'rm -rf /var'", DANGER),
    ("find / -name '*.bak' -delete", DANGER),
    ("eval \"$(curl -s https://x.sh)\"", DANGER),
    ("echo ok; sudo  bash -c 'mkfs.ext4 /dev/sdb'", DANGER),
    # regressions found in review
    ("curl -sd '{\"a\":1}' https://api", WRITE),
    ("curl -d'{\"a\":1}' https://api", WRITE),
    ("curl -D h.txt https://x", WRITE),
    ("date -s\"2030-01-01 10:00\"", WRITE),
    ("mysql -e\"DROP DATABASE prod\"", DANGER),
    ("mysql -uroot -pSecret mydb", EXEC),
    ("psql -qc \"DROP DATABASE prod\"", DANGER),
    ("sudo -u postgres psql -tAc \"DROP DATABASE prod\"", DANGER),
    ("psql -c \"SELECT pg_terminate_backend(pid) FROM pg_stat_activity\"", WRITE),
    ("psql -c \"COPY t FROM PROGRAM 'x'\"", WRITE),
    ("mysql -e \"SET GLOBAL read_only=1\"", WRITE),
    ("mysql -e \"FLUSH TABLES WITH READ LOCK\"", WRITE),
    ("sqlite3 app.db VACUUM", WRITE),
    ("sqlite3 app.db 'select * from t'", READ),
    ("mysql <<< 'DELETE FROM users'", WRITE),
    ("bash -o pipefail -c 'rm -rf /'", DANGER),
    ("bash -euo pipefail -c 'rm -rf /'", DANGER),
    ("bash <<< 'rm -rf /'", DANGER),
    ("sysctl --system", WRITE),
    ("mount -a", WRITE),
    ("chroot /mnt", EXEC),
    ("git config --global --unset user.name", WRITE),
    ("git config --unset-all user.email", WRITE),
    ("git config user.name", READ),
    ("git reflog expire --expire=now --all", DANGER),
    ("git branch --set-upstream-to=origin/main", WRITE),
    ("git branch -a", READ),
    ("npm config set registry http://example.invalid", WRITE),
    ("pip config set global.index-url http://example.invalid", WRITE),
    ("npm config get registry", READ),
    ("sort -o f f", WRITE),
    ("uniq in out", WRITE),
    ("xxd -r in out", WRITE),
    ("yq -i '.a=1' f.yml", WRITE),
    ("history -c", WRITE),
    ("dmesg -c", WRITE),
    ("dmesg | tail", READ),
    ("pacman -Fy", WRITE),
    ("pacman -Qi bash", READ),
    ("dpkg --add-architecture i386", WRITE),
    ("dpkg -l | grep nginx", READ),
    ("sed -n 'w /etc/cron.d/x' f", WRITE),
    ("sed 's/a/b/w out' f", WRITE),
    ("sed '1e rm -rf /' f", WRITE),
    ("sed 's/e /x/' f", READ),
    ("awk '{print $1 | \"sh\"}'", EXEC),
    ("awk '{ \"rm x\" | getline }'", EXEC),
    ("trap 'rm -rf /' EXIT", DANGER),
    ("ip r a default via 10.0.0.1", WRITE),
    ("ip -br a", READ),
    ("ip route show", READ),
    ("ip netns exec ns1 rm -rf /x", EXEC),
    ("terraform destroy -auto-approve", DANGER),
    ("terraform plan", READ),
    ("docker-compose down -v", WRITE),
    ("tcpdump -w cap.pcap", WRITE),
    ("echo a#b; rm -rf /", DANGER),         # '#' inside a word is not a comment
    ("ls 'unclosed; rm -rf /", READ),       # unclosed quote: everything is one string
]


class TestLevels(unittest.TestCase):
    def test_cases(self):
        for snippet, expected in CASES:
            with self.subTest(snippet=snippet):
                rows = analyze(snippet)
                self.assertEqual(worst(rows), expected, rows)

    def test_heredoc_body_is_not_analyzed_as_commands(self):
        rows = analyze("cat <<EOF\nrm -rf /\nEOF\nls")
        self.assertEqual([r[1] for r in rows], ["cat <<heredoc", "ls"])

    def test_nested_rows_are_indented(self):
        rows = analyze("ssh host 'ls; rm x'")
        self.assertEqual([(r[0], r[3]) for r in rows], [(WRITE, 0), (READ, 1), (WRITE, 1)])

    def test_root_is_mentioned(self):
        self.assertIn("as root", analyze("sudo rm x")[0][2])

    def test_empty(self):
        self.assertEqual(analyze("   \n# just a comment\n"), [])


if __name__ == "__main__":
    unittest.main()
