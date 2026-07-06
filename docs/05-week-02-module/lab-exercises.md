# Week 2 — Lab Exercises: Linux Fundamentals I

Work at your own keyboard on a lab **Linux** box (Ubuntu Ecom `172.20.242.30` or Ubuntu Wks). Nothing
here is graded yet, and nothing here hardens the box — you're learning to *operate and observe*. If a
command is denied, you probably need `sudo` in front of it (ask the facilitator before guessing).

**Prereqs:** SSH/console access to a lab Linux box; a shell prompt.

---

## Exercise 1 — Move around the filesystem
```bash
pwd                     # where am I?
cd /                    # go to the root
ls -l                   # what's here? note the columns
cd /etc                 # config lives here
ls | less               # page through (q to quit)
cat /etc/os-release      # which distro/version?
find /var/log -name "*.log" 2>/dev/null | head   # find log files
```
Note the key directories: `/etc` (config), `/home` (user files), `/var/log` (logs), `/tmp` (scratch),
`/root` (root's home).

## Exercise 2 — Read the user database
```bash
cat /etc/passwd          # one line per account
```
Each line: `name:x:UID:GID:comment:home:shell`. Answer:
- Which accounts have a real login shell (`/bin/bash`) vs. `nologin`/`false`?
- What is the UID of `root`? (It's `0` — remember that; UID 0 = full power.)

```bash
# Just the humans (UID >= 1000), roughly:
awk -F: '$3>=1000 && $3<65534 {print $1, $3}' /etc/passwd
```

## Exercise 3 — Create, inspect, remove a user
```bash
sudo useradd -m -s /bin/bash practice   # create with a home dir + bash
grep practice /etc/passwd                # confirm it exists
id practice                              # its UID/GID/groups
sudo passwd practice                     # set a password (type one twice)
sudo userdel -r practice                 # remove it and its home
grep practice /etc/passwd || echo "gone" # confirm removed
```
> This is the primitive behind the competition credential sweep — you must be able to spot and remove
> an account you didn't create.

## Exercise 4 — Permissions and ownership
```bash
cd /tmp
echo "secret" > myfile
ls -l myfile             # read the rwx columns
chmod 600 myfile         # owner read/write only
ls -l myfile             # now -rw-------
chmod u+x,g+r myfile     # add owner-execute, group-read
ls -l myfile
sudo chown root myfile   # change owner to root
ls -l myfile
rm -f myfile 2>/dev/null || sudo rm -f myfile
```
Read `rwx` as user / group / other. `chmod 640` = owner rw, group r, other none. Practice until you can
*predict* the `ls -l` output before you run it.

## Exercise 5 — Processes
```bash
ps aux | head            # all running processes
ps aux | grep ssh        # is sshd running?
top                      # live view — press q to quit
```
For any process line, identify: the **user** running it, the **PID**, and the **command**.

## Exercise 6 — Network listeners (what's open)
```bash
ss -tlnp                 # TCP listening sockets + owning process (sudo for names)
sudo ss -tlnp
```
For each listener, answer: **what port**, and **which program** is listening? On Ubuntu Ecom you should
see a web server. A listener you can't explain is exactly what you hunt for in competition.

## Done?
You've hit the objectives if you can: navigate and find files, read `/etc/passwd`, create/inspect/
remove a user, set permissions and predict `ls -l`, and list processes + listeners. Repeat Exercises 3,
4, and 6 solo for [`homework.md`](homework.md).
