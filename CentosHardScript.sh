############# CentOS 6 Hardening Script ###########

####Set-Core-Permissions#####

#Secure the Terminal by removing all non-essential consoles
mv /etc/securetty /etc/securetty.orig
echo "tty1" > /etc/securetty 

#Secure root directory and passwd/shadow files

chmod 700 /root

cd /etc
chown root:root passwd shadow group gshadow
chmod 644 passwd group
chmod 400 shadow gshadow

#Set sticky bit on these so only owner can mv/delete

chmod -s /bin/ping6
chmod -s /usr/libexec/openssh/ssh-keysign
chmod -s /usr/sbin/usernetctl
chmod -s /usr/bin/chsh
chmod -s /usr/bin/chfn

#Modify userhelper so PAM settings can't be modified

chgrp wheel /usr/sbin/userhelper
chmod 4710 /usr/sbin/userhelper

#Use SHA512 for password hashing

authconfig --passalgo=sha512 --update

#Change the default mask for all created daemons
echo umask 027 >> /etc/sysconfig/init

#Add profile timeouts to reap idle users
echo "Idle users will be removed after 15 minutes" >> /etc/profile.d/os-security.sh
echo "readonly TMOUT=900" >> /etc/profile.d/os-security.sh
echo "readonly HISTFILE" >> /etc/profile.d/os-security.sh 
chmod +x /etc/profile.d/os-security.sh
chown root:root /etc/profile.d/os-security.sh
chmod 700 /etc/profile.d/os-security.sh

####Login-Security####

#Modify the PAM config
mv /etc/pam.d/system-auth /etc/pam.d/system-auth.orig
touch /var/log/tallylog

echo "#%PAM-1.0
# This file is auto-generated.
# User changes will be destroyed the next time authconfig is run.
auth        required      pam_env.so
auth        sufficient    pam_unix.so nullok try_first_pass
auth        requisite     pam_succeed_if.so uid >= 500 quiet
auth        required      pam_deny.so
auth        required      pam_tally2.so deny=3 onerr=fail unlock_time=60
auth        required      pam_wheel.so use_uid

account     required      pam_unix.so
account     sufficient    pam_succeed_if.so uid < 500 quiet
account     required      pam_permit.so
account     required      pam_tally2.so per_user

password    requisite     pam_cracklib.so try_first_pass retry=3 minlen=9 lcredit=-2 ucredit=-2 dcredit=-2 ocredit=-2
password    sufficient    pam_unix.so sha512 shadow nullok try_first_pass use_authtok remember=10
password    required      pam_deny.so

session     optional      pam_keyinit.so revoke
session     required      pam_limits.so
session     [success=1 default=ignore] pam_succeed_if.so service in crond quiet use_uid
session     required      pam_unix.so " > /etc/pam.d/system-auth

chown root:root /etc/pam.d/system-auth
chmod 600 /etc/pam.d/system-auth

#Modify SSH config

mv /etc/ssh/sshd_config /etc/ssh/sshd_config.orig

echo "# This is the sshd server system-wide configuration file.  See
# sshd_config(5) for more information.

# This sshd was compiled with PATH=/usr/local/bin:/bin:/usr/bin

# The strategy used for options in the default sshd_config shipped with
# OpenSSH is to specify options with their default value where
# possible, but leave them commented.  Uncommented options change a
# default value.

Port 2200
#AddressFamily any
#ListenAddress 0.0.0.0
#ListenAddress ::

# Disable legacy (protocol version 1) support in the server for new
# installations. In future the default will change to require explicit
# activation of protocol 1
Protocol 2


# Lifetime and size of ephemeral version 1 server key
ServerKeyBits 2048
Ciphers aes128-ctr,aes192-ctr,aes256-ctr

# Logging
SyslogFacility AUTHPRIV

# Authentication:
LoginGraceTime 2m
StrictModes yes
MaxAuthTries 5
MaxSessions 1
UsePAM yes
PermitRootLogin no
AllowGroups ssh
HostbasedAuthentication no
UsePrivilegeSeparation yes
AllowTcpForwarding no
LogLevel INFO
IgnoreRhosts yes
PermitUserEnvironment no

#SSH Session Keep-Alive
TCPKeepAlive Yes
ClientAliveInterval 300
ClientAliveCountMax 0

# To disable tunneled clear text passwords, change to no here!
PasswordAuthentication yes
PermitEmptyPasswords no

# Change to no to disable s/key passwords
ChallengeResponseAuthentication no

# Accept locale-related environment variables
AcceptEnv LANG LC_CTYPE LC_NUMERIC LC_TIME LC_COLLATE LC_MONETARY LC_MESSAGES
AcceptEnv LC_PAPER LC_NAME LC_ADDRESS LC_TELEPHONE LC_MEASUREMENT
AcceptEnv LC_IDENTIFICATION LC_ALL LANGUAGE
AcceptEnv XMODIFIERS

#X11
X11Forwarding no

# no default banner path
#Banner none

# override default of no subsystems
Subsystem	sftp	/usr/libexec/openssh/sftp-server" > /etc/ssh/sshd_config

chown root:root /etc/ssh/sshd_config
chmod 600 /etc/ssh/sshd_config

#####Disable-Kernel-Drivers#####

#IPV6
echo Òoptions ipv6 disable=1Ó > /etc/modprobe.d/ipv6.conf
echo ÒNETWORKING_IPV6=noÓ >> /etc/sysconfig/network
echo ÒIPV6INIT=noÓ >> /etc/sysconfig/network
#DCCP
echo "install dccp /bin/true" >> /etc/modprobe.d/CIS.conf
#SCTP
echo "install sctp /bin/true" >> /etc/modprobe.d/CIS.conf
#RDS
echo "install rds /bin/true" >> /etc/modprobe.d/CIS.conf
#TIPC
echo "install tipc /bin/true" >> /etc/modprobe.d/CIS.conf

#####Set-Kernel-Parameters#####
mv /etc/sysctl.conf /etc/sysctl.conf.orig

echo "##Kernel-Options##
#Turn off System Request debugging functionality of the kernel 
kernel.sysrq = 0   
#Append core dumps with the PID 
kernel.core_uses_pid = 1   
#Buffer overflow protection
kernel.exec-shield=1
#Enable address space layout randomization
kernel.randomize_va_space=1
#Increase system file descriptor limit     
fs.file-max = 65535   
#Allow for more PIDs  
kernel.pid_max = 65536

##IPv4-networking start##
#Increase system IP port limits 
net.ipv4.ip_local_port_range = 2000 65000
#Prevent against the common 'syn flood attack'
net.ipv4.tcp_max_syn_backlog = 1280
net.ipv4.tcp_syncookies = 1
net.ipv4.tcp_synack_retries = 2
#Enable bad error message Protection
net.ipv4.icmp_ignore_bogus_error_responses = 1
#Disable IP forwarding
net.ipv4.ip_forward = 0
#Do not accept Source Routed Packets
net.ipv4.conf.all.accept_source_route = 0
net.ipv4.conf.default.accept_source_route = 0
#Log spoofed, source routed and redirect packets.
net.ipv4.conf.all.log_martians = 1
net.ipv4.conf.default.log_martians = 1
#Do not accept Redirect Packets
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.default.accept_redirects = 0
net.ipv4.conf.all.send_redirects = 0 
net.ipv4.conf.default.send_redirects = 0
net.ipv4.conf.all.secure_redirects = 0
net.ipv4.conf.default.secure_redirects = 0
#Ignore all ICMP echo and timestamp requests sent to it via broadcast/multicast 
net.ipv4.icmp_echo_ignore_broadcasts = 1
#Enable source validation by reversed path, as specified in RFC1812
net.ipv4.conf.all.rp_filter = 1
net.ipv4.conf.default.rp_filter = 1   

##IPv6-networking-start##
#Do not accept redirects
net.ipv6.conf.all.accept_redirect = 0
net.ipv6.conf.default.accept_redirect = 0
#Do not send Router Solicitations
net.ipv6.conf.default.router_solicitations = 0
#Do not accept router advertisements
net.ipv6.conf.all.accept_ra = 0
net.ipv6.conf.default.accept_ra = 0
#Do not accept router preference packet?
net.ipv6.conf.default.accept_ra_rtr_pref = 0   
#Do not grab prefix information in router advertisement
net.ipv6.conf.default.accept_ra_pinfo = 0   
#Do not accept hop limit settings from a router advertisement 
net.ipv6.conf.default.accept_ra_defrtr = 0   
#Router advertisements can not assign a global unicast address to an interface 
net.ipv6.conf.default.autoconf = 0   
#Do not send neighbor solicitations
net.ipv6.conf.default.dad_transmits = 0   
#Set number of global unicast IPv6 addresses
net.ipv6.conf.default.max_addresses = 1

##Other##
#Disable netfilter on bridges.
net.bridge.bridge-nf-call-ip6tables = 0
net.bridge.bridge-nf-call-iptables = 0
net.bridge.bridge-nf-call-arptables = 0" > /etc/sysctl

chown root:root /etc/sysctl
chmod 640 /etc/sysctl

#####Disable-Unnecessary-Services#####

chkconfig saslauthd off
chkconfig rcpbind off
chkconfig rdisc off
chkconfig nscd off
chkconfig netfs off
chkconfig netconsole off
chkconfig ip6tables off
chkconfig atd off
chkconfig yum-updatesd off
chkconfig syslog off

chkconfig chargen-dgram off
chkconfig chargen-stream off
chkconfig daytime-dgram off
chkconfig daytime-stream off
chkconfig echo-dgram off
chkconfig echo-stream off
chkconfig tcpmux-server off
chkconfig avahi-daemon off
chkconfig cups off
chkconfig nfslock off
chkconfig rpcgssd off
chkconfig rpcidmapd off
chkconfig rpcbind off
chkconfig rpcidmapd off
chkconfig rpcsvcgssd off

#####Remove-Unnecessary-Packages#####

yum erase finger
yum erase telnet
yum erase telnet-server
yum erase talk
yum erase talk-server
yum erase anacron

yum erase bind
yum erase rsh
yum erase rsh-server
yum erase ypbind
yum erase ypserv
yum erase tftp
yum erase tftp-server
yum erase xinetd
yum erase dhcp
yum erase openldap-servers
yum erase openldap-clients
yum erase vsftpd
yum erase dovecot
yum erase samba
yum erase squid
yum erase sendmail
yum erase net-snmp
yum groupremove ÒX Window SystemÓ

#####Keep-Software-Up-to-Date#####

#Get/Check GPG Key
rpm --import http://mirror.centos.org/centos/RPM-GPG-KEY-CentOS-6
rpm -q --queryformat "%{SUMMARY}\n" gpg-pubkey

#Modify yum config
mv /etc/yum.conf /etc/yum.conf.orig

echo "[main]
cachedir=/var/cache/yum/
keepcache=0
debuglevel=2
logfile=/var/log/yum.log
exactarch=1
obsoletes=1
gpgcheck=1
plugins=1
installonly_limit=5
bugtracker_url=http://bugs.centos.org/set_project.php?project_id=16&ref=http://bugs.centos.org/bug_report_page.php?category=yum
distroverpkg=centos-release

#  This is the default, if you make this bigger yum won't see if the metadata
# is newer on the remote and so you'll gain the bandwidth of not having to
# download the new metadata and pay for it by yum not having correct
# information.
#  It is esp. important, to have correct metadata, for distributions like
# Fedora which don't keep old packages around. If you don't like this checking
# interupting your command line usage, it's much better to have something
# manually check the metadata once an hour (yum-updatesd will do this).
# metadata_expire=90m

# PUT YOUR REPOS HERE OR IN separate files named file.repo
# in /etc/yum.repos.d" > /etc/yum.conf

chown root:root /etc/yum.conf
chmod 640 /etc/yum.conf

#Check for updates and upgrade

yum check-update
yum upgrade

#####Install-Logging/Audit/Security#####

#Rsyslog
yum install rsyslog
chkconfig rsyslog on

mv /etc/rsyslog.conf /etc/rsyslog.conf.orig

echo "$ActionFileDefaultTemplate RSYSLOG TraditionalFileFormat

auth,user.* /var/log/messages
kern.* /var/log/kern.log
daemon.* /var/log/daemon.log
syslog.* /var/log/syslog
lpr,news,uucp,local0,local1,local2,local3,local4,local5,local6.* /var/log/unused.log
" > /etc/rsyslog.conf

chown root:root /etc/rsyslog.conf
chmod 640 /etc/rsyslog.conf

pkill -HUP rsyslogd

#AIDE
yum install aide
chkconfig aide on

#Generate a new AIDE database
aide --init
mv /var/lib/aide/aidb.db.new.gz /var/lib/aide/aide.db.gz
aide --check

#Auditd
yum install audit
chkconfig auditd on

#Auditd Config

mv /etc/audit/auditd.conf /etc/audit/auditd.conf.orig

echo "#
# This file controls the configuration of the audit daemon
#

log_file = /var/log/audit/audit.log
log_format = RAW
log_group = root
priority_boost = 4
flush = INCREMENTAL
freq = 20
num_logs = 5
disp_qos = lossy
dispatcher = /sbin/audispd
name_format = NONE
##name = mydomain
max_log_file = 10 
max_log_file_action = keep_logs
space_left = 75
space_left_action = email
action_mail_acct = root
admin_space_left = 50
admin_space_left_action = halt
disk_full_action = SUSPEND
disk_error_action = SUSPEND
##tcp_listen_port = 
tcp_listen_queue = 5
tcp_max_per_addr = 1
##tcp_client_ports = 1024-65535
tcp_client_max_idle = 0
enable_krb5 = no
krb5_principal = auditd
##krb5_key_file = /etc/audit/audit.key" > /etc/audit/auditd.conf

chown root:root /etc/audit/auditd.conf
chmod 640 /etc/audit/auditd.conf

#Auditd rules

mv /etc/audit/audit.rules /etc/audit/audit.rules.orig

echo "# This file contains the auditctl rules that are loaded
# whenever the audit daemon is started via the initscripts.
# The rules are simply the parameters that would be passed
# to auditctl.

# First rule - delete all
-D

# Increase the buffers to survive stress events.
# Make this bigger for busy systems
-b 320

#Set system audit so that audit rules cannot be modified with auditctl

-e 2

# Feel free to add below this line. See auditctl man page

#modify rules
-a always,exit -F arch=b64 -S adjtimex -S settimeofday -k time-change
-a always,exit -F arch=b32 -S adjtimex -S settimeofday -S stime -k time-change
-a always,exit -F arch=b64 -S clock_settime -k time-change
-a always,exit -F arch=b32 -S clock_settime -k time-change -w /etc/localtime -p wa -k time-change

#identity rules
-w /etc/group -p wa -k identity
-w /etc/passwd -p wa -k identity
-w /etc/gshadow -p wa -k identity
-w /etc/shadow -p wa -k identity
-w /etc/security/opasswd -p wa -k identity

#network rules
-a exit,always -F arch=b64 -S sethostname -S setdomainname -k system-locale
-a exit,always -F arch=b32 -S sethostname -S setdomainname -k system-locale
-w /etc/issue -p wa -k system-locale
-w /etc/issue.net -p wa -k system-locale
-w /etc/hosts -p wa -k system-locale
-w /etc/sysconfig/network -p wa -k system-locale

#selinux
-w /etc/selinux/ -p wa -k MAC-policy

#login/logout
-w /var/log/faillog -p wa -k logins
-w /var/log/lastlog -p wa -k logins
-w /var/log/btmp -p wa -k session

#session info
-w /var/run/utmp -p wa -k session
-w /var/log/wtmp -p wa -k session

#permission modifications
-a always,exit -F arch=b64 -S chmod -S fchmod -S fchmodat -F auid>=500 -F auid!=4294967295 -k perm_mod
-a always,exit -F arch=b32 -S chmod -S fchmod -S fchmodat -F auid>=500 -F auid!=4294967295 -k perm_mod
-a always,exit -F arch=b64 -S chown -S fchown -S fchownat -S lchown -F auid>=500 -F auid!=4294967295 -k perm_mod
-a always,exit -F arch=b32 -S chown -S fchown -S fchownat -S lchown -F auid>=500 -F auid!=4294967295 -k perm_mod
-a always,exit -F arch=b64 -S setxattr -S lsetxattr -S fsetxattr -S removexattr -S lremovexattr -S fremovexattr -F auid>=500 -F auid!=4294967295 -k perm_mod
-a always,exit -F arch=b32 -S setxattr -S lsetxattr -S fsetxattr -S removexattr -S lremovexattr -S fremovexattr -F auid>=500 -F auid!=4294967295 -k perm_mod

#unauthorized access
-a always,exit -F arch=b64 -S creat -S open -S openat -S truncate -S ftruncate -F exit=-EACCES -F auid>=500 -F auid!=4294967295 -k access
-a always,exit -F arch=b32 -S creat -S open -S openat -S truncate -S ftruncate -F exit=-EACCES -F auid>=500 -F auid!=4294967295 -k access
-a always,exit -F arch=b64 -S creat -S open -S openat -S truncate -S ftruncate -F exit=-EPERM -F auid>=500 -F auid!=4294967295 -k access
-a always,exit -F arch=b32 -S creat -S open -S openat -S truncate -S ftruncate -F exit=-EPERM -F auid>=500 -F auid!=4294967295 -k access

#privileged commands
find PART -xdev \( -perm -4000 -o -perm -2000 \) -type f | awk '{print \ '-a always,exit -F path=' $1 ' -F perm=x -F auid>=500 -F auid!=4294967295 \ -k privileged' }'

#system mounts
-a always,exit -F arch=b64 -S mount -F auid>=500 -F auid!=4294967295 -k mounts
-a always,exit -F arch=b32 -S mount -F auid>=500 -F auid!=4294967295 -k mounts

#deletion events
-a always,exit -F arch=b64 -S unlink -S unlinkat -S rename -S renameat -F auid>=500 -F auid!=4294967295 -k delete
-a always,exit -F arch=b32 -S unlink -S unlinkat -S rename -S renameat -F auid>=500 -F auid!=4294967295 -k delete

#sudoers
-w /etc/sudoers -p wa -k scope

#sudo log
-w /var/log/sudo.log -p wa -k actions

#kernel rules
-w /sbin/insmod -p x -k modules
-w /sbin/rmmod -p x -k modules
-w /sbin/modprobe -p x -k modules
-a always,exit arch=b64 -S init_module -S delete_module -k modules

#Password changes
auditctl -w /etc/passwd -p war -k password-file

#Shadow Changes
auditctl -w /etc/shadow -k shadow-file -p rwxa

#Suppress mount warnings
auditctl -a exit,never -S mount

#Watch /tmp
auditctl -w /tmp -p e -k webserver-watch-tmp" > /etc/audit/audit.rules

chown root:root /etc/audit/audit.rules
chmod 640 /etc/audit/audit.rules

#####TCP_Wrappers#####

yum install tcp_wrappers

#TCP_Wrappers Config
mv /etc/hosts.deny /etc/hosts.deny.orig
mv  /etc/hosts.allow  /etc/hosts.allow.orig

echo "ALL:ALL" > /etc/hosts.deny
echo "sshd:ALL" > /etc/hosts.allow
echo "portmap: localhost" >> /etc/hosts.allow
echo "portmap: 127.0.0.1" >> /etc/hosts.allow

chmod 644 /etc/hosts.allow
chmod 644 /etc/hosts.deny

#Make sure iptables is on
chkconfig iptables on
service iptables restart

mv /etc/host.conf /etc/host.conf.orig
echo "order bind,hosts
multi on
nospoof on" > /etc/host.conf

chmod 644 /etc/host.conf

#####Postfix#####

mv /etc/postfix/main.cf /etc/postfix/main.cf.orig

echo "inet_interfaces = localhost

#Limit Denial of Service Attacks

default_process_limit = 100
smtpd_client_connection_count_limit = 10
smtpd_client_connection_rate_limit = 30
queue_minfree = 20971520
header_size_limit = 51200
message_size_limit = 10485760
smtpd_recipient_limit = 100

#Configure Trusted Networks and Hosts
mynetworks_style = subnet
mynetworks_style = host
mynetworks = 127.0.0.1" > /etc/postfix/main.cf

#logwatch

/etc/logwatch/conf/logwatch.conf

HostLimit = no
SplitHosts = yes
MultiEmail = no
Service = -zz-disk_space

#####CRON#####

#Restrict Cron
chown root:root /etc/crontab
chmod 600 /etc/crontab
cd /etc
chown -R root:root cron.hourly cron.daily cron.weekly cron.monthly cron.d
chmod -R go-rwx cron.hourly cron.daily cron.weekly cron.monthly cron.d
chown root:root /var/spool/cron
chmod -R go-rwx /var/spool/cron

rm /etc/cron.deny
rm /etc/at.deny
chmod og-rwx /etc/cron.allow
chmod og-rwx /etc/at.allow
chown root:root /etc/cron.allow
chown root:root /etc/at.allow

rm /etc/at.deny
touch /etc/at.allow
chown root:root /etc/at.allow
chmod og-rwx /etc/at.allow

chown root:root /etc/cron.d
chmod og-rwx /etc/cron.d

chown root:root /etc/crontab
chmod og-rwx /etc/crontab

chown root:root /etc/cron.hourly
chmod og-rwx /etc/cron.hourly

chown root:root /etc/cron.daily
chmod og-rwx /etc/cron.daily

chown root:root /etc/cron.weekly
chmod og-rwx /etc/cron.weekly

chown root:root /etc/cron.montly
chmod og-rwx /etc/cron.montly

Remove the cron.deny file:
# rm /etc/cron.deny
2. Edit /etc/cron.allow, adding one line for each user allowed to use the crontab command to create
cron jobs.
3. Remove the at.deny file:
# rm /etc/at.deny
4. Edit /etc/at.allow, adding one line for each user allowed to use the at command to create at jobs.

##CronJobs

#YUM
echo Òyum -R 120 -e 0 -d 0 -y upgrade yumÓ >> /etc/cron.monthly/yum.cron
echo Òyum -R 10 -e 0 -d 0 -y upgradeÓ >> /etc/cron.monthly/yum.cron

#Logwatch
echo "/usr/share/logwatch/scripts/logwatch.pl 0logwatch" > /etc/cron.daily/logwatch.cron


######Verify-Packages#####

echo "These packages have changed, it may be wise to re-install the packages below: "
rpm -qVa | awk '$2!="c" {print $0}'


#####Webmin#####

echo
"[Webmin]
name=Webmin Distribution Neutral
#baseurl=http://download.webmin.com/download/yum
mirrorlist=http://download.webmin.com/download/yum/mirrorlist
enabled=1" > /etc/yum.repos.d/webmin.repo

wget -O /tmp http://www.webmin.com/jcameron-key.asc
rpm --import /tmp/jcameron-key.asc

yum -y install webmin

###Sources###
#Created from:
#http://wiki.centos.org/HowTos/OS_Protection
#http://benchmarks.cisecurity.org/downloads/show-single/?file=rhel6.100
#http://www.nsa.gov/ia/_files/os/redhat/rhel5-guide-i731.pdf