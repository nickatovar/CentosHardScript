############# CentOS 6 Hardening Script ###########

#This script is meant to take basic steps in hardening your
#Centos6.X environment remember however that no system is
#inpenetratable and watching your logs is the best defense
#against intruders and malicious activity.

#Look for "*Change This*" throughout this script for specific
#system settings that should be altered.

#This script will remove most standard installation packages
#leaving only basic applications including SSH and Postfix that
#have outside access. Make sure that if you are using ssh to 
#log into your your server add a user, other than root,
#and add them to an ssh capable group. 

#Please review the sources below to understand what this
#script is actually doing.

###Sources###
#Created from:
#http://wiki.centos.org/HowTos/OS_Protection
#http://benchmarks.cisecurity.org/downloads/show-single/?file=rhel6.100
#http://www.nsa.gov/ia/_files/os/redhat/rhel5-guide-i731.pdf

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
echo umask 027 >> /etc/profile

#Add profile timeouts to reap idle users
echo "#Idle users will be removed after 15 minutes" >> /etc/profile.d/os-security.sh
echo "readonly TMOUT=900" >> /etc/profile.d/os-security.sh
echo "readonly HISTFILE" >> /etc/profile.d/os-security.sh 
chmod +x /etc/profile.d/os-security.sh
chown root:root /etc/profile.d/os-security.sh
chmod 700 /etc/profile.d/os-security.sh

#Update locate Database
updatedb

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

echo "#This is the sshd server system-wide configuration file. See sshd_config(5) for more information.

#The default port is 22, change the port number below to help secure the server
#*Change This*
Port 22

#Disable legacy (protocol version 1) support.
Protocol 2

#SSH key size and cipher type
ServerKeyBits 2048
Ciphers aes128-ctr,aes192-ctr,aes256-ctr

##Logging settings##
#logging level and syslog category
LogLevel INFO
SyslogFacility AUTHPRIV

##AuthenticationSettings##
PasswordAuthentication yes
UsePrivilegeSeparation yes
PermitEmptyPasswords no
PermitUserEnvironment no
ChallengeResponseAuthentication no
PermitRootLogin no
LoginGraceTime 2m
MaxAuthTries 5
MaxSessions 1
StrictModes yes
UsePAM yes
HostbasedAuthentication no
AllowTcpForwarding no
IgnoreRhosts yes

#Change this to a group on your system that you want to have ssh access
#Or use AllowUsers, DenyUsers, DenyGroups for other options
#*Change This* (if you want)
AllowGroups ssh

#SSH Session Keep-Alive
ClientAliveInterval 300
ClientAliveCountMax 0

# Accept locale-related environment variables
AcceptEnv LANG LC_CTYPE LC_NUMERIC LC_TIME LC_COLLATE LC_MONETARY LC_MESSAGES
AcceptEnv LC_PAPER LC_NAME LC_ADDRESS LC_TELEPHONE LC_MEASUREMENT
AcceptEnv LC_IDENTIFICATION LC_ALL LANGUAGE
AcceptEnv XMODIFIERS

#X11
X11Forwarding no

#Set a banner file to let users know they are on the right system
Banner /etc/motd

#Allow for sftp
Subsystem	sftp	/usr/libexec/openssh/sftp-server" > /etc/ssh/sshd_config

chown root:root /etc/ssh/sshd_config
chmod 600 /etc/ssh/sshd_config

#####Disable-Kernel-Drivers#####

#IPV6
echo "options ipv6 disable=1" > /etc/modprobe.d/ipv6.conf
echo "NETWORKING_IPV6=no" >> /etc/sysconfig/network
echo "IPV6INIT=no" >> /etc/sysconfig/network
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
net.ipv4.tcp_timestamps = 0
net.ipv4.icmp_echo_ignore_broadcasts = 1
#Enable source validation by reversed path, as specified in RFC1812
net.ipv4.conf.all.rp_filter = 1
net.ipv4.conf.default.rp_filter = 1   

##IPv6-networking-start##
#Do not accept redirects
net.ipv6.conf.all.accept_redirects = 0
net.ipv6.conf.default.accept_redirects = 0
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
chkconfig cvs off

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

yum -y erase finger
yum -y erase telnet
yum -y erase telnet-server
yum -y erase talk
yum -y erase talk-server
yum -y erase anacron
yum -y erase cvs

yum -y erase bind
yum -y erase rsh
yum -y erase rsh-server
yum -y erase ypbind
yum -y erase ypserv
yum -y erase tftp
yum -y erase tftp-server
yum -y erase xinetd
yum -y erase dhcp
yum -y erase openldap-servers
yum -y erase openldap-clients
yum -y erase vsftpd
yum -y erase dovecot
yum -y erase samba
yum -y erase squid
yum -y erase sendmail
yum -y erase net-snmp
yum -y groupremove "X Window System"

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
pkgpolicy=newest
distroverpkg=centos-release
groupremove_leaf_only=1
exactarch=1
obsoletes=1
gpgcheck=1
plugins=1
installonly_limit=5
metadata_expire=1800
bugtracker_url=http://bugs.centos.org/set_project.php?project_id=16&ref=http://bugs.centos.org/bug_report_page.php?category=yum

# PUT YOUR REPOS HERE OR IN separate files named file.repo
# in /etc/yum.repos.d" > /etc/yum.conf

chown root:root /etc/yum.conf
chmod 640 /etc/yum.conf

#Check for updates and upgrade

yum -y install yum-utils
yum -y check-update
yum -y upgrade

#####Install-Logging/Audit/Security#####

##Rsyslog##

#Remove default logs
rm -fR /var/log/

#Make sure all rsyslogs are created and secure
touch /var/log/auth.log
chown root:root /var/log/auth.log
chmod og-rwx /var/log/auth.log

touch /var/log/kern.log
chown root:root /var/log/kern.log
chmod og-rwx /var/log/kern.log

touch /var/log/daemon.log
chown root:root /var/log/daemon.log
chmod og-rwx /var/log/daemon.log

touch /var/log/sys.log
chown root:root /var/log/sys.log
chmod og-rwx /var/log/sys.log

touch /var/log/mail.log
chown root:root /var/log/mail.log
chmod og-rwx /var/log/mail.log

touch /var/log/err.log
chown root:root /var/log/err.log
chmod og-rwx /var/log/err.log

touch /var/log/misc.log
chown root:root /var/log/misc.log
chmod og-rwx /var/log/misc.log

yum -y install rsyslog

mv /etc/rsyslog.conf /etc/rsyslog.conf.orig

echo "\$ActionFileDefaultTemplate RSYSLOG_TraditionalFileFormat

auth,user.* /var/log/auth.log
kern.*   /var/log/kern.log
daemon.* /var/log/daemon.log
syslog.* /var/log/sys.log
mail.*   /var/log/mail.log
*.err    /var/log/err.log
lpr,news,uucp,local0,local1,local2,local3,local4,local5,local6.* /var/log/misc.log
" > /etc/rsyslog.conf

chown root:root /etc/rsyslog.conf
chmod 640 /etc/rsyslog.conf

chkconfig rsyslog on

#Restart rsyslog
/etc/init.d/rsyslog restart

#Logwatch (used to summarize rsyslog)
yum -y  install logwatch

mv /etc/logwatch/conf/logwatch.conf /etc/logwatch/conf/logwatch.conf.orig

echo "
# Logwatch Configuration File

# Default Log Directory
LogDir = /var/log

# You can override the default temp directory (/tmp) here
TmpDir = /var/cache/logwatch

# Default person to mail reports to.
#*Change This*
MailTo = user@example.com

# Default person to mail reports from.
MailFrom = Logwatch

#Send to stdout instead of being mailed to above person.
Print = No

# Use archives? 
#Archives = No (Default:yes)
#Range = All

# The time range for the reports (All, Today, Yesterday)
Range = All

# Detail level for the report (Low, Med, High)
Detail = High 

#This should be left as All for most people.  
Service = All

# The below services are disabled, comment them if you would like to use them
Service = \"-zz-network\"     # Prevents execution of zz-network service, which
                            # prints useful network configuration info.
Service = \"-zz-sys\"         # Prevents execution of zz-sys service, which
                            # prints useful system configuration info.
Service = \"-eximstats\"      # Prevents execution of eximstats service, which
                            # is a wrapper for the eximstats program.

# Mail Command
mailer = \"sendmail -t\"" >> /etc/logwatch/conf/logwatch.conf

chkconfig logwatch on

##Auditd##
yum -y install audit

#Auditd Config

mv /etc/audit/auditd.conf /etc/audit/auditd.conf.orig

echo "
#
# This file controls the configuration of the audit daemon
#

log_file = /var/log/auditd.log
log_format = RAW
log_group = root
max_log_file = 10 
max_log_file_action = keep_logs
priority_boost = 4
flush = INCREMENTAL
freq = 20
num_logs = 5
disp_qos = lossy
dispatcher = /sbin/audispd
name_format = hostname

admin_space_left = 50
space_left = 75
space_left_action = email
admin_space_left_action = email
action_mail_acct = root
disk_full_action = syslog
disk_error_action = syslog

use_libwrap = yes

" > /etc/audit/auditd.conf

chown root:root /etc/audit/auditd.conf
chmod 640 /etc/audit/auditd.conf

chkconfig auditd on

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

# Feel free to add below this line. See auditctl man page

#modify rules
-a always,exit -F arch=b64 -S adjtimex -S settimeofday -k time-change
-a always,exit -F arch=b64 -S clock_settime -k time-change
-w /etc/localtime -p wa -k time-change

#identity rules
-w /etc/group -p wa -k identity
-w /etc/passwd -p wa -k identity
-w /etc/gshadow -p wa -k identity
-w /etc/shadow -p wa -k identity
-w /etc/security/opasswd -p wa -k identity

#network rules
-a exit,always -F arch=b64 -S sethostname -S setdomainname -k system-locale
-w /etc/issue -p wa -k system-locale
-w /etc/issue.net -p wa -k system-locale
-w /etc/hosts -p wa -k system-locale
-w /etc/sysconfig/network -p wa -k system-locale

#selinux
-w /etc/selinux/ -p wa -k MAC-policy

#login/logout
-w /var/log/faillog -p wa -k logins
-w /var/log/lastlog -p wa -k logins

#session info
-w /var/log/btmp -p wa -k session
-w /var/run/utmp -p wa -k session
-w /var/log/wtmp -p wa -k session

#permission modifications
-a always,exit -F arch=b64 -S chmod -S fchmod -S fchmodat -F auid>=500 -F auid!=4294967295 -k perm_mod
-a always,exit -F arch=b64 -S chown -S fchown -S fchownat -S lchown -F auid>=500 -F auid!=4294967295 -k perm_mod
-a always,exit -F arch=b64 -S setxattr -S lsetxattr -S fsetxattr -S removexattr -S lremovexattr -S fremovexattr -F auid>=500 -F auid!=4294967295 -k perm_mod

#unauthorized access
-a always,exit -F arch=b64 -S creat -S open -S openat -S truncate -S ftruncate -F exit=-EACCES -F auid>=500 -F auid!=4294967295 -k access
-a always,exit -F arch=b64 -S creat -S open -S openat -S truncate -S ftruncate -F exit=-EPERM -F auid>=500 -F auid!=4294967295 -k access

#privileged commands
find PART -xdev \( -perm -4000 -o -perm -2000 \) -type f | awk '{print \ '-a always,exit -F path=' $1 ' -F perm=x -F auid>=500 -F auid!=4294967295 \ -k privileged' }'

#system mounts
-a always,exit -F arch=b64 -S mount -F auid>=500 -F auid!=4294967295 -k mounts

#deletion events
-a always,exit -F arch=b64 -S unlink -S unlinkat -S rename -S renameat -F auid>=500 -F auid!=4294967295 -k delete

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
auditctl -w /tmp -p e -k webserver-watch-tmp

#Set system audit so that audit rules cannot be modified with auditctl
-e 2 " > /etc/audit/audit.rules

chown root:root /etc/audit/audit.rules
chmod 640 /etc/audit/audit.rules

#Restart auditd
/etc/init.d/auditd restart

##AIDE##
yum -y install aide

mv /etc/aide.conf /etc/aide.conf.orig

echo "
# AIDE configuration file.

@@define DBDIR /var/lib/aide
@@define LOGDIR /var/log

# The location of the database to be read.
database=file:@@{DBDIR}/aide.db.gz

# The location of the database to be written.
database_out=file:@@{DBDIR}/aide.db.new.gz

# Whether to gzip the output to database
gzip_dbout=yes

# Logging
verbose=5

report_url=file:@@{LOGDIR}/aide.log

# These are the default rules.

ALLXTRAHASHES = sha1+rmd160+sha256+sha512+tiger
EVERYTHING = R+ALLXTRAHASHES
NORMAL = R+rmd160+sha256
DIR = p+i+n+u+g+acl+selinux+xattrs
PERMS = p+i+u+g+acl+selinux
LOG = >
LSPP = R+sha256
DATAONLY =  p+n+u+g+s+acl+selinux+xattrs+md5+sha256+rmd160+tiger

# Next decide what directories/files you want in the database.

/boot   NORMAL
/bin    NORMAL
/sbin   NORMAL
/lib    NORMAL
/lib64  NORMAL
/opt    NORMAL
/usr    NORMAL
/root   NORMAL
# These are too volatile
!/usr/src
!/usr/tmp

# Check only permissions, inode, user and group for /etc, but
# cover some important files closely.
/etc    PERMS
!/etc/mtab
# Ignore backup files
!/etc/.*~
/etc/exports  NORMAL
/etc/fstab    NORMAL
/etc/passwd   NORMAL
/etc/group    NORMAL
/etc/gshadow  NORMAL
/etc/shadow   NORMAL
/etc/security/opasswd   NORMAL

/etc/hosts.allow   NORMAL
/etc/hosts.deny    NORMAL

/etc/sudoers NORMAL
/etc/skel NORMAL

/etc/logrotate.d NORMAL

/etc/resolv.conf DATAONLY

/etc/nscd.conf NORMAL
/etc/securetty NORMAL

# Shell/X starting files
/etc/profile NORMAL
/etc/bashrc NORMAL
/etc/bash_completion.d/ NORMAL
/etc/login.defs NORMAL
/etc/zprofile NORMAL
/etc/zshrc NORMAL
/etc/zlogin NORMAL
/etc/zlogout NORMAL
/etc/profile.d/ NORMAL
/etc/X11/ NORMAL

# Pkg manager
/etc/yum.conf NORMAL
/etc/yumex.conf NORMAL
/etc/yumex.profiles.conf NORMAL
/etc/yum/ NORMAL
/etc/yum.repos.d/ NORMAL

/var/log   LOG
/var/run/utmp LOG

# This gets new/removes-old filenames daily
!/var/log/sa
# As we are checking it, we've truncated yesterdays size to zero.
!/var/log/aide.log

# LSPP rules...
# AIDE produces an audit record, so this becomes perpetual motion.
# /var/log/audit/ LSPP
/etc/audit/ LSPP
/etc/libaudit.conf LSPP
/usr/sbin/stunnel LSPP
/var/spool/at LSPP
/etc/at.allow LSPP
/etc/at.deny LSPP
/etc/cron.allow LSPP
/etc/cron.deny LSPP
/etc/cron.d/ LSPP
/etc/cron.daily/ LSPP
/etc/cron.hourly/ LSPP
/etc/cron.monthly/ LSPP
/etc/cron.weekly/ LSPP
/etc/crontab LSPP
/var/spool/cron/root LSPP

/etc/login.defs LSPP
/etc/securetty LSPP
/var/log/faillog LSPP
/var/log/lastlog LSPP

/etc/hosts LSPP
/etc/sysconfig LSPP

/etc/inittab LSPP
/etc/grub/ LSPP
/etc/rc.d LSPP

/etc/ld.so.conf LSPP

/etc/localtime LSPP

/etc/sysctl.conf LSPP

/etc/modprobe.conf LSPP

/etc/pam.d LSPP
/etc/security LSPP
/etc/aliases LSPP
/etc/postfix LSPP

/etc/ssh/sshd_config LSPP
/etc/ssh/ssh_config LSPP

/etc/stunnel LSPP

/etc/vsftpd.ftpusers LSPP
/etc/vsftpd LSPP

/etc/issue LSPP
/etc/issue.net LSPP

/etc/cups LSPP

!/var/log/and-httpd

# Admins dot files constantly change, just check perms
/root/\..* PERMS" > /etc/aide.conf

chkconfig aide on

##TCP_Wrappers##

yum -y install tcp_wrappers

#TCP_Wrappers Config
mv /etc/hosts.deny /etc/hosts.deny.orig
mv  /etc/hosts.allow  /etc/hosts.allow.orig

echo "ALL:ALL" > /etc/hosts.deny
echo "sshd:ALL" > /etc/hosts.allow

chmod 644 /etc/hosts.allow
chmod 644 /etc/hosts.deny

mv /etc/host.conf /etc/host.conf.orig
echo "order bind,hosts
multi on
nospoof on" > /etc/host.conf

chmod 644 /etc/host.conf

#####Postfix#####

#Make sure postfix is installed and running
yum install postfix
chkconfig postfix on

#Set to recieve internal mail only, but can send summaries externally
#*Change This* if you need something different

mv /etc/postfix/main.cf /etc/postfix/main.cf.orig

echo "inet_interfaces = localhost

#Limit Denial of Service Attacks
smtpd_client_connection_count_limit = 10
smtpd_client_connection_rate_limit = 30
smtpd_banner = \$myhostname ESMTP ""
queue_minfree = 20971520
header_size_limit = 51200
message_size_limit = 10485760
smtpd_recipient_limit = 100

#Configure Trusted Networks and Hosts
mynetworks = 127.0.0.1/8
myorigin = \$mydomain
mydestination = \$myhostname localhost.\$mydomain localhost \$mydomain
relay_domains = 
fallback_relay =" > /etc/postfix/main.cf

mkfifo /var/spool/postfix/public/pickup
/etc/init.d/postfix restart

#####CRON#####

#Restrict Cron
mkdir /etc/crontab
chown root:root /etc/crontab
chmod 600 /etc/crontab

rm /etc/cron.deny
echo "root" > /etc/cron.allow
chmod og-rwx /etc/cron.allow
chown root:root /etc/cron.allow

cd /etc
mkdir cron.hourly cron.daily cron.weekly cron.monthly cron.d
chown -R root:root cron.hourly cron.daily cron.weekly cron.monthly cron.d
chmod -R go-rwx cron.hourly cron.daily cron.weekly cron.monthly cron.d

mkdir /var/spool/cron
chown root:root /var/spool/cron
chmod -R go-rwx /var/spool/cron

##CronJobs

#YUM
echo "yum -R 120 -e 0 -d 0 -y upgrade yum" > /etc/cron.monthly/yum.cron
echo "yum -R 10 -e 0 -d 0 -y upgrade" >> /etc/cron.monthly/yum.cron

#AIDE
echo "aide --check" > /etc/cron.daily/aide.cron

#Logwatch
echo "/usr/share/logwatch/scripts/logwatch.pl 0logwatch" > /etc/cron.daily/logwatch.cron

#Aureport
echo "aureport --key --summary" >> /etc/cron.daily/aureport.cron

#Verify-Packages
echo "rpm -qVa" > /etc/cron.daily/rpm.cron

#####FIREWALL#####

#Make sure iptables is on
chkconfig iptables on
service iptables restart

#Vars *Change This*
 NET=venet0
 SSH=22

#Flush all current rules from iptables

 iptables -F
 
#Save to make sure flush is not just temporary

 /sbin/service iptables save
 
#Set default chain behaviour

 iptables -P INPUT DROP
 iptables -P FORWARD DROP
 iptables -P OUTPUT ACCEPT
 
#Create a new SYN flood protection chain

 iptables -N SYN-Flood

#Create a LOG chain

 iptables -N LOGnDROP
 
#Set access for localhost

 iptables -A INPUT -i lo -j ACCEPT
 
#Accept packets belonging to established and related connections

 iptables -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT

#Allow SSH connections. This is essential when working on remote
#servers via SSH to prevent locking yourself out of the system

 iptables -A INPUT -p tcp --dport $SSH -j ACCEPT
  
#ICMP rules
 
 iptables -A INPUT -p icmp --icmp-type echo-reply -j ACCEPT
 iptables -A INPUT -i $NET -m limit --limit 3/second --limit-burst 8 -p icmp --icmp-type echo-request -j ACCEPT
 iptables -A INPUT -i $NET -p icmp --icmp-type destination-unreachable -j ACCEPT
 iptables -A INPUT -i $NET -p icmp --icmp-type time-exceeded -j ACCEPT

#Log and then drop martians
 
 iptables -A INPUT -i $NET -s 0.0.0.0/8 -j LOGnDROP
 iptables -A INPUT -i $NET -s 10.0.0.0/8 -j LOGnDROP
 iptables -A INPUT -i $NET -s 127.0.0.0/8 -j LOGnDROP
 iptables -A INPUT -i $NET -s 169.254.0.0/16 -j LOGnDROP
 iptables -A INPUT -i $NET -s 172.16.0.0/12 -j LOGnDROP
 iptables -A INPUT -i $NET -s 192.0.0.0/24 -j LOGnDROP
 iptables -A INPUT -i $NET -s 192.0.2.0/24 -j LOGnDROP
 iptables -A INPUT -i $NET -s 192.168.0.0/16 -j LOGnDROP
 iptables -A INPUT -i $NET -s 198.18.0.0/15 -j LOGnDROP
 iptables -A INPUT -i $NET -s 198.51.100.0/24 -j LOGnDROP
 iptables -A INPUT -i $NET -s 203.0.113.0/24 -j LOGnDROP
 iptables -A INPUT -i $NET -s 240.0.0.0/4 -j LOGnDROP
 iptables -A INPUT -i $NET -s 255.255.255.255/32 -j LOGnDROP
 iptables -A INPUT -i $NET -s 224.0.0.0/4 -j LOGnDROP

#SYN flood protection
 
 iptables -A SYN-Flood -m limit --limit 10/second --limit-burst 50 -j RETURN
 iptables -A SYN-Flood -j LOGnDROP
 
#Log then drop the packets when finished

 iptables -A INPUT -j LOGnDROP
 iptables -A LOGnDROP -m limit --limit 2/minute -j LOG --log-prefix "IPTables-Dropped: " --log-level 4
 iptables -A LOGnDROP -j DROP
 
#Save settings

 /sbin/service iptables save

#List rules

 iptables -L -v
 
##AIDE Database##
#After everything is finished
#generate a new database#
aide --init
mv /var/lib/aide/aide.db.new.gz /var/lib/aide/aide.db.gz
aide --check