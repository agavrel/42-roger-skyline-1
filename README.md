# 42-roger-skyline-1

### 3 / Network and Security Part

You must create a non-root user to connect to the machine and work.
```
sudo adduser roger
```

Use sudo, with this user, to be able to perform operation requiring special rights.
```
sudo usermod -aG sudo roger
```

To switch to the newly created user use:
```
su roger
```
_NB: while entering the password you won't see anything, it is normal._  

use ```passwd``` if you want to change the password to a more robust one.  



• We don’t want you to use the DHCP service of your machine. You’ve got to
configure it to have a static IP and a Netmask in \30.
```
```

You have to change the default port of the SSH service by the one of your choice. Let's change it to 242.
```
sudo cat /etc/ssh/sshd_config | grep 'Port ' \
&& sudo chmod 0777 /etc/ssh/sshd_config \
&& sudo sed -i 's/#Port 22/Port 242/g' /etc/ssh/sshd_config /etc/ssh/sshd_config \
&& sudo chmod 0644 /etc/ssh/sshd_config \
&& sudo cat /etc/ssh/sshd_config | grep 'Port '
&& sudo service sshd restart
```

SSH access HAS TO be done with publickeys. SSH root access SHOULD NOT
be allowed directly, but with a user who can be root.

On your Computer:
```
mkdir keys
&& umask 077 \
&& wg genkey | tee keys/server_privatekey | wg pubkey > keys/server_publickey \
&& ssh-add keys/server_publickey \
&& cat keys/server_privatekey
```

Copy the {content} of the private key and then in the Virtual Machine type:
```
echo '{content}' > server_privatekey
ssh-add server_privatekey
```

Check that the key is now present with:
```
.ssh/authorized_keys
```

You have to set the rules of your firewall on your server only with the services used outside the VM. You only need the SSH access
```
$ sudo iptables -P INPUT DROP
$ sudo iptables -P OUTPUT DROP
$ sudo iptables -A INPUT -i lo -j ACCEPT
$ sudo iptables -A INPUT -p tcp -m tcp --dport 242 -j ACCEPT
$ sudo iptables -A OUTPUT -o lo -j ACCEPT
$ sudo iptables -A OUTPUT -p tcp --sport 242 -m state --state ESTABLISHED -j ACCEPT
```
_NB: use the correct ssh port that you previously changed_

Additionally you can disable the password login but make sure that ```.ssh/authorized_keys``` contains the private kay.
```
PasswordAuthentication no
```

You have to set a DOS (Denial Of Service Attack) protection on your open ports of your VM.  

Run the following script:
```
#!bin/sh
### 1: Drop invalid packets ###
/sbin/iptables -t mangle -A PREROUTING -m conntrack --ctstate INVALID -j DROP  

### 2: Drop TCP packets that are new and are not SYN ###
/sbin/iptables -t mangle -A PREROUTING -p tcp ! --syn -m conntrack --ctstate NEW -j DROP

### 3: Drop SYN packets with suspicious MSS value ###
/sbin/iptables -t mangle -A PREROUTING -p tcp -m conntrack --ctstate NEW -m tcpmss ! --mss 536:65535 -j DROP  

### 4: Block packets with bogus TCP flags ###
/sbin/iptables -t mangle -A PREROUTING -p tcp --tcp-flags FIN,SYN,RST,PSH,ACK,URG NONE -j DROP
/sbin/iptables -t mangle -A PREROUTING -p tcp --tcp-flags FIN,SYN FIN,SYN -j DROP
/sbin/iptables -t mangle -A PREROUTING -p tcp --tcp-flags SYN,RST SYN,RST -j DROP
/sbin/iptables -t mangle -A PREROUTING -p tcp --tcp-flags FIN,RST FIN,RST -j DROP
/sbin/iptables -t mangle -A PREROUTING -p tcp --tcp-flags FIN,ACK FIN -j DROP
/sbin/iptables -t mangle -A PREROUTING -p tcp --tcp-flags ACK,URG URG -j DROP
/sbin/iptables -t mangle -A PREROUTING -p tcp --tcp-flags ACK,FIN FIN -j DROP
/sbin/iptables -t mangle -A PREROUTING -p tcp --tcp-flags ACK,PSH PSH -j DROP
/sbin/iptables -t mangle -A PREROUTING -p tcp --tcp-flags ALL ALL -j DROP
/sbin/iptables -t mangle -A PREROUTING -p tcp --tcp-flags ALL NONE -j DROP
/sbin/iptables -t mangle -A PREROUTING -p tcp --tcp-flags ALL FIN,PSH,URG -j DROP
/sbin/iptables -t mangle -A PREROUTING -p tcp --tcp-flags ALL SYN,FIN,PSH,URG -j DROP
/sbin/iptables -t mangle -A PREROUTING -p tcp --tcp-flags ALL SYN,RST,ACK,FIN,URG -j DROP  

### 5: Block spoofed packets ###
/sbin/iptables -t mangle -A PREROUTING -s 224.0.0.0/3 -j DROP
/sbin/iptables -t mangle -A PREROUTING -s 169.254.0.0/16 -j DROP
/sbin/iptables -t mangle -A PREROUTING -s 172.16.0.0/12 -j DROP
/sbin/iptables -t mangle -A PREROUTING -s 192.0.2.0/24 -j DROP
/sbin/iptables -t mangle -A PREROUTING -s 192.168.0.0/16 -j DROP
/sbin/iptables -t mangle -A PREROUTING -s 10.0.0.0/8 -j DROP
/sbin/iptables -t mangle -A PREROUTING -s 0.0.0.0/8 -j DROP
/sbin/iptables -t mangle -A PREROUTING -s 240.0.0.0/5 -j DROP
/sbin/iptables -t mangle -A PREROUTING -s 127.0.0.0/8 ! -i lo -j DROP  

### 6: Drop ICMP (you usually don't need this protocol) ###
/sbin/iptables -t mangle -A PREROUTING -p icmp -j DROP  

### 7: Drop fragments in all chains ###
/sbin/iptables -t mangle -A PREROUTING -f -j DROP  

### 8: Limit connections per source IP ###
/sbin/iptables -A INPUT -p tcp -m connlimit --connlimit-above 111 -j REJECT --reject-with tcp-reset  

### 9: Limit RST packets ###
/sbin/iptables -A INPUT -p tcp --tcp-flags RST RST -m limit --limit 2/s --limit-burst 2 -j ACCEPT
/sbin/iptables -A INPUT -p tcp --tcp-flags RST RST -j DROP  

### 10: Limit new TCP connections per second per source IP ###
/sbin/iptables -A INPUT -p tcp -m conntrack --ctstate NEW -m limit --limit 60/s --limit-burst 20 -j ACCEPT
/sbin/iptables -A INPUT -p tcp -m conntrack --ctstate NEW -j DROP  

### 11: Use SYNPROXY on all ports (disables connection limiting rule) ###
# Hidden - unlock content above in "Mitigating SYN Floods With SYNPROXY" section
```

You have to set a protection against scans on your VM’s open ports.
https://unix.stackexchange.com/questions/345114/how-to-protect-against-port-scanners
```
# First create ipset lists
ipset create port_scanners hash:ip family inet hashsize 32768 maxelem 65536 timeout 600
ipset create scanned_ports hash:ip,port family inet hashsize 32768 maxelem 65536 timeout 6

# And iptables rules
iptables -A INPUT -m state --state INVALID -j DROP
iptables -A INPUT -m state --state NEW -m set ! --match-set scanned_ports src,dst -m hashlimit --hashlimit-above 1/hour --hashlimit-burst 5 --hashlimit-mode srcip --hashlimit-name portscan --hashlimit-htable-expire 10000 -j SET --add-set port_scanners src --exist
iptables -A INPUT -m state --state NEW -m set --match-set port_scanners src -j DROP
iptables -A INPUT -m state --state NEW -j SET --add-set scanned_ports src,dst
```

### Stop the services you don’t need for this project.

you can display with:
```
service --status-all
```

You need to keep the following ones:
```
ssh
ufw
```

### WIP (booh!)
Create a script that updates all the sources of package, then your packages and which logs the whole in a file named /var/log/update_script.log. Create a scheduled
task for this script once a week at 4AM and every time the machine reboots.
• Make a script to monitor changes of the /etc/crontab file and sends an email to
root if it has been modified. Create a scheduled script task every day at midnight.
