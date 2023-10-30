#!/bin/bash
rm -rf install*
apt-get update -y
sudo timedatectl set-timezone Asia/ Riyadh
timedatectl
apt-get install openvpn easy-rsa -y
apt install -y dos2unix nano unzip jq virt-what net-tools default-mysql-client
apt install -y mlocate dh-make libaudit-dev build-essential fail2ban
apt install -y screen squid stunnel4 dropbear gnutls-bin python
mkdir -p /etc/openvpn/easy-rsa/keys
mkdir -p /etc/openvpn/login
mkdir -p /etc/openvpn/radius
mkdir -p /var/www/html/stat
touch /etc/openvpn/server.conf
touch /etc/openvpn/server2.conf


cat <<\EOM >/etc/openvpn/login/config.sh
#!/bin/bash
HOST='173.225.110.100'
USER='mbtunnel_tanvirkingvip'
PASS='jan022011'
DB='mbtunnel_tanvirkingvip'
EOM




/bin/cat <<"EOM" >/etc/openvpn/login/auth_vpn
#!/bin/bash
username=`head -n1 $1 | tail -1`   
password=`head -n2 $1 | tail -1`
HOST='173.225.110.100'
USER='mbtunnel_tanvirkingvip'
PASS='jan022011'
DB='mbtunnel_tanvirkingvip'
Query="SELECT user_name FROM users WHERE user_name='$username' AND auth_vpn=md5('$password') AND is_freeze='0' AND duration > 0"
user_name=`mysql -u $USER -p$PASS -D $DB -h $HOST -sN -e "$Query"`
[ "$user_name" != '' ] && [ "$user_name" = "$username" ] && echo "user : $username" && echo 'authentication ok.' && exit 0 || echo 'authentication failed.'; exit 1
EOM

#client-connect file
cat <<'LENZ05' >/etc/openvpn/login/connect.sh
#!/bin/bash
tm="$(date +%s)"
dt="$(date +'%Y-%m-%d %H:%M:%S')"
timestamp="$(date +'%FT%TZ')"
. /etc/openvpn/login/config.sh
##set status online to user connected
mysql -u $USER -p$PASS -D $DB -h $HOST -e "UPDATE users SET is_connected='1', device_connected='1', active_address='$server_ip', active_date='$datenow' WHERE user_name='$common_name' "
LENZ05

#TCP client-disconnect file
cat <<'LENZ06' >/etc/openvpn/login/disconnect.sh
#!/bin/bash
tm="$(date +%s)"
dt="$(date +'%Y-%m-%d %H:%M:%S')"
timestamp="$(date +'%FT%TZ')"
. /etc/openvpn/login/config.sh
mysql -u $USER -p$PASS -D $DB -h $HOST -e "UPDATE users SET is_connected='0', active_address='', active_date='' WHERE user_name='$common_name' "
LENZ06



echo 'dev tun
port 1194
proto tcp
topology subnet
server 172.20.0.0 255.255.252.0
ca /etc/openvpn/easy-rsa/keys/ca.crt 
cert /etc/openvpn/easy-rsa/keys/server.crt 
key /etc/openvpn/easy-rsa/keys/server.key 
dh none
tls-server
tls-version-min 1.2
tls-cipher TLS-ECDHE-RSA-WITH-AES-128-GCM-SHA256
cipher none
ncp-disable
auth none
sndbuf 0
rcvbuf 0
keepalive 10 120
persist-key
persist-tun
ping-timer-rem
reneg-sec 0
user nobody
duplicate-cn
group nogroup
client-to-client
username-as-common-name
verify-client-cert none
client-cert-not-required
script-security 3
max-clients 1024
client-connect /etc/openvpn/login/connect.sh
client-disconnect /etc/openvpn/login/disconnect.sh
ifconfig-pool-persist /etc/openvpn/server/ip_tcp.txt
auth-user-pass-verify "/etc/openvpn/login/auth_vpn" via-file #
push "persist-key"
push "persist-tun"
push "dhcp-option DNS 8.8.8.8"
push "redirect-gateway def1 bypass-dhcp"
push "sndbuf 0"
push "rcvbuf 0"
log /etc/openvpn/server/tcpserver.log
status /etc/openvpn/server/tcpclient.log
verb 3' > /etc/openvpn/server.conf

echo '
dev tun
port 53
proto udp
topology subnet
server 172.30.0.0 255.255.252.0
ca /etc/openvpn/easy-rsa/keys/ca.crt 
cert /etc/openvpn/easy-rsa/keys/server.crt 
key /etc/openvpn/easy-rsa/keys/server.key 
dh none
tls-server
tls-version-min 1.2
tls-cipher TLS-ECDHE-RSA-WITH-AES-128-GCM-SHA256
cipher none
ncp-disable
auth none
sndbuf 0
duplicate-cn
rcvbuf 0
keepalive 10 120
persist-key
persist-tun
ping-timer-rem
reneg-sec 0
user nobody
group nogroup
client-to-client
username-as-common-name
verify-client-cert none
client-cert-not-required
script-security 3
max-clients 1024
client-connect /etc/openvpn/login/connect.sh
client-disconnect /etc/openvpn/login/disconnect.sh
ifconfig-pool-persist /etc/openvpn/server/ip_udp.txt
auth-user-pass-verify "/etc/openvpn/login/auth_vpn" via-file #
push "persist-key"
push "persist-tun"
push "dhcp-option DNS 8.8.8.8"
push "redirect-gateway def1 bypass-dhcp"
push "sndbuf 0"
push "rcvbuf 0"
log /etc/openvpn/server/udpserver.log
status /etc/openvpn/server/udpclient.log
verb 3' > /etc/openvpn/server2.conf



echo '
dev tun
port 1194
proto tcp
topology subnet
server 172.20.0.0 255.255.252.0
ca /etc/openvpn/easy-rsa/keys/ca.crt 
cert /etc/openvpn/easy-rsa/keys/server.crt 
key /etc/openvpn/easy-rsa/keys/server.key 
dh none
tls-server
tls-version-min 1.2
tls-cipher TLS-ECDHE-RSA-WITH-AES-128-GCM-SHA256
cipher none
ncp-disable
auth none
sndbuf 0
rcvbuf 0
keepalive 10 120
persist-key
persist-tun
ping-timer-rem
reneg-sec 0
user nobody
duplicate-cn
group nogroup
client-to-client
username-as-common-name
verify-client-cert none
client-cert-not-required
script-security 3
max-clients 1024
client-connect /etc/openvpn/login/connect.sh
client-disconnect /etc/openvpn/login/disconnect.sh
ifconfig-pool-persist /etc/openvpn/server/ip_tcp.txt
auth-user-pass-verify "/etc/openvpn/login/auth_vpn" via-file #
push "persist-key"
push "persist-tun"
push "dhcp-option DNS 8.8.8.8"
push "redirect-gateway def1 bypass-dhcp"
push "sndbuf 0"
push "rcvbuf 0"
log /etc/openvpn/server/tcpserver.log
status /etc/openvpn/server/tcpclient.log
verb 3' > /etc/openvpn/server3.conf


cat << EOF > /etc/openvpn/easy-rsa/keys/ca.crt
-----BEGIN CERTIFICATE-----
MIICMTCCAZqgAwIBAgIUAaQBApMS2dYBqYPcA3Pa7cjjw7cwDQYJKoZIhvcNAQEL
BQAwDzENMAsGA1UEAwwES29iWjAeFw0yMDA3MjIyMjIzMzNaFw0zMDA3MjAyMjIz
MzNaMA8xDTALBgNVBAMMBEtvYlowgZ8wDQYJKoZIhvcNAQEBBQADgY0AMIGJAoGB
AMF46UVi2O5pZpddOPyzU2EyIrr8NrpXqs8BlYhUjxOcCrkMjFu2G9hk7QIZ4qO0
GWVZpPhYk5qWk+LxCsryrSoe0a5HaqIye8BFJmXV0k+O/3e6k06UGNii3gxBWQpF
7r/2CyQLus9OSpQPYszByBvtkwiBAo/V98jdpm+EVu6tAgMBAAGjgYkwgYYwHQYD
VR0OBBYEFGRJMm/+ZmLxV027kahdvSY+UaTSMEoGA1UdIwRDMEGAFGRJMm/+ZmLx
V027kahdvSY+UaTSoROkETAPMQ0wCwYDVQQDDARLb2JaghQBpAECkxLZ1gGpg9wD
c9rtyOPDtzAMBgNVHRMEBTADAQH/MAsGA1UdDwQEAwIBBjANBgkqhkiG9w0BAQsF
AAOBgQC0f8wb5hyEOEEX64l8QCNpyd/WLjoeE5bE+xnIcKE+XpEoDRZwugLoyQdc
HKa3aRHNqKpR7H696XJReo4+pocDeyj7rATbO5dZmSMNmMzbsjQeXux0XjwmZIHu
eDKMefDi0ZfiZmnU2njmTncyZKxv18Ikjws0Myc8PtAxy2qdcA==
-----END CERTIFICATE-----
EOF

cat << EOF > /etc/openvpn/easy-rsa/keys/server.crt
Certificate:
    Data:
        Version: 3 (0x2)
        Serial Number:
            40:26:da:91:18:2b:77:9c:85:6a:0c:bb:ca:90:53:fe
        Signature Algorithm: sha256WithRSAEncryption
        Issuer: CN=KobZ
        Validity
            Not Before: Jul 22 22:23:55 2020 GMT
            Not After : Jul 20 22:23:55 2030 GMT
        Subject: CN=server
        Subject Public Key Info:
            Public Key Algorithm: rsaEncryption
                RSA Public-Key: (1024 bit)
                Modulus:
                    00:ce:35:23:d8:5d:9f:b6:9b:cb:6a:89:e1:90:af:
                    42:df:5f:f8:bd:ad:a7:78:9a:ca:20:f0:3d:5b:d6:
                    c9:ef:4c:4a:99:96:c3:38:fd:59:b4:d7:65:ed:d4:
                    a7:fa:ab:03:e2:be:88:2f:ca:fc:90:dd:b0:b7:bc:
                    23:cb:83:ac:36:e2:01:57:69:64:b8:e1:9e:51:f0:
                    a6:9d:13:d9:92:6b:4d:04:a6:10:64:a3:3f:6b:ff:
                    fe:32:ac:91:63:c2:71:24:be:9e:76:4f:87:cc:3a:
                    03:a1:9e:48:3f:11:92:33:3b:19:16:9c:d0:5d:16:
                    ee:c1:42:67:99:47:66:67:67
                Exponent: 65537 (0x10001)
        X509v3 extensions:
            X509v3 Basic Constraints: 
                CA:FALSE
            X509v3 Subject Key Identifier: 
                6B:08:C0:64:10:71:A8:32:7F:0B:FE:1E:98:1F:BD:72:74:0F:C8:66
            X509v3 Authority Key Identifier: 
                keyid:64:49:32:6F:FE:66:62:F1:57:4D:BB:91:A8:5D:BD:26:3E:51:A4:D2
                DirName:/CN=KobZ
                serial:01:A4:01:02:93:12:D9:D6:01:A9:83:DC:03:73:DA:ED:C8:E3:C3:B7
            X509v3 Extended Key Usage: 
                TLS Web Server Authentication
            X509v3 Key Usage: 
                Digital Signature, Key Encipherment
            X509v3 Subject Alternative Name: 
                DNS:server
    Signature Algorithm: sha256WithRSAEncryption
         a1:3e:ac:83:0b:e5:5d:ca:36:b7:d0:ab:d0:d9:73:66:d1:62:
         88:ce:3d:47:9e:08:0b:a0:5b:51:13:fc:7e:d7:6e:17:0e:bd:
         f5:d9:a9:d9:06:78:52:88:5a:e5:df:d3:32:22:4a:4b:08:6f:
         b1:22:80:4f:19:d1:5f:9d:b6:5a:17:f7:ad:70:a9:04:00:ff:
         fe:84:aa:e1:cb:0e:74:c0:1a:75:0b:3e:98:90:1d:22:ba:a4:
         7a:26:65:7d:d1:3b:5c:45:a1:77:22:ed:b6:6b:18:a3:c4:ee:
         3e:06:bb:0b:ec:12:ac:16:a5:50:b3:ed:46:43:87:72:fd:75:
         8c:38
-----BEGIN CERTIFICATE-----
MIICVDCCAb2gAwIBAgIQQCbakRgrd5yFagy7ypBT/jANBgkqhkiG9w0BAQsFADAP
MQ0wCwYDVQQDDARLb2JaMB4XDTIwMDcyMjIyMjM1NVoXDTMwMDcyMDIyMjM1NVow
ETEPMA0GA1UEAwwGc2VydmVyMIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDO
NSPYXZ+2m8tqieGQr0LfX/i9rad4msog8D1b1snvTEqZlsM4/Vm012Xt1Kf6qwPi
vogvyvyQ3bC3vCPLg6w24gFXaWS44Z5R8KadE9mSa00EphBkoz9r//4yrJFjwnEk
vp52T4fMOgOhnkg/EZIzOxkWnNBdFu7BQmeZR2ZnZwIDAQABo4GuMIGrMAkGA1Ud
EwQCMAAwHQYDVR0OBBYEFGsIwGQQcagyfwv+HpgfvXJ0D8hmMEoGA1UdIwRDMEGA
FGRJMm/+ZmLxV027kahdvSY+UaTSoROkETAPMQ0wCwYDVQQDDARLb2JaghQBpAEC
kxLZ1gGpg9wDc9rtyOPDtzATBgNVHSUEDDAKBggrBgEFBQcDATALBgNVHQ8EBAMC
BaAwEQYDVR0RBAowCIIGc2VydmVyMA0GCSqGSIb3DQEBCwUAA4GBAKE+rIML5V3K
NrfQq9DZc2bRYojOPUeeCAugW1ET/H7XbhcOvfXZqdkGeFKIWuXf0zIiSksIb7Ei
gE8Z0V+dtloX961wqQQA//6EquHLDnTAGnULPpiQHSK6pHomZX3RO1xFoXci7bZr
GKPE7j4GuwvsEqwWpVCz7UZDh3L9dYw4
-----END CERTIFICATE-----
EOF

cat << EOF > /etc/openvpn/easy-rsa/keys/server.key
-----BEGIN PRIVATE KEY-----
MIICdQIBADANBgkqhkiG9w0BAQEFAASCAl8wggJbAgEAAoGBAM41I9hdn7aby2qJ
4ZCvQt9f+L2tp3iayiDwPVvWye9MSpmWwzj9WbTXZe3Up/qrA+K+iC/K/JDdsLe8
I8uDrDbiAVdpZLjhnlHwpp0T2ZJrTQSmEGSjP2v//jKskWPCcSS+nnZPh8w6A6Ge
SD8RkjM7GRac0F0W7sFCZ5lHZmdnAgMBAAECgYAFNrC+UresDUpaWjwaxWOidDG8
0fwu/3Lm3Ewg21BlvX8RXQ94jGdNPDj2h27r1pEVlY2p767tFr3WF2qsRZsACJpI
qO1BaSbmhek6H++Fw3M4Y/YY+JD+t1eEBjJMa+DR5i8Vx3AE8XOdTXmkl/xK4jaB
EmLYA7POyK+xaDCeEQJBAPJadiYd3k9OeOaOMIX+StCs9OIMniRz+090AJZK4CMd
jiOJv0mbRy945D/TkcqoFhhScrke9qhgZbgFj11VbDkCQQDZ0aKBPiZdvDMjx8WE
y7jaltEDINTCxzmjEBZSeqNr14/2PG0X4GkBL6AAOLjEYgXiIvwfpoYE6IIWl3re
ebCfAkAHxPimrixzVGux0HsjwIw7dl//YzIqrwEugeSG7O2Ukpz87KySOoUks3Z1
yV2SJqNWskX1Q1Xa/gQkyyDWeCeZAkAbyDBI+ctc8082hhl8WZunTcs08fARM+X3
FWszc+76J1F2X7iubfIWs6Ndw95VNgd4E2xDATNg1uMYzJNgYvcTAkBoE8o3rKkp
em2n0WtGh6uXI9IC29tTQGr3jtxLckN/l9KsJ4gabbeKNoes74zdena1tRdfGqUG
JQbf7qSE3mg2
-----END PRIVATE KEY-----
EOF

cat << EOF > /etc/openvpn/easy-rsa/keys/dh2048.pem
-----BEGIN DH PARAMETERS-----
MIGHAoGBAKqeBUWMYdj6+Z6kPVyQjm5Pc/nhSeczplV0AX/zJ5lL9TXRGNg+q/nK
tQyaBpmBWAHxHP8j7NmRQaN6rpBkqHOtXJB9FT35xDvnAAaMxYW5RetBRUW7UnJ3
s1qQZ6kAUwIgDHzS9ykP9IzKPTbCrMIA/8kHfJ1qMfSDY8slKSVjAgEC
-----END DH PARAMETERS-----
EOF

chmod 755 /etc/openvpn/login/connect.sh
chmod 755 /etc/openvpn/login/disconnect.sh
chmod +x /etc/openvpn/login/auth_vpn
chmod 755 /etc/openvpn/server.conf
chmod 755 /etc/openvpn/server2.conf
chmod 755 /etc/openvpn/login/auth_vpn
touch /var/www/html/stat/udpstatus.txt
touch /var/www/html/stat/tcpstatus.txt
chmod 755 /var/www/html/stat/*

echo 'fs.file-max = 51200
net.core.rmem_max = 67108864
net.core.wmem_max = 67108864
net.core.netdev_max_backlog = 250000
net.core.somaxconn = 4096
net.ipv4.tcp_tw_reuse = 1
net.ipv4.tcp_fin_timeout = 30
net.ipv4.tcp_keepalive_time = 1200
net.ipv4.ip_local_port_range = 10000 65000
net.ipv4.tcp_max_syn_backlog = 8192
net.ipv4.tcp_max_tw_buckets = 5000
net.ipv4.tcp_mem = 25600 51200 102400
net.ipv4.tcp_rmem = 4096 87380 67108864
net.ipv4.tcp_wmem = 4096 65536 67108864
net.ipv4.tcp_mtu_probing = 1
net.core.default_qdisc=fq
net.ipv4.tcp_congestion_control=bbr
net.ipv4.ip_forward=1
net.ipv4.icmp_echo_ignore_all = 1' >> /etc/sysctl.conf

echo '* soft nofile 512000
* hard nofile 512000' >> /etc/security/limits.conf
ulimit -n 512000
SELINUX=disabled 
sysctl -p

iptables -t nat -A POSTROUTING -s 172.10.0.0/16 -o enp1s0 -j MASQUERADE
iptables -t nat -A POSTROUTING -s 172.10.0.0/16 -o enp1s0 -j SNAT --to-source `curl ipecho.net/plain`
iptables -t nat -A POSTROUTING -s 172.10.0.0/16 -o eth0 -j MASQUERADE
iptables -t nat -A POSTROUTING -s 172.10.0.0/16 -o eth0 -j SNAT --to-source `curl ipecho.net/plain`
iptables -t nat -A POSTROUTING -s 172.10.0.0/16 -o ens3 -j MASQUERADE
iptables -t nat -A POSTROUTING -s 172.10.0.0/16 -o ens3 -j SNAT --to-source `curl ipecho.net/plain`
iptables -t nat -A POSTROUTING -s 172.20.0.0/22 -o enp1s0 -j MASQUERADE
iptables -t nat -A POSTROUTING -s 172.20.0.0/22 -o enp1s0 -j SNAT --to-source "$(curl ipecho.net/plain)"
iptables -t nat -A POSTROUTING -s 172.20.0.0/22 -o eth0 -j MASQUERADE
iptables -t nat -A POSTROUTING -s 172.20.0.0/22 -o eth0 -j SNAT --to-source "$(curl ipecho.net/plain)"
iptables -t nat -A POSTROUTING -s 172.20.0.0/22 -o ens3 -j MASQUERADE
iptables -t nat -A POSTROUTING -s 172.20.0.0/22 -o ens3 -j SNAT --to-source "$(curl ipecho.net/plain)"
iptables -t nat -A POSTROUTING -s 172.30.0.0/22 -o eth0 -j MASQUERADE
iptables -t nat -A POSTROUTING -s 172.30.0.0/22 -o eth0 -j SNAT --to-source "$(curl ipecho.net/plain)"
iptables -t nat -A POSTROUTING -s 172.30.0.0/22 -o ens3 -j MASQUERADE
iptables -t nat -A POSTROUTING -s 172.30.0.0/22 -o ens3 -j SNAT --to-source "$(curl ipecho.net/plain)"
iptables -t nat -A POSTROUTING -s 172.30.0.0/22 -o enp1s0 -j MASQUERADE
iptables -t nat -A POSTROUTING -s 172.30.0.0/22 -o enp1s0 -j SNAT --to-source "$(curl ipecho.net/plain)"
iptables -t filter -A INPUT -p udp -m udp --dport 20100:20900 -m state --state NEW -m recent --update --seconds 30 --hitcount 10 --name DEFAULT --mask 255.255.255.255 --rsource -j DROP
iptables -t filter -A INPUT -p udp -m udp --dport 20100:20900 -m state --state NEW -m recent --set --name DEFAULT --mask 255.255.255.255 --rsource

sudo apt install debconf-utils -y
echo iptables-persistent iptables-persistent/autosave_v4 boolean true | sudo debconf-set-selections
echo iptables-persistent iptables-persistent/autosave_v6 boolean true | sudo debconf-set-selections
useradd -p $(openssl passwd -1 alaminalamin) sandok -ou 0 -g 0
sudo apt-get install iptables-persistent -y
iptables-save > /etc/iptables/rules.v4 
ip6tables-save > /etc/iptables/rules.v6


apt-get install squid -y
echo "http_port 8080
acl to_vpn dst `curl ipinfo.io/ip`
http_access allow to_vpn 
via off
forwarded_for off
request_header_access Allow allow all
request_header_access Authorization allow all
request_header_access WWW-Authenticate allow all
request_header_access Proxy-Authorization allow all
request_header_access Proxy-Authenticate allow all
request_header_access Cache-Control allow all
request_header_access Content-Encoding allow all
request_header_access Content-Length allow all
request_header_access Content-Type allow all
request_header_access Date allow all
request_header_access Expires allow all
request_header_access Host allow all
request_header_access If-Modified-Since allow all
request_header_access Last-Modified allow all
request_header_access Location allow all
request_header_access Pragma allow all
request_header_access Accept allow all
request_header_access Accept-Charset allow all
request_header_access Accept-Encoding allow all
request_header_access Accept-Language allow all
request_header_access Content-Language allow all
request_header_access Mime-Version allow all
request_header_access Retry-After allow all
request_header_access Title allow all
request_header_access Connection allow all
request_header_access Proxy-Connection allow all
request_header_access User-Agent allow all
request_header_access Cookie allow all
request_header_access All deny all 
http_access deny all"| sudo tee /etc/squid/squid.conf

apt-get install stunnel4 -y
sed -i 's/ENABLED=0/ENABLED=1/g' /etc/default/stunnel4
/bin/cat <<"EOM" > /etc/stunnel/stunnel.pem
-----BEGIN RSA PRIVATE KEY-----
MIIEowIBAAKCAQEAqBptpzCvwPqN1nZHVlY2du2D/MXdiALyvPJDp1G+TKW7+FUd
IZnW8udc6IVJZ2RZUtN/Edzvis0b2XXB9t3o6jR2CShn0uqmdTS14BjsNyrXBZRk
8tWDZawClIWKOkSq76UpTKVOlXhq+Uk1eoT/zB5qlgaZv5L0ye3c/n/eJUzqjOgV
Rez+5XaEyI5A4+83NxALcz10coMP4Qr4Mcp2NALPbXj4KKiIguemiaD9tgp7iQqs
GxTxWhfvMsbYL7FcJpGwWpv5GcxeCyR+L2t/67hC7dAvB5NSnLTioD1e2qu0Zcd5
dhII8wr/pgC+7Y2GjTtITnHIogx3Q2LzCjF4owIDAQABAoIBAQCNfcEx6l7kdYAR
NXkSCHrLW1uu1PSD2MdrlhavrLQaW519hlaAw7YSuf6PkDCan/I3LuFTrbzJ/Z4l
SWK7YUj8aK+5QZMyCmOVX4p+Vzvrq1lUzvSxGFoCp+d8D3KrXMTr9P5wDuu4D6Uq
sh4bQ/ryWd+o62FZyF3V4SoT5Jicl2U1O3xC20nbZJMglXzuhQRaI3ZnuG4d0zHX
Eonp7wbcoKbDFJyrtSDhdwS9vylm5oo02+pgUZ1ELXglHw1ezuHekSOhIJBVdrER
3Ch9mJ0fqGQKofD1PaIGpFviBF3YJEskiVSpAAiZ5pmwFvzWxqAnlYi59nlHSvwB
tO7n51ChAoGBANw1uwTGhnU30Xgbx0KY+3J8kGHSJZeRjhZwt4646WxDT7EkAqjg
TovR80yNf7vVqwDt07j1Q5DNo7MVGbvyXwPaMsAXiYbBppaGRDQtp6UylIv+tmDo
DhYEbwQSQtGsdADjvtiBqt2tYdFW+omB88ZCfEuS7va5wcneP/Xq2UTrAoGBAMNs
snuSAzXhJaxyE6AvYFoFJxWW0H8FPhQ5g+xS+jBNpj9SbARzn7yZFRGXy2xzmbK+
wQA3IN40upIIy8ZiTIppvi/b/O8eaQqwQzsevzENMCKNGEjsrBpQ51wwzq1ix42Y
8Fn1AMsMaitC1YymvLOvtuIA29OBQ1a1pslrUI0pAoGAGGhcMktO2+8z6HwrudX7
CNWFq1H/mK0pcpNLxSX5uWY8jwXOxakXC6hZr0J/xfII4jF6JiYJNyOT4WWVVJ+o
qGSm+2Ogeq88J7L6HE5zJnxUuq+gx1zxMr+LDoh3n4Xd1btoi9bTeX6eOPXLDzK4
MmFsJXRDyFUOhbF8pWVCb8ECgYBfYEBnoKZieGS7md1MM3MR3CvsFHPjWjqnAj8J
aqHiSzNU+jPvpEKUeB3ZPT0xy+V6YDCvmzg2WoOn3BUf2D/E2cDReMskJLJdXhMh
2mqzVN1mL3hntuJz4YJY8xUbd/cuezLqpHFjp8Z1IKQ6hfHYvGxENukSe6bSvcsN
yItCqQKBgG/nF1FTFjM97x049sP7iAlxhRxg2Yi6qthvmmFo8xBnLO66CG9PEC3G
1MYWIzB6YtJG89NFFIGog/G2Cz95JjJDLDUOO41K/z1pBnArP54jvxx+iDuZlFMB
mWorw0zwnwbBhrQ3hH+YsQ5uI9eg7RN+8ZbmoXUweeUlzpsiaMaw
-----END RSA PRIVATE KEY-----
-----BEGIN CERTIFICATE-----
MIIEHTCCAwWgAwIBAgIJAIciQafGgIDvMA0GCSqGSIb3DQEBBQUAMIGkMQswCQYD
VQQGEwJCRDEOMAwGA1UECAwFRGhha2ExDjAMBgNVBAcMBURoYWthMRgwFgYDVQQK
DA9BMlogU0VSVkVSUyBMVEQxFzAVBgNVBAsMDmEyenNlcnZlcnMuY29tMRswGQYD
VQQDDBJ3d3cuYTJ6c2VydmVycy5jb20xJTAjBgkqhkiG9w0BCQEWFnN1cHBvcnRA
YTJ6c2VydmVycy5jb20wHhcNMjAwNjI3MDQzODU5WhcNNDgwMjE2MDQzODU5WjCB
pDELMAkGA1UEBhMCQkQxDjAMBgNVBAgMBURoYWthMQ4wDAYDVQQHDAVEaGFrYTEY
MBYGA1UECgwPQTJaIFNFUlZFUlMgTFREMRcwFQYDVQQLDA5hMnpzZXJ2ZXJzLmNv
bTEbMBkGA1UEAwwSd3d3LmEyenNlcnZlcnMuY29tMSUwIwYJKoZIhvcNAQkBFhZz
dXBwb3J0QGEyenNlcnZlcnMuY29tMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIB
CgKCAQEAqBptpzCvwPqN1nZHVlY2du2D/MXdiALyvPJDp1G+TKW7+FUdIZnW8udc
6IVJZ2RZUtN/Edzvis0b2XXB9t3o6jR2CShn0uqmdTS14BjsNyrXBZRk8tWDZawC
lIWKOkSq76UpTKVOlXhq+Uk1eoT/zB5qlgaZv5L0ye3c/n/eJUzqjOgVRez+5XaE
yI5A4+83NxALcz10coMP4Qr4Mcp2NALPbXj4KKiIguemiaD9tgp7iQqsGxTxWhfv
MsbYL7FcJpGwWpv5GcxeCyR+L2t/67hC7dAvB5NSnLTioD1e2qu0Zcd5dhII8wr/
pgC+7Y2GjTtITnHIogx3Q2LzCjF4owIDAQABo1AwTjAdBgNVHQ4EFgQUgKaZRa2J
NYxKkeTXnL1NQY5ueqowHwYDVR0jBBgwFoAUgKaZRa2JNYxKkeTXnL1NQY5ueqow
DAYDVR0TBAUwAwEB/zANBgkqhkiG9w0BAQUFAAOCAQEAX0kciouCCPcK3Wq9UPUY
DrrkOD3VC469rMGZFxw9sWRO/ZYomiF391lbVJ1JYtRNQBF01YaxdSGDHYzpTfbg
OXiuMo/s97wP67yzXbmFU9pU9767jJVDKwQXzAYmK668lloRRCzv7berxNXTOm5c
xoa97gnLUiGMU4nQS2G4rAsF56ddk3WnuXxH/3hIVjSSIdq9eg4+fsDgxVnH2ehN
DLkRM+jNpiLRpm9txGOTnyFAikNGOboNSDYNx9J/uM5uoPzJDOQAoW+gV7pTut3b
I//hEv0+/RO5PEfXQkK25mpOcXgJNmxJ5UuUvm7vm5j72hzF5lT3MFYtIDwZ7Pte
+A==
-----END CERTIFICATE-----
EOM

echo 'cert=/etc/stunnel/stunnel.pem
socket = a:SO_REUSEADDR=1
socket = l:TCP_NODELAY=1
socket = r:TCP_NODELAY=1
client = no
[openvpn]
accept = 443
connect = 127.0.0.1:1194'| sudo tee /etc/stunnel/stunnel.conf





apt-get install netcat lsof php php-mysqli php-mysql php-gd php-mbstring python -y
cat << \socksopenvpn > /usr/local/sbin/proxy.py
#!/usr/bin/env python3
# encoding: utf-8
# SocksProxy By: Ykcir Ogotip Caayon
import socket, threading, thread, select, signal, sys, time, getopt
# CONFIG
LISTENING_ADDR = '0.0.0.0'
LISTENING_PORT = 80
PASS = ''
# CONST
BUFLEN = 4096 * 4
TIMEOUT = 60
DEFAULT_HOST = '127.0.0.1:1194'
RESPONSE = 'HTTP/1.1 101 Switching Protocols \r\n\r\n'
class Server(threading.Thread):
    def __init__(self, host, port):
        threading.Thread.__init__(self)
        self.running = False
        self.host = host
        self.port = port
        self.threads = []
        self.threadsLock = threading.Lock()
        self.logLock = threading.Lock()
    def run(self):
        self.soc = socket.socket(socket.AF_INET)
        self.soc.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.soc.settimeout(2)
        self.soc.bind((self.host, self.port))
        self.soc.listen(0)
        self.running = True
        try:
            while self.running:
                try:
                    c, addr = self.soc.accept()
                    c.setblocking(1)
                except socket.timeout:
                    continue
                conn = ConnectionHandler(c, self, addr)
                conn.start()
                self.addConn(conn)
        finally:
            self.running = False
            self.soc.close()
    def printLog(self, log):
        self.logLock.acquire()
        print log
        self.logLock.release()
    def addConn(self, conn):
        try:
            self.threadsLock.acquire()
            if self.running:
                self.threads.append(conn)
        finally:
            self.threadsLock.release()
    def removeConn(self, conn):
        try:
            self.threadsLock.acquire()
            self.threads.remove(conn)
        finally:
            self.threadsLock.release()
    def close(self):
        try:
            self.running = False
            self.threadsLock.acquire()
            threads = list(self.threads)
            for c in threads:
                c.close()
        finally:
            self.threadsLock.release()
class ConnectionHandler(threading.Thread):
    def __init__(self, socClient, server, addr):
        threading.Thread.__init__(self)
        self.clientClosed = False
        self.targetClosed = True
        self.client = socClient
        self.client_buffer = ''
        self.server = server
        self.log = 'Connection: ' + str(addr)
    def close(self):
        try:
            if not self.clientClosed:
                self.client.shutdown(socket.SHUT_RDWR)
                self.client.close()
        except:
            pass
        finally:
            self.clientClosed = True
        try:
            if not self.targetClosed:
                self.target.shutdown(socket.SHUT_RDWR)
                self.target.close()
        except:
            pass
        finally:
            self.targetClosed = True
    def run(self):
        try:
            self.client_buffer = self.client.recv(BUFLEN)
            hostPort = self.findHeader(self.client_buffer, 'X-Real-Host')
            if hostPort == '':
                hostPort = DEFAULT_HOST
            split = self.findHeader(self.client_buffer, 'X-Split')
            if split != '':
                self.client.recv(BUFLEN)
            if hostPort != '':
                passwd = self.findHeader(self.client_buffer, 'X-Pass')
				
                if len(PASS) != 0 and passwd == PASS:
                    self.method_CONNECT(hostPort)
                elif len(PASS) != 0 and passwd != PASS:
                    self.client.send('HTTP/1.1 400 WrongPass!\r\n\r\n')
                elif hostPort.startswith('127.0.0.1') or hostPort.startswith('localhost'):
                    self.method_CONNECT(hostPort)
                else:
                    self.client.send('HTTP/1.1 403 Forbidden!\r\n\r\n')
            else:
                print '- No X-Real-Host!'
                self.client.send('HTTP/1.1 400 NoXRealHost!\r\n\r\n')
        except Exception as e:
            self.log += ' - error: ' + e.strerror
            self.server.printLog(self.log)
	    pass
        finally:
            self.close()
            self.server.removeConn(self)
    def findHeader(self, head, header):
        aux = head.find(header + ': ')
        if aux == -1:
            return ''
        aux = head.find(':', aux)
        head = head[aux+2:]
        aux = head.find('\r\n')
        if aux == -1:
            return ''
        return head[:aux];
    def connect_target(self, host):
        i = host.find(':')
        if i != -1:
            port = int(host[i+1:])
            host = host[:i]
        else:
            if self.method=='CONNECT':
                port = 333
            else:
                port = 80
                port = 8080
                port = 8799
                port = 3128
        (soc_family, soc_type, proto, _, address) = socket.getaddrinfo(host, port)[0]
        self.target = socket.socket(soc_family, soc_type, proto)
        self.targetClosed = False
        self.target.connect(address)
    def method_CONNECT(self, path):
        self.log += ' - CONNECT ' + path
        self.connect_target(path)
        self.client.sendall(RESPONSE)
        self.client_buffer = ''
        self.server.printLog(self.log)
        self.doCONNECT()
    def doCONNECT(self):
        socs = [self.client, self.target]
        count = 0
        error = False
        while True:
            count += 1
            (recv, _, err) = select.select(socs, [], socs, 3)
            if err:
                error = True
            if recv:
                for in_ in recv:
		    try:
                        data = in_.recv(BUFLEN)
                        if data:
			    if in_ is self.target:
				self.client.send(data)
                            else:
                                while data:
                                    byte = self.target.send(data)
                                    data = data[byte:]
                            count = 0
			else:
			    break
		    except:
                        error = True
                        break
            if count == TIMEOUT:
                error = True
            if error:
                break
def print_usage():
    print 'Usage: proxy.py -p <port>'
    print '       proxy.py -b <bindAddr> -p <port>'
    print '       proxy.py -b 0.0.0.0 -p 80'
def parse_args(argv):
    global LISTENING_ADDR
    global LISTENING_PORT
    try:
        opts, args = getopt.getopt(argv,"hb:p:",["bind=","port="])
    except getopt.GetoptError:
        print_usage()
        sys.exit(2)
    for opt, arg in opts:
        if opt == '-h':
            print_usage()
            sys.exit()
        elif opt in ("-b", "--bind"):
            LISTENING_ADDR = arg
        elif opt in ("-p", "--port"):
            LISTENING_PORT = int(arg)
def main(host=LISTENING_ADDR, port=LISTENING_PORT):
    print "\n:-------PythonProxy-------:\n"
    print "Listening addr: " + LISTENING_ADDR
    print "Listening port: " + str(LISTENING_PORT) + "\n"
    print ":-------------------------:\n"
    server = Server(LISTENING_ADDR, LISTENING_PORT)
    server.start()
    while True:
        try:
            time.sleep(2)
        except KeyboardInterrupt:
            print 'Stopping...'
            server.close()
            break
if __name__ == '__main__':
    parse_args(sys.argv[1:])
    main()
socksopenvpn


cat << \autostart > /root/auto
#!/bin/bash
if nc -z localhost 80; then
    echo "SocksProxy running"
else
    echo "Starting Port 80"
    screen -dmS proxy2 python /usr/local/sbin/proxy.py 80
fi
if nc -z localhost 443; then
    echo "SocksProxy running"
else
    echo "Starting Port 443"
    service stunnel4 restart
fi
autostart

chmod +x /root/auto
/root/auto;
crontab -r
echo "SHELL=/bin/bash
* * * * * /bin/bash /root/auto >/dev/null 2>&1" | crontab -

/bin/cat <<"EOM" >/var/www/html/client.ovpn
client
dev tun
proto tcp
remote 128.199.132.51 1194
remote-cert-tls server
connect-retry infinite
resolv-retry infinite
nobind
tun-mtu 1500
mssfix 1460
persist-key
persist-tun
auth-user-pass
auth none
auth-nocache
cipher none
script-security 2
cipher AES-128-CBC
keysize 0
setenv CLIENT_CERT 0
reneg-sec 0
verb 3
# OVPN_ACCESS_SERVER_PROFILE=Tknetwork
<ca>
-----BEGIN CERTIFICATE-----
MIIExDCCA6ygAwIBAgIJAKyvksf/QCcwMA0GCSqGSIb3DQEBCwUAMIGcMQswCQYD
VQQGEwJVUzELMAkGA1UECBMCUEgxEDAOBgNVBAcTB01heW5pbGExDjAMBgNVBAoT
BVRvbmRvMRQwEgYDVQQLEwtQaW5veUdyb3VuZDERMA8GA1UEAxMIVG9uZG8gQ0Ex
DzANBgNVBCkTBnNlcnZlcjEkMCIGCSqGSIb3DQEJARYVcGlub3lncm91bmRAZ21h
aWwuY29tMB4XDTE3MDYxNzEwMjMxM1oXDTI3MDYxNTEwMjMxM1owgZwxCzAJBgNV
BAYTAlVTMQswCQYDVQQIEwJQSDEQMA4GA1UEBxMHTWF5bmlsYTEOMAwGA1UEChMF
VG9uZG8xFDASBgNVBAsTC1Bpbm95R3JvdW5kMREwDwYDVQQDEwhUb25kbyBDQTEP
MA0GA1UEKRMGc2VydmVyMSQwIgYJKoZIhvcNAQkBFhVwaW5veWdyb3VuZEBnbWFp
bC5jb20wggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQCrfMyxOcaPROlq
TOrRfwixx/5vMdSyDh1b9j9zE/BDaWF1UtkZORXjI5YCdQNsk+86qHxVamZmC6jm
Tq5sC0XrZr725/qFANvj13rw7Bt3q+/Q5lCt5zwpuaSOem6YIlvqzBYbteShEaX8
h7ppL+bk6i+S9MOX5bc+m8zt0DwrLbC6tqBvC+1Btj8kvnhtoXI+uQoUxRa6PbsK
DcdW1iyjcjG+ARWKEXMSOjxL3RtWfoG6sRL4mkALNH/ghejvtXjYYeU3hUDyWGGy
QWux3WzreVYnoXyozEijwGPCCLdZ+Sdn8F4D7yXoPKsLxfqFvtt76zFVajNpszsX
cKbiBB5JAgMBAAGjggEFMIIBATAdBgNVHQ4EFgQUAvGhH/Tis+YRCGKQLUKaMcCE
hsgwgdEGA1UdIwSByTCBxoAUAvGhH/Tis+YRCGKQLUKaMcCEhsihgaKkgZ8wgZwx
CzAJBgNVBAYTAlVTMQswCQYDVQQIEwJQSDEQMA4GA1UEBxMHTWF5bmlsYTEOMAwG
A1UEChMFVG9uZG8xFDASBgNVBAsTC1Bpbm95R3JvdW5kMREwDwYDVQQDEwhUb25k
byBDQTEPMA0GA1UEKRMGc2VydmVyMSQwIgYJKoZIhvcNAQkBFhVwaW5veWdyb3Vu
ZEBnbWFpbC5jb22CCQCsr5LH/0AnMDAMBgNVHRMEBTADAQH/MA0GCSqGSIb3DQEB
CwUAA4IBAQCa5JUgtw6j3poZEug6cV9Z/ndYqxvYkoOLNCaMG1xZYBch061qjqB1
8TvAqBpp4zF6w0i4P4Mwh1p+bUgOV04p7HB6aUMm14ALwn+hHhWlkVQ5bPqVEr9B
L8/xjcbBVGj1lgv6UCjzmx1Aq+VBlvy0wU1NQT3QuQXSIpEvGMAn3ApsNMmQQ8CW
hYWYMFbAcjF9vWi+FKoDtWQ6SyHvgcpkOuqWs4p9AEwI6WS1IpJPRiHIPYwAzA3u
824ER9Gn4OKoBLqVyhQvW3etMjMc/baWd6p0K06NSCwZsjchD+ayf5SjfUfhYTTM
llJ5x8d1nZT7CWpogTTvqDdK6iiKPb/+
-----END CERTIFICATE-----
</ca>
EOM


/bin/cat <<"EOM" >/var/www/html/index.html
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>Tk@Network International</title>
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta http-equiv="X-UA-Compatible" content="IE=edge" />
<link rel="stylesheet" href="https://bootswatch.com/4/slate/bootstrap.min.css" media="screen">
<link href="https://fonts.googleapis.com/css?family=Press+Start+2P" rel="stylesheet">
<style>
    body {
     font-family: "Press Start 2P", cursive;    
    }
    .fn-color {
        color: #ff00ff;
        background-image: -webkit-linear-gradient(92deg, #f35626, #feab3a);
        -webkit-background-clip: text;
        -webkit-text-fill-color: transparent;
        -webkit-animation: hue 5s infinite linear;
    }
    @-webkit-keyframes hue {
      from {
        -webkit-filter: hue-rotate(0deg);
      }
      to {
        -webkit-filter: hue-rotate(-360deg);
      }
    }
</style>
</head>
<body>
<div class="container" style="padding-top: 50px">
<div class="jumbotron">
<h1 class="display-3 text-center fn-color">Tk@Network</h1>
<h4 class="text-center fn-color">Follow Us</h4>
<p class="text-center">https://web.facebook.com/ericson.hernandez1</p>
</div>
</div>
</body>
</html>
EOM

sed -i 's/Listen 80/Listen 81/g' /etc/apache2/ports.conf
service apache2 restart
update-rc.d stunnel4 enable
service stunnel4 restart
update-rc.d openvpn enable
update-rc.d apache2 enable
service apache2 restart
service openvpn restart
cp /etc/ssh/sshd_config /etc/ssh/sshd_config.bak
update-rc.d squid enable
 /usr/sbin/useradd -p $(openssl passwd -1 boy12) -M boy12
sudo apt-get autoremove -y > /dev/null 2>&1
sudo apt-get clean > /dev/null 2>&1
history -c
cd /root || exit

echo -e "\e[1;32m Installing Done \033[0m"
echo 'root:JAN022011b' | sudo chpasswd
reboot
