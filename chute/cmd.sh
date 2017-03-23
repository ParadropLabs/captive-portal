#!/bin/bash

CLIENT_IFACE='wlan0'

# start captivator dependencies
/etc/init.d/rsyslog restart

/bin/chmod a+x /var/www/index.pl
/usr/sbin/a2enmod rewrite
/usr/sbin/a2enmod cgid
/usr/sbin/a2enmod php5

echo 1 > /proc/sys/net/ipv4/ip_forward

# Allow icmp
iptables -t filter -A INPUT -p icmp --icmp-type 0  -j ACCEPT
iptables -t filter -A INPUT -p icmp --icmp-type 8  -j ACCEPT

# Allow traffic to specified addresses, e.g. the login page.
iptables -t mangle -A PREROUTING -d 173.229.3.10 -j ACCEPT
iptables -t mangle -A PREROUTING -d 173.229.3.20 -j ACCEPT
for domain in $CP_ALLOW_DOMAIN; do
    iptables -t mangle -A PREROUTING -d "$domain" -j ACCEPT
done

# Create clients chain
# This is used to authenticate users who have already signed up
iptables -N clients -t mangle

# First send all traffic via newly created clients chain
# At the prerouting NAT stage this will DNAT them to the local
# webserver for them to signup if they aren't authorised
# Packets for unauthorised users are marked for dropping later
iptables -t mangle -A PREROUTING -i ${CLIENT_IFACE} -j clients

# MAC address not found. Mark the packet 99
iptables -t mangle -A clients -j MARK --set-mark 99

# Redirects web requests from Unauthorised users to logon Web Page
iptables -t nat -A PREROUTING -m mark --mark 99 -p tcp --dport 80 -j REDIRECT --to-port 80

# Forward return traffic from the Internet.
iptables -A FORWARD -i eth0 -o wlan0 -m state --state ESTABLISHED,RELATED -j ACCEPT

# Forward user traffic if it is authenticated (not marked) or DNS.  Drop anything else.
# Some sites load content over UDP port 443 (might be QUIC, google.com/finance
# seems to do tihs), so webpage can still load unless we block UDP.
iptables -A FORWARD -i wlan0 -o eth0 -p udp --dport 53 -j ACCEPT
iptables -A FORWARD -i wlan0 -o eth0 -m mark --mark 99 -j REJECT

iptables -t nat -A POSTROUTING -o eth0 -j MASQUERADE

# If environment variables are set, then use them to override the default URLs
# in the chute php script.
if [ -n "$CP_AUTH_URL" ]; then
    sed -i "s|auth_url = .*;|auth_url = \"$CP_AUTH_URL\";|" /var/www/index.php
fi
if [ -n "$CP_LOGIN_URL" ]; then
    sed -i "s|login_url = .*;|login_url = \"$CP_LOGIN_URL\";|" /var/www/index.php
fi
if [ -n "$CP_LANDING_URL" ]; then
    sed -i "s|landing_url = .*;|landing_url = \"$CP_LANDING_URL\";|" /var/www/index.php
fi
if [ -n "$CP_LOCATION" ]; then
    sed -i "s|location = .*;|location = \"$CP_LOCATION\";|" /var/www/index.php
fi
if [ -n "$CP_EXPIRATION" ]; then
    sed -i "s|expiration = .*;|expiration = $CP_EXPIRATION;|" /var/www/index.php
fi

/etc/init.d/apache2 restart

python captive.py
