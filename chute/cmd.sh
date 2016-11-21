#!/bin/bash

CLIENT_IFACE='wlan0'

# start captivator dependencies
/etc/init.d/rsyslog restart

/bin/chmod a+x /var/www/index.pl
/usr/sbin/a2enmod rewrite
/usr/sbin/a2enmod cgid
/usr/sbin/a2enmod php5

echo 1 > /proc/sys/net/ipv4/ip_forward

# Add dhcp support
iptables -t filter -A INPUT -p udp --dport 67 -j ACCEPT
iptables -t filter -A INPUT -p udp --dport 68 -j ACCEPT

# Allow icmp
iptables -t filter -A INPUT -p icmp --icmp-type 0  -j ACCEPT
iptables -t filter -A INPUT -p icmp --icmp-type 8  -j ACCEPT

# Allow lo
iptables -A INPUT  -i lo -j ACCEPT
iptables -A OUTPUT -o lo -j ACCEPT

# Allow DNS lookups
iptables -A INPUT -p udp --dport 53 -j ACCEPT
iptables -A OUTPUT -p udp -m udp --sport 53 -j ACCEPT
iptables -A OUTPUT -p udp -o eth0 --dport 53 -j ACCEPT
iptables -A INPUT -p udp -i eth0 --sport 53 -j ACCEPT

# Allow traffic to the login page at 5nines.com.  We add a couple of known IP
# addresses here and an optional one from environment variable.
iptables -t mangle -A PREROUTING -d 173.229.3.10 -j ACCEPT
iptables -t mangle -A PREROUTING -d 173.229.3.20 -j ACCEPT
if [ -n "$CP_ALLOW_DOMAIN" ]; then
    iptables -t mangle -A PREROUTING -d "$CP_ALLOW_DOMAIN" -j ACCEPT
fi

# Create internet chain
# This is used to authenticate users who have already signed up
iptables -N internet -t mangle

# First send all traffic via newly created internet chain
# At the prerouting NAT stage this will DNAT them to the local
# webserver for them to signup if they aren't authorised
# Packets for unauthorised users are marked for dropping later
iptables -t mangle -A PREROUTING -i ${CLIENT_IFACE} -j internet

# MAC address not found. Mark the packet 99
iptables -t mangle -A internet -j MARK --set-mark 99

# Redirects web requests from Unauthorised users to logon Web Page
iptables -t nat -A PREROUTING -m mark --mark 99 -p tcp --dport 80 -j REDIRECT --to-port 80
iptables -t nat -A PREROUTING -m mark --mark 99 -p tcp --dport 443 -j REDIRECT --to-port 80

# Do the same for the INPUT chain to stop people accessing the web through Squid
iptables -t filter -A INPUT -p tcp --dport 80 -j ACCEPT
iptables -t filter -A INPUT -p udp --dport 53 -j ACCEPT
iptables -t filter -A INPUT -m mark --mark 99 -j DROP

# Enable Internet connection sharing
iptables -A FORWARD -i eth0 -o wlan0 -m state --state ESTABLISHED,RELATED -j ACCEPT

# Forward user traffic if it is authenticated (not marked) or DNS.  Drop anything else.
# Some sites load content over UDP port 443 (might be QUIC, google.com/finance
# seems to do tihs), so webpage can still load unless we block UDP.
iptables -A FORWARD -i wlan0 -o eth0 -m mark ! --mark 99 -j ACCEPT
iptables -A FORWARD -i wlan0 -o eth0 -p udp --dport 53 -j ACCEPT

iptables -t nat -A POSTROUTING -o eth0 -j MASQUERADE

iptables -t filter -P FORWARD DROP

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

while true; do
    sleep 1m

    now=$(date +%s)
    iptables -t mangle -L internet | grep -E "expires [0-9]+" | while read line; do
        mac=$(echo "$line" | grep -oP "(?<=MAC )..:..:..:..:..:..")
        expires=$(echo "$line" | grep -oP "(?<=expires )\d+")

        if [ "$now" -gt "$expires" ]; then
            iptables -t mangle -D internet -m mac --mac-source $mac -m comment --comment "expires $expires" -j RETURN
        fi
    done
done
