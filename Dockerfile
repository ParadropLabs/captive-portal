# Captive Portal
FROM ubuntu:14.04
MAINTAINER Paradrop Team <info@paradrop.io>

# Install dependencies.
RUN apt-get update && apt-get install -y \
	apache2 \
	iptables \
	rsyslog \
	conntrack \
	aptitude \
	libapache2-mod-php5 \
    python-pip \
    php5-curl \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/* /tmp/* /var/tmp/* \
    && mkdir -p /opt/captive-portal

WORKDIR /opt/captive-portal

# Install files required by the chute.
ADD chute/000-default.conf /etc/apache2/sites-available/000-default.conf
ADD chute/cmd.sh /usr/local/bin/cmd.sh
ADD chute/rmtrack /usr/bin/rmtrack
ADD chute/index.php /var/www/index.php
ADD chute/favicon.ico /var/www/favicon.ico
ADD chute/captive.py /opt/captive-portal/
ADD chute/radius-defs /opt/captive-portal/
ADD chute/requirements.txt /opt/captive-portal/

RUN echo "www-data ALL = NOPASSWD: /sbin/iptables *" >> /etc/sudoers.d/www-data
RUN echo "www-data ALL = NOPASSWD: /usr/bin/rmtrack [0-9]*.[0-9]*.[0-9]*.[0-9]*" >> /etc/sudoers.d/www-data

RUN echo "nameserver 127.0.0.1" > /etc/resolvconf/resolv.conf.d/base

RUN pip install -r /opt/captive-portal/requirements.txt

# Set up permissions.
RUN chmod +x /usr/local/bin/cmd.sh && \
    chmod +x /usr/bin/rmtrack && \
    chmod 0755 /var/www/* && \
    touch /var/www/users && \
    chown www-data /var/www/*

CMD ["/usr/local/bin/cmd.sh"]
