FROM alpine:3.1
MAINTAINER Shane Weeden (sweeden@au1.ibm.com)

WORKDIR /projects

RUN apk update && apk upgrade && \
    apk add --update bash jq curl freeradius freeradius-sqlite freeradius-radclient sqlite openssl-dev && \
    chgrp radius  /usr/sbin/radiusd && chmod g+rwx /usr/sbin/radiusd && \
    rm /var/cache/apk/*
# says anyone can connect with shared secret SECRET
ADD clients.conf /etc/raddb/clients.conf
# establishes script for authorize step which calls ISAM for TOTP validation
ADD default /etc/raddb/sites-available/default
# installs the script that calls ISAM
ADD testclient.sh totp_validate.sh /usr/local/bin/
RUN chgrp radius /usr/local/bin/t*.sh && chmod g+rwx /usr/local/bin/t*.sh

VOLUME \
    /opt/db/ \
    /etc/freeradius/certs

EXPOSE \
    1812/udp \
    1813 \
    18120

# CMD ["top"]
CMD ["radiusd","-xx","-f"]

