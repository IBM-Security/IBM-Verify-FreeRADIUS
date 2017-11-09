FROM centos:7

MAINTAINER Jared Page jaredpa@au1.ibm.com

RUN echo "Setting version"
RUN echo "0.1" > /version

EXPOSE \
    1812/udp \
    1813 \
    18120

RUN yum upgrade -y
RUN yum update -y
RUN yum install freeradius freeradius-sqlite freeradius-radclient sqlite openssl-dev -y  
RUN yum install nano -y

COPY "configuration/radiusd_3_0_4.conf" "/etc/raddb/radiusd.conf"
COPY "configuration/clients.conf" "/etc/raddb/clients.conf"
# COPY "configuration/authorize" "/etc/raddb/mods-config/files/authorize"
# COPY "configuration/default" "/etc/raddb/sites-available/default"s
# COPY "configuration/filter" "/etc/raddb/policy.d/filter"

COPY "output/rlm_isam.so" "/usr/lib64/freeradius/rlm_isam.so"

#ENTRYPOINT radiusd -X
