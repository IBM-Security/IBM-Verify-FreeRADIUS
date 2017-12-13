FROM centos:7

MAINTAINER Jared Page jaredpa@au1.ibm.com

RUN echo "Setting version"
RUN echo "0.2" > /version

EXPOSE \
    1812/udp \
    1813 \
    18120

RUN yum upgrade -y
RUN yum update -y
RUN yum install freeradius freeradius-sqlite freeradius-radclient sqlite openssl-dev -y  
RUN yum install nano -y

COPY "configuration/3013/radiusd.conf" "/etc/raddb/radiusd.conf"
COPY "configuration/3013/clients.conf" "/etc/raddb/clients.conf"
COPY "configuration/3013/default" "/etc/raddb/sites-available/default"

COPY "output/rlm_verify.so" "/usr/lib64/freeradius/rlm_verify.so"

ENTRYPOINT radiusd -X
