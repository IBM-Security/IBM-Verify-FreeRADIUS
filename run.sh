#!/bin/bash
docker stop testing
docker build -t jared/isam-freeradius -t jared/isam-freeradius .
docker run -it -d -p 1812:1812 -p 1812:1812/udp --rm --name testing jared/isam-freeradius
