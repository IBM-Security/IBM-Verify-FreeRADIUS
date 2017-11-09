#!/bin/bash
docker build -t isam_freeradius .
exit 0
#
# To deploy to Bluemix.
#
docker tag isam_freeradius registry.ng.bluemix.net/sweeden/isam_freeradius:latest
docker push registry.ng.bluemix.net/sweeden/isam_freeradius:latest
# Get an IP with: cf ic ip request
# Check with: cf ic ip list
cf ic run -p 169.44.117.85:22:22/udp --name bm_isam_freeradius registry.ng.bluemix.net/sweeden/isam_freeradius:latest 

# Check that it comes up running with
cf ic ps -a

# Note that port 22 is forwarded, so we need to change freeradius to listen on 22
# First join a shell to the container
# Find container ID: cf ic ps -a
cf ic exec -it 18277c40-d18 /bin/bash

Then you can edit /etc/raddb/radius.conf and change the list port from 0 to 22
Then you can stop and restart the container

