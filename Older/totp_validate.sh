#!/bin/bash
USERNAME="$1"
PASSWORD="$2"
CLIENTIP="$3"
RESULT="Reject"

#ISAMHOST="tf.securitypoc.com"
ISAMHOST="verify.securitypoc.com"

# Pulls the HTTP response code from the entire curl response
function curl_response_code {
  echo "$1" | grep -e "^< HTTP\/1.[01]" -e "^HTTP\/1.[01]" | sed -e "s/.*HTTP\/1.[01] \([0-9]*\).*/\1/"
}

# Looks for a single line in the curl response which starts with { and ends with }
function curl_json_body {
  echo "$1" | grep -e "^{" -e "}$"
}

function debug_log {
    echo `date` "$1" >> /tmp/x.x
}

$(debug_log "Received request with username: $USERNAME password: $PASSWORD clientip: $CLIENTIP")

RSP=$(curl -k -i -H "Content-type: application/json" -H "Accept: application/json" -u "api-client:passw0rd" -X PUT -d "{\"username\":\"$USERNAME\",\"otp\":\"$PASSWORD\"}" "https://$ISAMHOST/mga/sps/apiauthsvc?PolicyId=urn:ibm:security:authentication:asf:totp_validate" 2>/dev/null)

$(debug_log "RSP: $RSP")

RSPCODE=$(curl_response_code "$RSP")
if [ "$RSPCODE" == "200" ]
then
    JSONBODY=$(curl_json_body "$RSP")
    if [ ! -z "$JSONBODY" ]
    then
        STATUS=$(echo "$JSONBODY" | jq .status)
        if [ $STATUS == "\"success\"" ]
        then
            RESULT="Accept"
        fi
    fi
fi
$(debug_log "Request with username: $USERNAME password: $PASSWORD clientip: $CLIENTIP returning: $RESULT")
echo "$RESULT"
