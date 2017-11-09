#!/bin/bash
# 
# @file test_verify_radius.sh
# @brief IBM Verify FreeRadius Test Client
# This bash script is intended to help test the IBM Verify FreeRadius module. 
#  
# @author: Jared Page (jaredpa@au1.ibm.com)
# @copyright 2017 The IBM Verify FreeRADIUS server project

# Example commands:
# Simple mode: sh test_verify_radius.sh multi localhost 1812 testing123 jaredpa@au1.ibm.com 1234
# Multi mode: sh test_verify_radius.sh multi localhost 1812 testing123 jaredpa@au1.ibm.com

MODE=$1
HOST=$2
PORT=$3
SECRET=$4
USER=$5
OTP=$6

usage(){
	printf "\r\n=====Welcome to the IBM Verify FreeRadius Test Client=====\r\n\r\n"
	printf "This script is intended to help you test the IBM Verify FreeRadius Module (https://github.com/ibm-security/IBM-Verify-FreeRadius). "
	printf "The module allows FreeRadius to call out to ISAM Authentication Policy and return a response to the supplicant FreeRadius user. "
	printf "These callouts can handle the base included ISAM policy along with custom policies. Simple mode is designed to cater toward clients who cannot handle the ACCEPT-CHALLENGE return type\r\n"
	printf "of the FreeRadius server. Multi type allows Challenges. \r\n\r\n"
	printf "All these mode types are are handled within this script - with recurisve functions looping on ACCEPT-CHALLENGE responses. The script uses the radclient capability, with radclient being a prerequiste. In addition, these script needs permission to make temporary files via mktemp. \r\n\r\n"
	printf "Usage: \r\n       test_verify_radius.sh <mode> <host> <port> <secret> <user> <otp:OPTIONAL>\r\n\r\n"
	printf "Parameters:\r\n"
	printf "               <mode>  -  The mode you would like to run the test client in. This mode must match the mode set on the FreeRadius module. Valid values are simple | multi | interactive. \r\n"
	printf "               <host>  -  The host (either IP or hostname) of the FreeRadius server with the ISAM module installed.\r\n"
	printf "               <port>  -  The port of the FreeRadius server.\r\n"
	printf "             <secret>  -  The FreeRadius client secret. This is defined in the clients.conf of the server.\r\n"
	printf "               <user>  -  The username of the user you are trying to authenticate.\r\n"
	printf "       <otp:OPTIONAL>  -  This OPTIONAL field for Multi mode (mandatory for Simple mode) is the OTP for authentication. \r\n"
	printf "\r\n"
	printf "Examples:\r\n"
	printf "Simple mode: $ sh test_verify_radius.sh simple localhost 1812 testing123 jaredpa@au1.ibm.com 1234\r\n"
	printf " Multi mode: $ sh test_verify_radius.sh multi localhost 1812 testing123 jaredpa@au1.ibm.com\r\n\r\n"
	exit 1
}

if [ -z "$MODE" -o -z "$HOST" -o -z "$PORT" -o -z "$USER" -o -z "$SECRET" ]; then usage;fi


capture_otp_recursive(){
	HOST=$1
	PORT=$2
	SECRET=$3
	initiate_rad_client_output=$4

	if [ -z "$HOST" -o -z "$PORT" -o -z "$SECRET" -o -z "$initiate_rad_client_output" ]; then echo "usage: capture_otp_recursive.sh <host> <port> <secret> <initiate_rad_client_output>"; exit 1;fi

	if [[ $initiate_rad_client_output == *"Received Access-Challenge"* ]]; then
		temp_file=$(mktemp)

		echo "Received a challenge!"

		parsed_state=$(echo "$initiate_rad_client_output" | awk 'BEGIN {last = "NEW"} /State = /{last = $3} END {print last}')
		parsed_id=$(echo "$initiate_rad_client_output" | awk 'BEGIN {last = "NEW"} /Id /{last = $4} END {print last}')

		echo "Enter the State [ENTER] [${parsed_state}]: "
		read STATE
#		STATE=${STATE:-1234}
		STATE=${STATE:-${parsed_state}}
		echo "Enter the ID [ENTER] [${parsed_id}]: "
		read ID
		ID=${ID:-${parsed_id}}
		echo "Enter your OTP [ENTER]: "
		read OTP
		OTP=${OTP:-1234}

		echo "==========The chosen parameters=========="
		echo "The state: $STATE"
		echo "The ID: $ID"
		echo "The OTP: $OTP"
		echo "========================================="

		echo "User-Name = $USER" >> ${temp_file}
		echo "NAS-IP-Address = 127.0.0.1" >> ${temp_file}
		echo "User-Password = $OTP" >> ${temp_file}
		echo "State = $STATE" >> ${temp_file}

    	initiate_rad_client_output=$(radclient -x -i "$ID" -f ${temp_file} -F "$HOST":"$PORT" auth "$SECRET")
    	
    	echo "\r\n$initiate_rad_client_output"

		rm ${temp_file}

    	capture_otp_recursive $HOST $PORT $SECRET "$initiate_rad_client_output"

	else
		echo "Complete\r\n"
	fi
}

#### SINGLE MODE ####	
if [ "${MODE}" == "simple" ]
then
	if [ "${OTP}" ]
	then
		printf "Initiating the policy with OTP supplied"
		temp_file=$(mktemp)
		echo "User-Name = $USER" >> ${temp_file}
		echo "NAS-IP-Address = 127.0.0.1" >> ${temp_file}
		echo "User-Password = $OTP" >> ${temp_file}
		contents=$(cat ${temp_file})
		echo "\r\n"
		cat ${temp_file}
		initiate_rad_client_output=$(radclient -x -f ${temp_file} -F $HOST:$PORT auth $SECRET)

		echo "$initiate_rad_client_output"
		rm ${temp_file}
	else
		echo "ERROR: Simple mode selected but no OTP supplied"
	fi
#### MULTI MODE ####	
elif [ "${MODE}" == "multi" ]
then
	printf "Initiating the policy with the OTP supplied on the challenge"
	
	temp_file=$(mktemp)
	echo "User-Name = $USER" >> ${temp_file}
	echo "NAS-IP-Address = 127.0.0.1" >> ${temp_file}
    echo "\r\n"
    cat ${temp_file}

	initiate_rad_client_output=$(radclient -x -f ${temp_file} -F $HOST:$PORT auth $SECRET)

	rm ${temp_file}

    echo "$initiate_rad_client_output"

    capture_otp_recursive $HOST $PORT $SECRET "$initiate_rad_client_output"

#### INTERACTIVE MODE ####	
elif [ "${MODE}" == "interactive" ]
then
	printf "Initiating the poicy when the user can choose how to autheticate"

	echo "Make your policy choice (1 digit), followed by [ENTER]:"

	read choice
	
	echo "$choice"
else
	printf "Incorrect mode\r\n"
fi
