/**
 * $Id: 5acbecb64b88d31b25e0d25d81c1cf3b93a68f1b $
 * @file rlm_verify.c
 * @brief IBM ISAM FreeRadius Module Code. 
 *
 * @copyright 2017 The IBM ISAM FreeRADIUS server project
 * @copyright 2017 IBM Security
 * @author Jared Page jaredpa@au1.ibm.com
 *
 * Supported versions:
 * 030004
 */
// TODO change this ID
RCSID("$Id: 5acbecb64b88d31b25e0d25d81c1cf3b93a68f1b $")

#include <freeradius-devel/radiusd.h>
#include <freeradius-devel/modules.h>
#include <freeradius-devel/rad_assert.h>
#include <stdio.h>
#include <stdio.h>
#include <stdlib.h>

#include <string.h>
#include <stdbool.h>

#include "sdk/isam.h"
#include "rlm_verify.h"


#if RADIUSD_VERSION==030004
#define FR_STATE PW_STATE
#define CONF_PARSER_TERMINATOR { NULL, -1, 0, NULL, NULL }
#define fr_pair_find_by_num(packet, integer, state, tag)({pairfind(packet, integer, state, tag);})
#define pair_make_reply(reply, message, top)({pairmake_reply(reply, message, top);})
#endif
#if RADIUSD_VERSION==030013
#define pairmake_reply(reply, message, top)({pair_make_reply(reply, message, top);})
#endif

/*
 *	Define a structure for our module configuration.
 *
 *  A pointer to the structure is used as the instance handle.
 */
typedef struct rlm_verify_t {
	char const	*server;
	char const	*junction;
	char const	*protocol;
	char const	*resource;
	char const	*apikey;
	fr_ipaddr_t	client;
	bool		enabled;
	bool		debug;
	char const	*mode;
	uint32_t	port;
	char const	*usersuffix;
	char const	*replymessage;
} rlm_verify_t;

/*
 *	A mapping of configuration file names to internal variables in the handle.
 */

#if RADIUSD_VERSION==040000

static const CONF_PARSER module_config[] = {
 { FR_CONF_OFFSET("server", FR_TYPE_STRING, rlm_verify_t, server) },
 { FR_CONF_OFFSET("junction", FR_TYPE_STRING, rlm_verify_t, junction),.dflt = "/mga" },
 { FR_CONF_OFFSET("protocol", FR_TYPE_STRING, rlm_verify_t, protocol) },
 { FR_CONF_OFFSET("resource", FR_TYPE_STRING, rlm_verify_t, resource) },
 { FR_CONF_OFFSET("apikey", FR_TYPE_STRING, rlm_verify_t, apikey) },
 { FR_CONF_OFFSET("client", FR_TYPE_IPV4_ADDR, rlm_verify_t, client),.dflt = "*"},
 { FR_CONF_OFFSET("enabled", FR_TYPE_BOOL, rlm_verify_t, enabled), .dflt = "no" },
 { FR_CONF_OFFSET("debug", FR_TYPE_BOOL, rlm_verify_t, debug), .dflt = "no" },
 { FR_CONF_OFFSET("port", FR_TYPE_UINT32, rlm_verify_t, port), .dflt = "443" },
 { FR_CONF_OFFSET("mode", FR_TYPE_STRING, rlm_verify_t, mode) },
 { FR_CONF_OFFSET("user-suffix", FR_TYPE_STRING, rlm_verify_t, usersuffix), .dflt = "" },
 { FR_CONF_OFFSET("reply-message", FR_TYPE_STRING, rlm_verify_t, replymessage), .dflt = "This is an ISAM OTP challenge. Please enter your OTP." },
 //Required terminator (Null set)
 CONF_PARSER_TERMINATOR
};

#else

#define FR_CODE_ACCESS_REJECT PW_CODE_ACCESS_REJECT
#define FR_CODE_ACCESS_ACCEPT PW_CODE_ACCESS_ACCEPT
#define FR_CODE_ACCESS_CHALLENGE PW_CODE_ACCESS_CHALLENGE
#define FR_STATE PW_STATE

static const CONF_PARSER module_config[] = {
   	{ "server", FR_CONF_OFFSET(PW_TYPE_STRING, rlm_verify_t, server), NULL },
   	{ "junction", FR_CONF_OFFSET(PW_TYPE_STRING, rlm_verify_t, junction), "/mga" },
    { "protocol", FR_CONF_OFFSET(PW_TYPE_STRING, rlm_verify_t, protocol), NULL },
   	{ "apikey", FR_CONF_OFFSET(PW_TYPE_STRING, rlm_verify_t, apikey), NULL },
    { "resource", FR_CONF_OFFSET(PW_TYPE_STRING, rlm_verify_t, resource), NULL },
    { "enabled", FR_CONF_OFFSET(PW_TYPE_BOOLEAN, rlm_verify_t, enabled), "no" },
    { "debug", FR_CONF_OFFSET(PW_TYPE_BOOLEAN, rlm_verify_t, debug), "no" },
    { "port", FR_CONF_OFFSET(PW_TYPE_INTEGER, rlm_verify_t, port), NULL },
    { "mode", FR_CONF_OFFSET(PW_TYPE_STRING, rlm_verify_t, mode), NULL },
    { "user-suffix", FR_CONF_OFFSET(PW_TYPE_STRING, rlm_verify_t, usersuffix), "" },
    { "reply-message", FR_CONF_OFFSET(PW_TYPE_STRING, rlm_verify_t, replymessage), "This is an ISAM OTP challenge. Please enter your OTP." },
   	CONF_PARSER_TERMINATOR
};

#endif

/*
 *  This is the per module initialization section. This is seperate to each 
 *  configured instance or virtual server of the module. This currently 
 *  initializes all the properties found in radiusd.conf under 'isam'. 
 *  Additionally, the libcurl global init is done here too. 
 *
 *  These properties are (v1.0):
 *	- server <string>
 *	- protocol <string>
 *	- resource <string>
 *	- port <int>
 *	- client <string>
 *	- apikey <string>
 *	- enabled <boolean>
 *	- mode <string>
 *	- simple-format <string>
 *	- otp-length <int>
 *	- interactive_methods <string>
 *	- debug <boolean>
 *
 *  Also done in mod_instantiate is the starting of the session cleanup thread
 *  for multi mode. 
 *
 */
static int mod_instantiate(CONF_SECTION *conf, void *instance)
{
	char METHOD_NAME[] = "mod_instantiate()";
	cf_log_info(conf, "%s: >>>>>>>>>> Entering %s", MODULE_NAME, METHOD_NAME);
	rlm_verify_t	*inst = instance;

	cf_log_info(conf, "%s: %s ==========ISAM MODULE CONFIGURATION START==========", 
													MODULE_NAME, METHOD_NAME);

	if (!inst->server) {
		cf_log_err_cs(conf, "%s: %s Server is false: forcing error!", 
													MODULE_NAME, METHOD_NAME);
		return -1;
	}else{
		if (inst->debug) {
		    char *server_message;
		    asprintf(&server_message, "Server is: %s", inst->server);
			cf_log_info(conf, "%s: %s %s", MODULE_NAME, METHOD_NAME, server_message);
		}
	}

	if (!inst->junction) {
		cf_log_err_cs(conf, "%s: %s Junction is false: forcing error!", 
													MODULE_NAME, METHOD_NAME);
		return -1;
	}else{
		if (inst->debug) {
		    char *junction_message;
		    asprintf(&junction_message, "Junction is: %s", inst->junction);
			cf_log_info(conf, "%s: %s %s", MODULE_NAME, METHOD_NAME, junction_message);
		}
	}

	if (!inst->protocol) {
		cf_log_err_cs(conf, "%s: %s Protocol is false: forcing error!", 
													MODULE_NAME, METHOD_NAME);
		return -1;
	}else{
		if (inst->debug) {
		    char *protocol_message;
		    asprintf(&protocol_message, "Protocol is: %s", inst->protocol);
			cf_log_info(conf, "%s: %s %s", MODULE_NAME, METHOD_NAME, protocol_message);
		}
	}

	if (!inst->resource) {
		cf_log_err_cs(conf, "%s: %s Resource path is empty: forcing error!", 
													MODULE_NAME, METHOD_NAME);
		return -1;
	}else{
		if (inst->debug) {
		    char *resource_message;
		    asprintf(&resource_message, "Resource is: %s", inst->resource);
			cf_log_info(conf, "%s: %s %s", MODULE_NAME, METHOD_NAME, resource_message);
		}
	}

	if (!inst->apikey) {
		cf_log_err_cs(conf, "%s: %s API Key is empty: forcing error!",
													 MODULE_NAME, METHOD_NAME);
		return -1;
	}else{
		if (inst->debug) {
		    char *apikey_message;
		    asprintf(&apikey_message, "API Key is: %s", inst->apikey);
			cf_log_info(conf, "%s: %s %s", MODULE_NAME, METHOD_NAME, apikey_message);
		}
	}

	if (!inst->port) {
		cf_log_err_cs(conf, "%s: %s Port is empty: forcing error!", 
													MODULE_NAME, METHOD_NAME);
		return -1;
	}else{
		if (inst->debug) {

		    char *port_message;
		    asprintf(&port_message, "Port is: %08x", inst->port);

			// char out[] = "Port is: ";
			// char string[9];
			// sprintf(string, "%08x", inst->port);
			// strcat_isam( out, string ); 

			cf_log_info(conf, "%s: %s %s", MODULE_NAME, METHOD_NAME, port_message);
		}
	}

	if (!inst->mode) {
		cf_log_err_cs(conf, "%s: %s Mode is empty: forcing error!", 
													MODULE_NAME, METHOD_NAME);
		return -1;
	}else{
		if (inst->debug) {
		    char *mode_message;
		    asprintf(&mode_message, "Mode is: %s", inst->mode);
			cf_log_info(conf, "%s: %s %s", MODULE_NAME, METHOD_NAME, mode_message);
		}
	}

	// // char out[128] = "";
	// // 	cf_log_err_cs(conf, (inst->client).af);
	// // https://fossies.org/dox/freeradius-server-3.0.14/structfr__ipaddr__t.html

	// // if (inst->client->fr_inet_ifid_ntop()) {
	// // 	cf_log_err_cs(conf, "Client IP is false: forcing error!");
	// // 	return -1;
	// // }else{
	// // 	cf_log_err_cs(conf, "Client IP is True.");
	// // }

	if (!inst->enabled) {
		cf_log_err_cs(conf, "%s: %s Enabled is false: forcing error!", 
													MODULE_NAME, METHOD_NAME);
		return -1;
	}else{
		if (inst->debug) {
			cf_log_info(conf, "%s: %s Enabled is: True.", 
													MODULE_NAME, METHOD_NAME);
		}
	}

	if (!inst->usersuffix) {
		cf_log_err_cs(conf, "%s: %s User Suffix is false: forcing error!", 
													MODULE_NAME, METHOD_NAME);
		return -1;
	}else{
		if (inst->debug) {
		    char *user_suffix_message;
		    asprintf(&user_suffix_message, "User Suffix is: %s", inst->usersuffix);
			cf_log_info(conf, "%s: %s %s", MODULE_NAME, METHOD_NAME, user_suffix_message);
		}
	}

	if (!inst->replymessage) {
		cf_log_err_cs(conf, "%s: %s Reply Message is false: forcing error!", 
													MODULE_NAME, METHOD_NAME);
		return -1;
	}else{
		if (inst->debug) {
		    char *reply_message;
		    asprintf(&reply_message, "Reply Message is: %s", inst->replymessage);
			cf_log_info(conf, "%s: %s %s", MODULE_NAME, METHOD_NAME, reply_message);
		}
	}


	cf_log_info(conf, "%s: %s ==========ISAM MODULE CONFIGURATION END==========", 
													MODULE_NAME, METHOD_NAME);

	// ISAM_INIT();

	cf_log_info(conf, "%s: <<<<<<<<<< Exiting %s", MODULE_NAME, METHOD_NAME);
	return 0;
}



/*
 *	The authorize function takes the information the client has passed and, 
 *  based on the configuration, attempts to authenticate them by calling out to 
 *  ISAM for a result.
 *	This function is the one that interacts with the isam.c functions in a 
 *  meaningful way. 
 *  This handles both Simple and Multi mode and validates both username & 
 *  password as well as OTPs.
 */
#if RADIUSD_VERSION==040000
static rlm_rcode_t CC_HINT(nonnull) mod_authorize(UNUSED void *instance, 
										UNUSED void *thread, REQUEST *request)
#else
static rlm_rcode_t CC_HINT(nonnull) mod_authorize(UNUSED void *instance, 
															REQUEST *request)
#endif
{
	char METHOD_NAME[] = "mod_authorize()";
	RDEBUG("%s: >>>>>>>>>> Entering %s", MODULE_NAME, METHOD_NAME);

	VALUE_PAIR *state;

	request->reply->code = FR_CODE_ACCESS_REJECT;

	rlm_verify_t	*inst = instance;

	if (strcmp(inst->mode, "simple") == 0){
	  RDEBUG("%s: %s Simple mode", MODULE_NAME, METHOD_NAME);

	  int okay = check_request(request, NULL, inst->mode);

	  if (okay){
		  char *payload;
		  asprintf(&payload, "{\"username\":\"%s%s\",\"otp\":\"%s\", \"apikey\":\"%s\"}", 
		  	request->username->vp_strvalue, inst->usersuffix, request->password->vp_strvalue, inst->apikey);

		  HOSTOBJ *isam = ISAM_HOST_SET(inst->protocol, 
		  					inst->server, inst->port, inst->junction, inst->apikey, NULL, false);
		  POLICYOBJ *policy = ISAM_POLICY_SET(isam, inst->resource, 
		  								   METHOD_PUT, payload, NULL);

		  ISAM_CALL_AUTH_POLICY(policy);
		  ISAM_POLICY_PRINT(policy);

	  	  callout_response(policy, request, NULL, inst->mode, inst->replymessage);
		}
	}else if(strcmp(inst->mode, "multi") == 0){
		RDEBUG("%s: %s Multi mode", MODULE_NAME, METHOD_NAME);

		//Check for State
		RDEBUG("%s: %s Checking for state...", MODULE_NAME, METHOD_NAME);

		state = fr_pair_find_by_num(request->packet->vps, 0, FR_STATE, TAG_ANY);

		if(state){
		  RDEBUG("%s: %s State was present.", MODULE_NAME, METHOD_NAME);
		  int okay = check_request(request, state, inst->mode);

		  if (okay){

			#if RADIUSD_VERSION==040000
			char buffer[state->vp_length*sizeof(int)];
			#else
			#if RADIUSD_VERSION==030013
			char buffer[state->vp_length*sizeof(int)];
			#else
			#endif
			#if RADIUSD_VERSION==030004
			char buffer[state->length*sizeof(int)];
			#endif
			#endif
			
			#if RADIUSD_VERSION==040000
				fr_pair_value_snprint(buffer, sizeof(buffer), state, '"');
			#else
			if(!buffer){
				//TODO the vp_strvalue doesn't work for 3040 even though it SHOULD. 
				//This is a bug in the platform. 
				sprintf(buffer, "%s", state->vp_strvalue);
			}
			#endif

        	RDEBUG("New session, adding 'State' attribute to reply 0x%02x%02x%02x%02x%02x%02x%02x%02x",
               state->vp_octets[0], state->vp_octets[1], state->vp_octets[2], state->vp_octets[3],
               state->vp_octets[4], state->vp_octets[5], state->vp_octets[6], state->vp_octets[7]);

			RDEBUG("%s: %s The state %s", MODULE_NAME, METHOD_NAME, buffer);

			int count = count_states(session_states);

			RDEBUG("%s: %s Current stored states COUNT: %d", MODULE_NAME, 
															METHOD_NAME, count);


			RDEBUG("%s: %s Searching for buffer ", MODULE_NAME, METHOD_NAME);
			STATES *found_item = search(session_states, 
										request->username->vp_strvalue, buffer);


			if (!found_item){
				RDEBUG("%s: %s Searching for 'NEW'", MODULE_NAME, METHOD_NAME);
				found_item = search(session_states, 
										 request->username->vp_strvalue, "NEW");
			}

			if (found_item){

				if (!request->password ) {
					REDEBUG("No User-Password in the request. Can't do TOTP authentication");
					return RLM_MODULE_INVALID;
				}

				RDEBUG("%s: %s The found item: %s", MODULE_NAME, METHOD_NAME, 
														  found_item->username);

				found_item->state_client = buffer;

				char *payload;
				asprintf(&payload, "{\"username\":\"%s%s\",\"otp\":\"%s\", \"apikey\":\"%s\"}", 
					request->username->vp_strvalue, inst->usersuffix, request->password->vp_strvalue, inst->apikey);

				found_item->policy->attributes = payload;

				ISAM_CALL_AUTH_POLICY(found_item->policy);
				ISAM_POLICY_PRINT(found_item->policy);
				
				callout_response(found_item->policy, request, found_item, 
																		inst->mode, inst->replymessage);
			}else{
				//TODO go back to the normal flow
				REDEBUG("%s: %s No found item!", MODULE_NAME, METHOD_NAME);
			}
		  }
		}else{
		  RDEBUG("%s: %s There was no state present - assuming initial OTP flow"
		  											, MODULE_NAME, METHOD_NAME);

		  int okay = check_request(request, state, inst->mode);

		  if (okay){

			char *payload;
			if (!request->password ) {
				asprintf(&payload, "{\"username\":\"%s%s\",\"otp\":\"\", \"apikey\":\"%s\"}", 
												request->username->vp_strvalue, inst->usersuffix, inst->apikey);
			}else{
				asprintf(&payload, "{\"username\":\"%s%s\",\"otp\":\"%s\", \"apikey\":\"%s\"}", 
												request->username->vp_strvalue, inst->usersuffix, request->password->vp_strvalue, inst->apikey);
			}

	        char *auth_header;
	        asprintf(&auth_header, "Authorization: Basic %s", inst->apikey);

			const char *headers[] = {auth_header, NULL};

			HOSTOBJ *isam = ISAM_HOST_SET(inst->protocol, inst->server, 
											inst->port, inst->junction, inst->apikey, headers, false);
			POLICYOBJ *policy = ISAM_POLICY_SET(isam, inst->resource, 
											 METHOD_PUT, payload, NULL);

			ISAM_CALL_AUTH_POLICY(policy);
			ISAM_POLICY_PRINT(policy);

	  		callout_response(policy, request, NULL, inst->mode, inst->replymessage);
			}
		}
	}else if(strcmp(inst->mode, "interactive") == 0){
		RDEBUG("%s: %s Interactive mode", MODULE_NAME, METHOD_NAME);
		REDEBUG("%s: %s Interactive mode is currently not provided.", 
													MODULE_NAME, METHOD_NAME);
	}else{
		REDEBUG("%s: %s Wrong Mode, choose: simple/multi/interactive.", 
													MODULE_NAME, METHOD_NAME);
	}
	
	RDEBUG("%s: <<<<<<<<<< Exiting %s", MODULE_NAME, METHOD_NAME);

	return RLM_MODULE_HANDLED;
}

/*
 * Function:  check_request 
 * --------------------
 * Checks the request to see if the username & password are properly provided
 * and valid for the particular mode setup. 
 *
 *  request: the raw request object passed in mod_authorize.
 *  state: the client (radius) state if provided.
 *  mode: the mode (simple/multi) setup. From inst->mode.
 *
 *  returns: 0 if the request doesn't match requirements or 1 if it does.
 *
 */
static int check_request(REQUEST *request, VALUE_PAIR *state, const char *mode){
	char METHOD_NAME[] = "check_request()";
	RDEBUG("%s: >>>>>>>>>> Entering %s", MODULE_NAME, METHOD_NAME);

	  if(request->username){
	    if(request->username->vp_strvalue){
	    	if (!state && strcmp(mode, "multi") == 0){
	    		return 1;
	    	}
		  if(request->password){
		    if(request->password->vp_strvalue){
		    	return 1;
		    }else{
			  request->reply->code = FR_CODE_ACCESS_REJECT;
			  REDEBUG("%s: %s No password string was provided.", 
											MODULE_NAME, METHOD_NAME);
		    }
	      }else{
	        request->reply->code = FR_CODE_ACCESS_REJECT;
	        REDEBUG("%s: %s No password was provided.", 
	    										MODULE_NAME, METHOD_NAME);
          }
	    }else{
		  request->reply->code = FR_CODE_ACCESS_REJECT;
		  REDEBUG("%s: %s No username string was provided.", MODULE_NAME, 
		  													METHOD_NAME);
	    }
	  }else{
		request->reply->code = FR_CODE_ACCESS_REJECT;
		REDEBUG("%s: %s No username was provided.", MODULE_NAME, METHOD_NAME);
	  }

	  RDEBUG("%s: <<<<<<<<<< Exiting %s", MODULE_NAME, METHOD_NAME);
	  return 0;
}

/*
 * Function:  callout_response 
 * --------------------
 *  Parses the response from the ISAM_AUTH_POLICY function in isam.c.
 *  Check to see if the response was an error, or a success. 
 *  Depending on the mode, a new session_state will be created and all the 
 *  cleanup of memory happens if applicable to the mode / action. 
 *
 *  policy: the current policy flow struct.
 *  request: the raw request object passed in mod_authorize.
 *  current_state: The session struct in the linked list that has been matched. 
 *  mode: the mode (simple/multi) setup. From inst->mode.
 *
 */
static void callout_response(POLICYOBJ *policy, REQUEST *request, 
											STATES *current_state, const char *mode, const char *replymessage){
  char METHOD_NAME[] = "callout_response()";
  RDEBUG("%s: >>>>>>>>>> Entering %s", MODULE_NAME, METHOD_NAME);
  if (policy){
	if (policy->response->success == TRUE){
	    RDEBUG("%s: %s Success! The policy call was a success.", 
	    								  MODULE_NAME, METHOD_NAME);
	    RDEBUG("%s: %s The response payload: %s ", MODULE_NAME, 
	    					METHOD_NAME, policy->response->payload);

		char message_property[] = "message";

	    char *message = find_json_element(policy->response->payload,
	    										  message_property);

		char reply_message_property[] = "reply_message";

	    char *response_reply_message = find_json_element(policy->response->payload,
	    										  reply_message_property);

		char *final_reply_message;
		if (response_reply_message != NULL && strlen(response_reply_message) != 0){
			RDEBUG("%s: %s Response Reply message: %s", 
							MODULE_NAME, METHOD_NAME, response_reply_message);
			asprintf(&final_reply_message, response_reply_message);
		}else{
			asprintf(&final_reply_message, replymessage);
		}

		RDEBUG("%s: %s Final Reply message: %s", 
								MODULE_NAME, METHOD_NAME, final_reply_message);

	    if(message){

	    		RDEBUG("%s: %s Response message: %s", 
	    								MODULE_NAME, METHOD_NAME, message);
	    		RDEBUG("%s: %s Compared message: %s", 
	    								MODULE_NAME, METHOD_NAME, OTP_ERROR_MESSAGE);
	    	if (strcmp(message, OTP_ERROR_MESSAGE) == 0){

	    		if (strcmp(mode, "simple") == 0){

	    		RDEBUG("%s: %s Response message - the wrong OTP.", 
	    								MODULE_NAME, METHOD_NAME);

				request->reply->code = FR_CODE_ACCESS_REJECT;
				}else if (strcmp(mode, "multi") == 0){

	    			RDEBUG("%s: %s Challenging", MODULE_NAME, METHOD_NAME);
					
					request->reply->code = FR_CODE_ACCESS_CHALLENGE;

					//If it's multi mode, but they haven't provided a state 
					//means its the first time through - need to store the state
					if (current_state ==  NULL){
						time_t current_time;
						current_time = time(NULL);

					    if (current_time == ((time_t)-1))
					    {
					        (void) fprintf(stderr, 
					        	"Failure to obtain the current time.\n");
					        exit(0);
					    }


						char *new;
						asprintf(&new, "NEW");
						session_states = prepend(session_states, new, policy, 
								request->username->vp_strvalue, current_time);

					}
				}else{
		    		RDEBUG("%s: %s Wrong mode", MODULE_NAME, METHOD_NAME);
					request->reply->code = FR_CODE_ACCESS_REJECT;
				}
	    	}else{
	    		RDEBUG("%s: %s The message didn't match. ", MODULE_NAME, 
	    														METHOD_NAME);
	    	}
		}
		if(message){
    		FREE(message);
    	}	
    	#if RADIUSD_VERSION==040000
		pair_make_reply("Reply-Message", 
			final_reply_message
			, T_OP_EQ);
		#else
		#if RADIUSD_VERSION==030004
		pair_make_reply("Reply-Message", 
			final_reply_message
			, T_OP_EQ);
		#else
		pairmake_reply("Reply-Message", 
			final_reply_message
			, T_OP_EQ);
		#endif
		#endif

		char status_property[] = "status";

    	char *status = find_json_element(policy->response->payload, 
    											   status_property);
	    if(status){
	    	if (strcmp(status, OTP_SUCCESS_MESSAGE) == 0){
	    		RDEBUG("%s: %s Response message - correct Status.", 
	    								MODULE_NAME, METHOD_NAME);
				request->reply->code = FR_CODE_ACCESS_ACCEPT;
				//If the current_state is NULL, then we need to FREE everything
				if (strcmp(mode, "multi") == 0 && current_state){
					session_states = remove_any(session_states, current_state);       	
				}else{
					RDEBUG("%s: %s Memory allocation free.\r\n", MODULE_NAME, 
																METHOD_NAME);
					FREE(policy->host);
					FREE(policy->attributes);
					FREE(policy->response);
					FREE(policy);
				}
	    	}else{
	    		RDEBUG("%s: %s The success status didn't match. ", MODULE_NAME, 
    															METHOD_NAME);
	    	}
		}
		FREE(status);
	}else{
	    RDEBUG("%s: %s Failure! The policy call failed.", 
	    								  MODULE_NAME, METHOD_NAME);	
	    RDEBUG("%s: %s The response payload: %s ", MODULE_NAME,
	    				    METHOD_NAME, policy->response->payload);		
		request->reply->code = FR_CODE_ACCESS_REJECT;	
	}
  }else{
	RDEBUG("%s: %s Failure! The policy object was null.", 
										  MODULE_NAME, METHOD_NAME);
	request->reply->code = FR_CODE_ACCESS_REJECT;
  }
  RDEBUG("%s: <<<<<<<<<< Exiting %s", MODULE_NAME, METHOD_NAME);
}

/*
 *	Authenticate the user with the given password.
 */
static rlm_rcode_t CC_HINT(nonnull) mod_authenticate(UNUSED void *instance, 
								UNUSED void *thread, UNUSED REQUEST *request)
{
	return RLM_MODULE_OK;
}

#ifdef WITH_ACCOUNTING
/*
 *	Massage the request before recording it or proxying it
 */
static rlm_rcode_t CC_HINT(nonnull) mod_preacct(UNUSED void *instance, 
								UNUSED void *thread, UNUSED REQUEST *request)
{
	return RLM_MODULE_OK;
}

/*
 *	Write accounting information to this modules database.
 */
static rlm_rcode_t CC_HINT(nonnull) mod_accounting(UNUSED void *instance, 
								UNUSED void *thread, UNUSED REQUEST *request)
{
	return RLM_MODULE_OK;
}

/*
 *	See if a user is already logged in. Sets request->simul_count to the
 *	current session count for this user and sets request->simul_mpp to 2
 *	if it looks like a multilink attempt based on the requested IP
 *	address, otherwise leaves request->simul_mpp alone.
 *
 *	Check twice. If on the first pass the user exceeds his
 *	max. number of logins, do a second pass and validate all
 *	logins by querying the terminal server (using eg. SNMP).
 */
static rlm_rcode_t CC_HINT(nonnull) mod_checksimul(UNUSED void *instance, 
										UNUSED void *thread, REQUEST *request)
{
	request->simul_count = 0;

	return RLM_MODULE_OK;
}
#endif


/*
 *	Only free memory we allocated.  The strings allocated via
 *	cf_section_parse() do not need to be freed.
 * 
 *  The libcurl handle is cleaned up here. 
 */
static int mod_detach(UNUSED void *instance)
{
	ISAM_SHUTDOWN();
	/* free things here */
	return 0;
}

/*
 *	The module name should be the only globally exported symbol.
 *	That is, everything else should be 'static'.
 *
 *	If the module needs to temporarily modify it's instantiation
 *	data, the type should be changed to RLM_TYPE_THREAD_UNSAFE.
 *	The server will then take care of ensuring that the module
 *	is single-threaded.
 */
#if RADIUSD_VERSION==040000

extern rad_module_t rlm_verify;
rad_module_t rlm_verify = {
	.magic		= RLM_MODULE_INIT,
	.name		= "verify",
	.type		= RLM_TYPE_THREAD_SAFE,
	.inst_size	= sizeof(rlm_verify_t),
	.config		= module_config,
	.instantiate	= mod_instantiate,
	.detach		= mod_detach,
	.methods = {
		[MOD_AUTHENTICATE]	= mod_authenticate,
		[MOD_AUTHORIZE]		= mod_authorize,
#ifdef WITH_ACCOUNTING
		[MOD_PREACCT]		= mod_preacct,
		[MOD_ACCOUNTING]	= mod_accounting,
		[MOD_SESSION]		= mod_checksimul
#endif
	},
};
	
#else

#if RADIUSD_VERSION==030013

extern module_t rlm_verify;
module_t rlm_verify = {
	.magic		= RLM_MODULE_INIT,
	.name		= "verify",
	.type		= RLM_TYPE_THREAD_SAFE,
	.inst_size	= sizeof(rlm_verify_t),
	.config		= module_config,
	.instantiate	= mod_instantiate,
	.detach		= mod_detach,
	.methods = {
		[MOD_AUTHENTICATE]	= mod_authenticate,
		[MOD_AUTHORIZE]		= mod_authorize,
#ifdef WITH_ACCOUNTING
		[MOD_PREACCT]		= mod_preacct,
		[MOD_ACCOUNTING]	= mod_accounting,
		[MOD_SESSION]		= mod_checksimul
#endif
	},
};

#endif
#if RADIUSD_VERSION==030004
module_t rlm_verify = {
	RLM_MODULE_INIT,
	"verify",
	RLM_TYPE_THREAD_SAFE,		/* type */
	sizeof(rlm_verify_t),
	module_config,
	mod_instantiate,		/* instantiation */
	mod_detach,			/* detach */
	{
		mod_authenticate,	/* authentication */
		mod_authorize,	/* authorization */
#ifdef WITH_ACCOUNTING
		mod_preacct,	/* preaccounting */
		mod_accounting,	/* accounting */
		mod_checksimul,	/* checksimul */
#else
		NULL, NULL, NULL,
#endif
		NULL,			/* pre-proxy */
		NULL,			/* post-proxy */
		NULL			/* post-auth */
	},
};
#endif


#endif
