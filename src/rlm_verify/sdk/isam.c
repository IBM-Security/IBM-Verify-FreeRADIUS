/**
 * $Id: 5acbecb64b88d31b25e0d25d81c1cf3b93a68f1b $
 * @file isam.c
 * @brief IBM ISAM FreeRadius Module Code. 
 *
 * @copyright 2017 The IBM ISAM FreeRADIUS server project
 * @copyright 2017 IBM Security
 * @author Jared Page jaredpa@au1.ibm.com
 */
// TODO change this ID
// RCSID("$Id: 5acbecb64b88d31b25e0d25d81c1cf3b93a68f1b $")

#include <curl/curl.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdbool.h>
#include "cJSON.h"
#include "isam.h"


// Define our struct for accepting LCs output
struct BufferStruct {
    char * buffer;
    size_t size;
};
 
struct WriteThis {
  const char *readptr;
  long sizeleft;
};

/*
 * Function:  ISAM_INIT 
 * --------------------
 * 
 * This function should be called at the initializaiton of your program 
 * (in main perhaps). This sets up the global variables, handles and threads
 * needed for the ISAM communications. 
 * Returns 0 on success, 1 if curl failed to init and 2 if the cleanup thread failed to start.
 *
 */
int ISAM_INIT()
{
    char METHOD_NAME[] = "ISAM_INIT()";
    printf("%s: >>>>>>>>>> Entering %s", ISAM_SDK_NAME, METHOD_NAME);

    CURLcode result = curl_global_init( CURL_GLOBAL_ALL );
    if (result != CURLE_OK) {
      fprintf(stderr, "%s: %s %s", ISAM_SDK_NAME, METHOD_NAME, curl_easy_strerror(result));
      return 1;
    }

    printf("%s: %s Starting cleanup thread", ISAM_SDK_NAME, METHOD_NAME);
    pthread_t pth;
    if (pthread_create(&pth,NULL,ISAM_SESSION_CLEANUP_THREAD,session_states)) {
      perror("Error starting cleanup thread");
      return 2;
    }

    printf("%s: %s Cleanup thread started", ISAM_SDK_NAME, METHOD_NAME);

    printf("%s: <<<<<<<<<< Exiting %s", ISAM_SDK_NAME, METHOD_NAME);

    return 0;
}

/*
 * Function:  ISAM_SHUTDOWN 
 * --------------------
 * 
 * This function should be called at the program shutdown. It makes sure memory 
 * and handles are cleared.
 * Returns 0 on success or 1 if curl failed to clean up.
 *
 */
void ISAM_SHUTDOWN()
{
    char METHOD_NAME[] = "ISAM_SHUTDOWN()";
    printf("%s: >>>>>>>>>> Entering %s", ISAM_SDK_NAME, METHOD_NAME);

    curl_global_cleanup();

    printf("%s: <<<<<<<<<< Exiting %s", ISAM_SDK_NAME, METHOD_NAME);
}

/*
 * Function:  ISAM_SESSION_CLEANUP_THREAD 
 * --------------------
 * Starts a background thread that cleans up older STATE structs stored in 
 * the session_states linked list. This uses the traverse linked list function
 * with the callback of ISAM_STATES_CLEANUP in isam.c.
 *
 *  arg: the session_states variable. Also a global in this case - so not used.
 *
 */
static void *ISAM_SESSION_CLEANUP_THREAD(void *arg)
{
    char METHOD_NAME[] = "ISAM_SESSION_CLEANUP_THREAD()";
    printf("%s: >>>>>>>>>> Entering %s", ISAM_SDK_NAME, METHOD_NAME);

    int result;
    if ((result = pthread_mutex_init(&lock, NULL)) != 0)
    {
        fprintf(stderr, "%s: %s Mutex init failed: %d\r\n", ISAM_SDK_NAME, METHOD_NAME, result);
        return NULL;
    }

    while(1){
        traverse(session_states, ISAM_STATES_CLEANUP);
        usleep(THREAD_INTERVAL_TIME*1000000);
    }

    printf("%s: <<<<<<<<<< Exiting %s", ISAM_SDK_NAME, METHOD_NAME);
    return NULL;
}

/*
 * Function:  ISAM_HOST_SET 
 * --------------------
 * Contructs a HOSTOBJ type struct with the required parameters for the 
 * ISAM policy callout. This is required for ISAM_POLICY_SET.
 *
 *  protocol: The protocol used to connect to the ISAM box. 'http' or 'https'.
 *  hostname: The hostname of the ISAM appliance web reverse proxy.
 *  port: The port of the ISAM appliance web reverse proxy.
 *  junction: The junction name of the ISAM AAC from the web reverse proxy.
 *  apikey: The credentials required to access the endpoint.
 *  insecure_ssl: Whether to ignore SSL validation errors.
 *
 *  returns: A struct of HOSTOBJ created from the given parameters.
 *
 */
HOSTOBJ *ISAM_HOST_SET(const char *protocol, const char *hostname, 
                            int port, const char *junction, const char *apikey, 
                                        const char **headers, bool insecure_ssl){
    char METHOD_NAME[] = "ISAM_HOST_SET()";
    printf("%s: >>>>>>>>>> Entering %s\r\n", ISAM_SDK_NAME, METHOD_NAME);

    HOSTOBJ* new_node = (HOSTOBJ*)malloc(sizeof(HOSTOBJ));
    if(new_node == NULL){
        fprintf(stderr,"%s: %s Error creating a new HOSTOBJ.\r\n", 
                                                    ISAM_SDK_NAME, METHOD_NAME);
        exit(0);
    }

    new_node->protocol = protocol;
    new_node->hostname = hostname;
    new_node->port = port;
    new_node->junction = junction;
    new_node->apikey = apikey;
    new_node->headers = headers;
    new_node->insecure_ssl = insecure_ssl;
    printf("%s: %s HOSTOBJ properties set.\r\n", ISAM_SDK_NAME, METHOD_NAME);
 
    printf("%s: <<<<<<<<<< Exiting %s\r\n", ISAM_SDK_NAME, METHOD_NAME);
    return new_node;
}

/*
 * Function:  ISAM_POLICY_SET 
 * --------------------
 * Contructs a POLICYOBJ type struct with the required parameters for the ISAM 
 * policy callout. This uses the ISAM_HOST_OBJ struct and is requried for 
 * ISAM_CALL_AUTH_POLICY
 *
 *  HOSTOBJ: The struct made in ISAM_HOST_SET.
 *  policyid: The ID of the ISAM Authentication Policy.
 *  method: The HTTP Method (GET/POST/PUT etc) of the request.
 *  headers: The headers object to pass along with each request.
 *  attributes: The attributes to send along with the request. The body/query.
 *  state: The current stae of the Policy. This will be NULL on creation. 
 *
 *  returns: A struct of POLICYOBJ created from the given parameters.
 *
 */
POLICYOBJ *ISAM_POLICY_SET(HOSTOBJ *hostobj, const char *policyid, 
        const char *method, char *attributes, char *state){
    char METHOD_NAME[] = "ISAM_POLICY_SET()";
    printf("%s: >>>>>>>>>> Entering %s\r\n", ISAM_SDK_NAME, METHOD_NAME);

    POLICYOBJ* new_node = (POLICYOBJ*)malloc(sizeof(POLICYOBJ));
    if(new_node == NULL){
        fprintf(stderr, "%s: %s Error creating a new POLICYOBJ.\r\n", 
                                                    ISAM_SDK_NAME, METHOD_NAME);
        exit(0);
    }

    new_node->host = hostobj;
    new_node->policyid = policyid;
    new_node->method = method;
    new_node->attributes = attributes;
    new_node->state = state;
    new_node->response = (POLICYRESPONSE*)malloc(sizeof(POLICYRESPONSE));
    printf("%s: %s POLICYOBJ properties set.\r\n", ISAM_SDK_NAME, METHOD_NAME);
 
    printf("%s: <<<<<<<<<< Exiting %s\r\n", ISAM_SDK_NAME, METHOD_NAME);
    return new_node;
}

/*
 * Function:  ISAM_CALL_AUTH_POLICY 
 * --------------------
 * This function delegates the callout to ISAM, and handles the actions once the 
 * payload and response are returned. The details are stored in the 
 * POLICYRESPONSE object inside the POLICYOBJ pointer struct. 
 * This function is the point of contact for making an ISAM Policy callout.
 *
 *  POLICYOBJ: The struct made in ISAM_POLICY_SET.
 *
 */
void ISAM_CALL_AUTH_POLICY(POLICYOBJ *policy){
    char METHOD_NAME[] = "ISAM_CALL_AUTH_POLICY()";
    printf("%s: >>>>>>>>>> Entering %s\r\n", ISAM_SDK_NAME, METHOD_NAME);

    if (policy){
        char *path;
        if (policy->state && strcmp(policy->state,"NEW") != 0){
            asprintf(&path, "%s/sps/apiauthsvc?StateId=%s",
                                        policy->host->junction, policy->state);
        }else{
            asprintf(&path, "%s/sps/apiauthsvc?PolicyId=%s",
                                    policy->host->junction, policy->policyid);
        }

        printf("%s: %s Callout properties set.\r\n", 
                                                ISAM_SDK_NAME, METHOD_NAME);

        POLICYRESPONSE *callout_response = http_callout(policy->host->hostname, 
            policy->host->protocol, policy->host->port, 
            path, policy->host->headers, policy->host->apikey, policy->method, policy->attributes, policy->host->insecure_ssl);

        if (callout_response){
            printf("%s: %s Callout response obtained. \r\n", 
                                                    ISAM_SDK_NAME, METHOD_NAME);
            printf("%s: %s Setting policy properties. \r\n", 
                                                    ISAM_SDK_NAME, METHOD_NAME);
            printf("%s: %s The HTTP status code: %d. \r\n", 
                            ISAM_SDK_NAME, METHOD_NAME, callout_response->code);
            if (callout_response->code < 299){
                callout_response->success = TRUE;
            }else{
                callout_response->success = FALSE;
            }

            char state[] = "state";
            policy->state = find_json_element(callout_response->payload, state);
            policy->response = callout_response;
        }else{
            fprintf(stderr, "%s: %s  This response isn't correct.", 
                                                    ISAM_SDK_NAME, METHOD_NAME);
        }
        FREE(path);
    }else{
        fprintf(stderr, "%s: %s Policy variable appeared to be NULL", 
                                                    ISAM_SDK_NAME, METHOD_NAME);
    }
    printf("%s: <<<<<<<<<< Exiting %s\r\n", ISAM_SDK_NAME, METHOD_NAME);
}

/*
 * Function:  http_callout 
 * --------------------
 * This is the function that actually makes the libcurl request to the ISAM 
 * policy endpoint. This is only called in ISAM_CALL_AUTH_POLICY.
 *
 *  host: The hostname of the ISAM appliance web reverse proxy.
 *  protocol: The protocol used to connect to the ISAM box. 'http' or 'https'.
 *  port: The port of the ISAM appliance web reverse proxy.
 *  path: The full path of the ISAM API policy. 
 *  apikey: The credentials required to access the endpoint.
 *  method: The HTTP Method (GET/POST/PUT etc) of the request.
 *  payload: The body to send along with the request.
 *
 * returns: POLICYRESPONSE struct with the body / codes of the response of the 
 * http callout. 
 *
 */
static POLICYRESPONSE *http_callout(const char *host, const char *protocol, 
                                    int port, 
                                    const char *path, 
                                    const char **headers,
                                    const char *apikey, 
                                    const char *method, 
                                    const char *payload,
                                    bool insecure_ssl){
    char METHOD_NAME[] = "http_callout()";
    printf("%s: >>>>>>>>>> Entering %s\r\n", ISAM_SDK_NAME, METHOD_NAME);

      POLICYRESPONSE* response =(POLICYRESPONSE*)malloc(sizeof(POLICYRESPONSE));
      CURL *curl;
      CURLcode res;
      response->payload = NULL;
      response->code = 000;

       //Stuff to send
      struct WriteThis writestruct;
 
      writestruct.readptr = payload;
      writestruct.sizeleft = (long)strlen(payload);

      //Stuff to recieve
      struct BufferStruct output; 
      output.buffer = NULL;
      output.size = 0;


      /* get a curl handle */ 
      curl = curl_easy_init();
      if(curl) {
            printf("%s: %s Curl is loaded. \r\n", ISAM_SDK_NAME, METHOD_NAME);

            struct curl_slist *curl_headers = NULL;

            int i = 0;
            while (headers[i] != NULL) {
                // char *header = *n++;
                char *header = headers[i];
                printf("\r\n>>>>>>>>>>>>>>>>>POLICYOBJ Printout. Headers: %s\r\n",
                             (header) ? header : "Empty");
                i++;
            }

            // TODO: these headers will likely be cut down
            curl_headers = curl_slist_append(curl_headers, "Accept: application/json");
            curl_headers = curl_slist_append(curl_headers, 
                                            "Content-Type: application/json");
            curl_headers = curl_slist_append(curl_headers, "charsets: utf-8");
            curl_headers = curl_slist_append(curl_headers, "Expect:");
            curl_headers = curl_slist_append(curl_headers, "Transfer-Encoding:");

            char *auth_header;
            asprintf(&auth_header, "Authorization: Basic %s", apikey);

            curl_headers = curl_slist_append(curl_headers, auth_header);

            char *length_header;
            asprintf(&length_header, "Content-Length: %ld",
                                                        (long)strlen(payload));

            curl_headers = curl_slist_append(curl_headers, length_header);

            printf("%s: %s After set headers.\r\n", ISAM_SDK_NAME, METHOD_NAME);

            char *connection_string;
            asprintf(&connection_string, "%s://%s:%d%s",
                                                    protocol, host, port, path);

            if (insecure_ssl) {
              curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 0L);
              printf("%s: %s Ignoring SSL for this connection\n", ISAM_SDK_NAME, METHOD_NAME);
            }

            /* First set the URL that is about to receive our POST. */ 
            curl_easy_setopt(curl, CURLOPT_URL, connection_string);

            printf("%s: %s The connection string: %s \r\n", 
                                ISAM_SDK_NAME, METHOD_NAME, connection_string);
         
            /* Now specify we want to POST data */ 
            if (strcmp(method, METHOD_PUT) == 0){
                curl_easy_setopt(curl, CURLOPT_PUT, 1L);
            }else{
                curl_easy_setopt(curl, CURLOPT_POST, 1L);
            }
            curl_easy_setopt(curl, CURLOPT_HTTPHEADER, curl_headers);
         
            printf("%s: %s After set method. \r\n", ISAM_SDK_NAME, METHOD_NAME);

            /* we want to use our own read function */ 
            curl_easy_setopt(curl, CURLOPT_READFUNCTION, read_callback);
         
            /* pointer to pass to our read function */ 
            curl_easy_setopt(curl, CURLOPT_READDATA, &writestruct);
            curl_easy_setopt(curl, CURLOPT_POSTFIELDSIZE, writestruct.sizeleft);   
            curl_easy_setopt(curl, CURLOPT_POSTFIELDS, payload);

            curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteMemoryCallback); 
            curl_easy_setopt(curl, CURLOPT_WRITEDATA, (void *)&output); 
         
            /* get verbose debug output please */ 
            curl_easy_setopt(curl, CURLOPT_VERBOSE, 1L);

            printf("%s: %s After read and write method callback set. \r\n", 
                                                    ISAM_SDK_NAME, METHOD_NAME);
            printf("%s: %s payload %s\r\n", ISAM_SDK_NAME,METHOD_NAME, payload);
            printf("%s: %s sizeleft %ld \r\n", ISAM_SDK_NAME,
                                             METHOD_NAME, writestruct.sizeleft);

            // /* Perform the request, res will get the return code */ 
            res = curl_easy_perform(curl);
            curl_slist_free_all(curl_headers);

            printf("%s: %s After cURL perform\r\n", ISAM_SDK_NAME, METHOD_NAME);
            /* Check for errors */ 
            if(res != CURLE_OK)
              fprintf(stderr, "%s: %s curl_easy_perform() failed: %s\n",
                      ISAM_SDK_NAME, METHOD_NAME, curl_easy_strerror(res));

            long http_code = 0;
            curl_easy_getinfo (curl, CURLINFO_RESPONSE_CODE, &http_code);
     
            printf("%s: %s Cleaning up the cURL handle. \r\n", 
                                                    ISAM_SDK_NAME, METHOD_NAME);

            /* always cleanup */ 
            curl_easy_cleanup(curl);

            asprintf(&response->payload, "%s",output.buffer);
            // TODO - why doesn't this work ?
            // asprintf(&response->code, "%d",http_code);
            response->code = http_code;

            printf("%s: %s The HTTP status code: %d. \r\n", 
                                    ISAM_SDK_NAME, METHOD_NAME, response->code);

            // response->code = http_code;

            if( output.buffer )
            {
                FREE ( output.buffer );
                output.buffer = 0;
                output.size = 0;
            }
      }

    printf("%s: <<<<<<<<<< Exiting %s\r\n", ISAM_SDK_NAME, METHOD_NAME);
    return response;
}

static size_t read_callback(void *ptr, size_t size, size_t nmemb, void *userp) {

    struct WriteThis *writestruct = (struct WriteThis *)userp;
 
    if(size*nmemb < 1)
        return 0;
 
    if(writestruct->sizeleft) {
        *(char *)ptr = writestruct->readptr[0]; /* copy one single byte */ 
        writestruct->readptr++;                 /* advance pointer */ 
        writestruct->sizeleft--;                /* less data left */ 
        return 1;                        /* we return 1 byte at a time! */ 
    }

    return 0;                          /* no more data left to deliver */ 
}
 
static size_t WriteMemoryCallback(void *ptr, size_t size, 
                                                    size_t nmemb, void *data){
    char METHOD_NAME[] = "WriteMemoryCallback()";
    printf("%s: >>>>>>>>>> Entering %s\r\n", ISAM_SDK_NAME, METHOD_NAME);

    size_t realsize = size * nmemb;

    struct BufferStruct * mem = (struct BufferStruct *) data;

    mem->buffer = (char*) realloc(mem->buffer, mem->size + realsize + 1);

    printf("%s: %s After memory reallocation \r\n", ISAM_SDK_NAME, METHOD_NAME);

    if ( mem->buffer )
    {
    memcpy( &( mem->buffer[ mem->size ] ), ptr, realsize );
    mem->size += realsize;
    mem->buffer[ mem->size ] = 0;
    }

    printf("%s: <<<<<<<<<< Exiting %s\r\n", ISAM_SDK_NAME, METHOD_NAME);
    return realsize;
}

/*
 * Function:  ISAM_POLICY_PRINT 
 * --------------------
 * This is a helpder function to assist in debugging or info. It prints out 
 * all the current attributes of the POLICYOBJ.
 *
 *  POLICYOBJ: The struct made in ISAM_POLICY_SET.
 *
 */
void ISAM_POLICY_PRINT(POLICYOBJ *policy){
    char METHOD_NAME[] = "ISAM_POLICY_PRINT()";
    printf("%s: >>>>>>>>>> Entering %s\r\n", ISAM_SDK_NAME, METHOD_NAME);

    if(policy){

        if (policy->host){
            printf("\r\n>>>>>>>>>>>>>>>>>HOSTOBJ Printout. Protocol: %s\r\n",
                 (policy->host->protocol) ? policy->host->protocol : "Empty");
            printf("\r\n>>>>>>>>>>>>>>>>>HOSTOBJ Printout. Hostname: %s\r\n",
                 (policy->host->hostname) ? policy->host->hostname : "Empty");
            printf("\r\n>>>>>>>>>>>>>>>>>HOSTOBJ Printout. Port: %d\r\n",
                 (policy->host->port) ? policy->host->port : 0);
            printf("\r\n>>>>>>>>>>>>>>>>>HOSTOBJ Printout. APIKey: %s\r\n",
                 (policy->host->apikey) ? policy->host->apikey : "Empty");
            printf("\r\n>>>>>>>>>>>>>>>>>HOSTOBJ Printout. Junction: %s\r\n",
                 (policy->host->junction) ? policy->host->junction : "Empty");
        }

        printf("\r\n>>>>>>>>>>>>>>>>>POLICYOBJ Printout. PolicyID: %s\r\n",
                         (policy->policyid) ? policy->policyid : "Empty");
        printf("\r\n>>>>>>>>>>>>>>>>>POLICYOBJ Printout. Method: %s\r\n",
                         (policy->method) ? policy->method : "Empty");

        int i = 0;
            printf("\r\n>>>>>>>>>>>>>>>>>123POLICYOBJ Printout. i: %d\r\n",
                         i);
        while (policy->host->headers[i] != NULL) {
            // char *header = *n++;
            char *header = policy->host->headers[i];
            printf("\r\n>>>>>>>>>>>>>>>>>POLICYOBJ Printout. Headers: %s\r\n",
                         (header) ? header : "Empty");
            i++;
        }
        i = 0;

        printf("\r\n>>>>>>>>>>>>>>>>>POLICYOBJ Printout. Attributes: %s\r\n",
                         (policy->attributes) ? policy->attributes : "Empty");
        printf("\r\n>>>>>>>>>>>>>>>>>POLICYOBJ Printout. State: %s\r\n",
                         (policy->state) ? policy->state : "Empty");

        if (policy->response){
          printf("\r\n>>>>>>>>>>>>POLICYRESPONSE Printout. Code: %d\r\n",
                 (policy->response->code) ? policy->response->code : 0);
          printf("\r\n>>>>>>>>>>>>POLICYRESPONSE Printout. Success: %d\r\n",
                 (policy->response->success) ? policy->response->success : 0);
          printf("\r\n>>>>>>>>>>>>POLICYRESPONSE Printout. Payload: %s\r\n",
            (policy->response->payload) ? policy->response->payload : "Empty");
        }

    }
    printf("%s: <<<<<<<<<< Exiting %s\r\n", ISAM_SDK_NAME, METHOD_NAME);
}

/*
 * Function:  ISAM_STATES_PRINT 
 * --------------------
 * This is a helpder function to assist in debugging or info. It prints out 
 * all the current attributes of the STATES struct given. This is one of the 
 * states in the linked list session_states.
 *
 *  STATES: The state you want to inspect. 
 *
 */
void ISAM_STATES_PRINT(STATES *cursor){
    char METHOD_NAME[] = "ISAM_STATES_PRINT()";
    printf("%s: >>>>>>>>>> Entering %s\r\n", ISAM_SDK_NAME, METHOD_NAME);

    if(cursor){
        printf("%s: Cursor Exists %s\r\n", ISAM_SDK_NAME, METHOD_NAME);

        if (cursor->username){
            printf("\r\n>>>>>>>>>>>>>>>>>USERNAME Printout: %s \r\n", 
                            (cursor->username) ? cursor->username : "Empty");
        }

        if (cursor->state_client){
            printf("\r\n>>>>>>>>>>>>>>>>>STATES_CLIENT Printout: %s \r\n", 
                    (cursor->state_client) ? cursor->state_client : "Empty");
        }

        if (cursor->creation_time){
            printf("\r\n>>>>>>>>>>>>>>>>>CREATION_TIME Printout: %s \r\n", 
            (cursor->creation_time) ? ctime(&cursor->creation_time) : "Empty");
        }

        ISAM_POLICY_PRINT(cursor->policy);
    }
    printf("%s: <<<<<<<<<< Exiting %s\r\n", ISAM_SDK_NAME, METHOD_NAME);
}

/*
 * Function:  ISAM_STATES_CLEANUP 
 * --------------------
 * This function checks the age of the given STATES object and, if it's too 
 * old (as defined by MAX_AGE_STATE) deletes it.
 * This function should be run in the background cleanup thread, however can be 
 * invoked manually too. 
 *
 *  STATES: The state you want to inspect. 
 *
 */
static void ISAM_STATES_CLEANUP(STATES *cursor){
    char METHOD_NAME[] = "ISAM_STATES_CLEANUP()";
    printf("%s: >>>>>>>>>> Entering %s\r\n", ISAM_SDK_NAME, METHOD_NAME);
    ISAM_STATES_PRINT(cursor);
    if(cursor){
        printf("%s: Cursor Exists %s\r\n", ISAM_SDK_NAME, METHOD_NAME);

        if (cursor->creation_time){

            time_t now;
            now = time(NULL);
            double seconds = difftime(now, cursor->creation_time);

            printf("\r\n>>>>>>>>>>>>>>>>>Age of state: %f \r\n", 
                                                    (seconds) ? seconds : 0);

            if (seconds > MAX_AGE_STATE){
                printf("\r\n>>>>>>>>>>>>>>>>>State is too old ! Removing\r\n");
                session_states = remove_any(session_states, cursor);                
            }
        }
    }
    printf("%s: <<<<<<<<<< Exiting %s\r\n", ISAM_SDK_NAME, METHOD_NAME);
}

/*
 * Function:  find_json_element 
 * --------------------
 * Get the value of the JSON attribute in a valid JSON stanza. 
 *
 *  body: The JSON body.
 *  property: The property you want to retrieve.
 * 
 * returns: The value of the key/value pair of the JSON attribute. 
 *
 */
char *find_json_element(const char *body, const char *property){
    char METHOD_NAME[] = "find_json_element()";
    printf("%s: >>>>>>>>>> Entering %s\r\n", ISAM_SDK_NAME, METHOD_NAME);

    printf("%s: %s Attempting to find: %s in %s\r\n", ISAM_SDK_NAME, 
                                                METHOD_NAME, property, body);

    cJSON * root = cJSON_Parse(body);
    char *rendered = (char*) malloc(sizeof(char));
    rendered = NULL;
    if (root) {
        printf("%s: %s Looks like a JSON string\r\n", ISAM_SDK_NAME, 
                                                                METHOD_NAME);
        cJSON *framerate_item;
        if (!property){
            printf("%s: %s Property is null\r\n", ISAM_SDK_NAME, METHOD_NAME);
            rendered = cJSON_Print(root);
        }else{
            printf("%s: %s Getting the property\r\n", ISAM_SDK_NAME, 
                                                                METHOD_NAME);
            framerate_item = cJSON_GetObjectItemCaseSensitive(root, property);
            if(framerate_item){
               rendered = cJSON_Print(framerate_item);
               remove_quotes_isam_old(rendered);
               // remove_char_isam(rendered, '"');
            }else{
                printf("%s: %s Didn't get property\r\n", ISAM_SDK_NAME, METHOD_NAME);
            }
        }
        printf("%s: %s Deleting the root\r\n", ISAM_SDK_NAME, METHOD_NAME);
        cJSON_Delete(root);
    }else{
        printf("Error\r\n");
    }

    printf("%s: <<<<<<<<<< Exiting %s\r\n", ISAM_SDK_NAME, METHOD_NAME);
    return rendered;
}

/*
 * Function:  remove_quotes_isam 
 * --------------------
 * Remove quotes from the beginning and end of a string. This is needed because
 * cJSON retrieves the JSON attributes with their quotes still around them. Ugh!
 *
 *  str: The string to remove quotes from 
 *
 */
static void  remove_quotes_isam_old(char *str) {
    size_t len = strlen(str);
    memcpy(str, str+1, len-2);
    str[len-2] = 0;
}

static char *remove_char_isam(char *p, int ch)
{
    char *ptr;

    while (ptr = strchr(p, ch))
        strcpy(ptr, ptr + 1);

    return p;
}

/*
 * Function:  create 
 * --------------------
 * Create a new STATES node. You must specify the next node, null if you are 
 * appending. 
 *  
 * state_client: The state of the client application to maintain. 
 * policy: The POLICYOBJ to actually store. 
 * username: The username against which to store it. 
 * creation_time: When this was created. 
 * next: The next node in the linked list. Null if you are appending. 
 * 
 * returns: the new STATES node. 
 *
 */
STATES *create(char *state_client, POLICYOBJ *policy, 
                    const char *username, time_t creation_time, STATES *next){
    STATES* new_node = (STATES*)malloc(sizeof(STATES));
    if(new_node == NULL){
        fprintf(stderr, "Error creating a new node in STATES.\n");
        exit(0);
    }
    if (state_client && policy && username){
        new_node->state_client = state_client;
        new_node->policy = policy;
        new_node->username = username;
        new_node->creation_time = creation_time;
        new_node->next = next;
    }else{

        fprintf(stderr, "Unable to create session state object.\n");
    }
 
    return new_node;
}

/*
 * Function:  prepend 
 * --------------------
 * Prepends a new STATES node. You must specify the next node, null if you are 
 * appending. 
 *  
 * head: The node to prepend it to.
 * state_client: The state of the client application to maintain. 
 * policy: The POLICYOBJ to actually store. 
 * username: The username against which to store it. 
 * creation_time: When this was created. 
 * 
 * returns: the new STATES node. 
 */
STATES* prepend(STATES *head, char *state_client, 
                POLICYOBJ *policy, const char *username, time_t creation_time){
    pthread_mutex_lock(&lock);
    STATES *new_node = create(state_client, policy, username, 
                                                    creation_time, head);
    head = new_node;
    pthread_mutex_unlock(&lock);
    return head;
}

/*
 * Function:  append 
 * --------------------
 * Appends a new STATES node. You must specify the next node, null if you are 
 * appending. 
 *  
 * head: The head node of the linked list to append it to.
 * state_client: The state of the client application to maintain. 
 * policy: The POLICYOBJ to actually store. 
 * username: The username against which to store it. 
 * creation_time: When this was created. 
 * 
 * returns: the new STATES node. 
 */
STATES* append(STATES* head, char *state_client, 
                POLICYOBJ *policy, char *username, time_t creation_time)
{
    pthread_mutex_lock(&lock);
    printf("In append function.\n");
    if (head != NULL){
        /* go to the last node */
        STATES *cursor = head;
        while(cursor->next != NULL){

            printf("Looping.\n");
            cursor = cursor->next;
        }
     
        printf("In append function - creating\n");
        /* create a new node */
        STATES* new_node =  create(state_client, policy, 
                                        username,creation_time, NULL);
        cursor->next = new_node;
     
        printf("In append function - returning.\n");
        pthread_mutex_unlock(&lock);
        return head;
    }else{
    printf("In append function - was null\n");
        STATES* new_node =  create(state_client, policy, 
                                                username,creation_time, NULL);
        pthread_mutex_unlock(&lock);
        return new_node;
    }
}

/*
 * Function:  insert_after 
 * --------------------
 * Inserts a new STATES node. You must specify the next node, null if you are 
 * appending. 
 *  
 * state_client: The state of the client application to maintain. 
 * policy: The POLICYOBJ to actually store. 
 * username: The username against which to store it. 
 * creation_time: When this was created. 
 * prev: The node of the linked list you want to insert after.
 * 
 * returns: the new STATES node. 
 */
STATES* insert_after(STATES *head, char *state_client, 
    POLICYOBJ *policy, char *username, time_t creation_time, STATES* prev)
{
    /* find the prev node, starting from the first node*/
    STATES *cursor = head;
    while(cursor != prev)
        cursor = cursor->next;
 
    if(cursor != NULL)
    {
        STATES* new_node = create(state_client, policy, username, 
                                                creation_time, cursor->next);
        cursor->next = new_node;
        return head;
    }
    else
    {
        return NULL;
    }
}

/*
 * Function:  insert_before 
 * --------------------
 * Inserts a new STATES node. You must specify the next node, null if you are 
 * appending. 
 *  
 * state_client: The state of the client application to maintain. 
 * policy: The POLICYOBJ to actually store. 
 * username: The username against which to store it. 
 * creation_time: When this was created. 
 * nxt: The node of the linked list you want to insert before.
 * 
 * returns: the new STATES node. 
 */
STATES* insert_before(STATES *head, char *state_client, 
    POLICYOBJ *policy, char *username, time_t creation_time, STATES* nxt)
{
    if(nxt == NULL || head == NULL)
        return NULL;
 
    if(head == nxt)
    {
        head = prepend(head, state_client, policy, username, creation_time);
        return head;
    }
 
    /* find the prev node, starting from the first node*/
    STATES *cursor = head;
    while(cursor != NULL)
    {
        if(cursor->next == nxt)
            break;
        cursor = cursor->next;
    }
 
    if(cursor != NULL)
    {
        STATES* new_node = create(state_client, policy, 
                                        username, creation_time, cursor->next);
        cursor->next = new_node;
        return head;
    }
    else
    {
        return NULL;
    }
}

/*
 * Function:  reverse 
 * --------------------
 * Reverse the order of the session_states list.
 *  
 * head: The head of the linked list you want to reverse. 
 * 
 * returns: the new STATES head node. 
 */
STATES* reverse(STATES* head)
{
    STATES* prev    = NULL;
    STATES* current = head;
    STATES* next;
    while (current != NULL)
    {
        next  = current->next;
        current->next = prev;
        prev = current;
        current = next;
    }
    head = prev;
    return head;
}

/*
 * Function:  remove_front 
 * --------------------
 * Removes the first STATES node.
 *  
 * head: The head node of the linked list you want to remove. 
 * 
 * returns: the new STATES node head. 
 */
STATES* remove_front(STATES* head)
{
    char METHOD_NAME[] = "remove_front()";
    printf("%s: >>>>>>>>>> Entering %s\r\n", ISAM_SDK_NAME, METHOD_NAME);
    if(head == NULL)
        return NULL;
    STATES *front = head;
    head = head->next;
    front->next = NULL;
    /* is this the last node in the list */
    if(front == head)
        head = NULL;
    FREE(front);
    printf("%s: <<<<<<<<<< Exiting %s\r\n", ISAM_SDK_NAME, METHOD_NAME);
    return head;
}

/*
 * Function:  remove_back 
 * --------------------
 * Removes the last STATES node.
 *  
 * head: The head node of the linked list you want to remove the end of.
 * 
 * returns: the new STATES node head. 
 */
STATES* remove_back(STATES* head)
{
    char METHOD_NAME[] = "remove_back()";
    printf("%s: >>>>>>>>>> Entering %s\r\n", ISAM_SDK_NAME, METHOD_NAME);
    if(head == NULL)
        return NULL;
 
    STATES *cursor = head;
    STATES *back = NULL;
    while(cursor->next != NULL)
    {
        back = cursor;
        cursor = cursor->next;
    }
    if(back != NULL)
        back->next = NULL;
 
    /* if this is the last node in the list*/
    if(cursor == head)
        head = NULL;
 
    FREE(cursor);
 
    printf("%s: <<<<<<<<<< Exiting %s\r\n", ISAM_SDK_NAME, METHOD_NAME);
    return head;
}

/*
 * Function:  remove_any 
 * --------------------
 * Removes the a specific STATES node.
 *  
 * head: The head node of the linked list you want to remove something from.
 * nd: The specific node you want to remove.
 * 
 * returns: the new STATES node head. 
 */
STATES* remove_any(STATES* head,STATES* nd)
{
    char METHOD_NAME[] = "remove_any()";
    printf("%s: >>>>>>>>>> Entering %s\r\n", ISAM_SDK_NAME, METHOD_NAME);
    pthread_mutex_lock(&lock);
    /* if the node is the first node */
    if(nd == head)
    {
        head = remove_front(head);
        pthread_mutex_unlock(&lock);
        return head;
    }
 
    /* if the node is the last node */
    if(nd->next == NULL)
    {
        head = remove_back(head);
        pthread_mutex_unlock(&lock);
        return head;
    }
 
    printf("%s: >>>>>>>>>> Node is in the middle %s\r\n", 
                                                ISAM_SDK_NAME, METHOD_NAME);
    /* if the node is in the middle */
    STATES* cursor = head;
    while(cursor != NULL)
    {
        if(cursor->next == nd)
            break;
        cursor = cursor->next;
    }
 
    if(cursor != NULL)
    {
        STATES* tmp = cursor->next;
        cursor->next = tmp->next;
        tmp->next = NULL;
        FREE(tmp);
    }
    pthread_mutex_unlock(&lock);
    printf("%s: <<<<<<<<<< Exiting %s\r\n", ISAM_SDK_NAME, METHOD_NAME);
    return head;
}

/*
 * Function:  dispose 
 * --------------------
 * Free the memory stored by the linked list.
 *  
 * head: The head node of the linked list you want to free.
 */
static void dispose(STATES *head)
{
    STATES *cursor, *tmp;
 
    if(head != NULL)
    {
        cursor = head->next;
        head->next = NULL;
        while(cursor != NULL)
        {
            tmp = cursor->next;
            FREE(cursor);
            cursor = tmp;
        }
    }
}

/*
 * Function:  traverse 
 * --------------------
 * Step throught the linked list and call a function, passing the node.
 *  
 * head: The head node of the linked list you want to step through.
 * f: The function you want to pass each node to. 
 */
static void traverse(STATES *head,callback f){
    char METHOD_NAME[] = "traverse()";
    printf("%s: >>>>>>>>>> Entering %s \r\n", ISAM_SDK_NAME, METHOD_NAME);

    STATES *cursor = head;
    while(cursor != NULL)
    {
        f(cursor);
        cursor = cursor->next;
    }

    printf("%s: <<<<<<<<<<< Exiting %s \r\n", ISAM_SDK_NAME, METHOD_NAME);
}

/*
 * Function:  search 
 * --------------------
 * Step throught the linked list and search for a node with a specific username 
 * and state. 
 *  
 * head: The head node of the linked list you want to step through.
 * username: The username to search for.
 * search_state: The client state value to search for. 
 *
 * returns: the STATES struct of a matching object. 
 *
 */
STATES *search(STATES *head, const char *username,
                                                    const char *search_state){
    char METHOD_NAME[] = "search()";
    printf("%s: >>>>>>>>>> Entering %s \r\n", ISAM_SDK_NAME, METHOD_NAME);
    STATES *cursor = head;
    while(cursor != NULL)
    {
        printf("%s: %s >>>>>>>>>> Looking for: %s : %s \r\n", 
                            ISAM_SDK_NAME, METHOD_NAME, username, search_state);
        printf("%s: %s >>>>>>>>>> Search Result: %s : %s \r\n", 
            ISAM_SDK_NAME, METHOD_NAME, cursor->username, cursor->state_client);
        if ((strcmp(cursor->state_client, search_state) == 0 && 
            strcmp(cursor->username, username) == 0 ) || 
            (cursor->state_client == search_state && 
                strcmp(cursor->username, username) == 0 ) ){
            printf("%s: %s >>>>>>>>>> FOUND!: %s : %s \r\n", ISAM_SDK_NAME, 
                                           METHOD_NAME, username, search_state);
            return cursor;
        }else{
            cursor = cursor->next;
        }
    }
    printf("%s: <<<<<<<<<< Exiting %s \r\n", ISAM_SDK_NAME, METHOD_NAME);
    return NULL;
}

/*
 * Function:  count_states 
 * --------------------
 * Count the number of states in the linked list session_states. 
 *
 *  head: The head of the session_states list. 
 * 
 *  returns: The integer of the count
 *
 */
int count_states(STATES *head){
    STATES *cursor = head;
    int c = 0;
    while(cursor != NULL)
    {
        c++;
        cursor = cursor->next;
    }
    return c;
}

/*
 * Function:  strcat_isam 
 * --------------------
 * Given two char pointers, append them to each other. The first char pointer 
 * given will have the appended string. Why isn't this a standard C function !?
 *
 *  s: The char array to be appended to.
 *  t: The char array you want appended on the end. 
 * 
 *  returns: The length of the new char array.
 *
 */
int strcat_isam(char *s,const char *t){        
   pthread_mutex_lock(&lock);
   for(;*s!='\0';s++){
   }
   while((*s++ = *t++)!='\0'){        
   }
   // *t='\0';
   pthread_mutex_unlock(&lock);
   return 0;
}
