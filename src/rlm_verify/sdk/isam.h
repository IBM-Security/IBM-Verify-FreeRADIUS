#include <time.h>
#include <pthread.h>
#include <stdbool.h>

#define FREE(ptr) do { \
	free((ptr));	\
	ptr = NULL;		\
}while(0)

#define TRUE 1
#define FALSE 0
#define THREAD_INTERVAL_TIME 10
#define MAX_AGE_STATE 60

typedef struct isam_host_appliance_object
{
	const char *protocol;
	const char *hostname; 
	int port;
	const char *junction;
	const char *apikey;
	const char **headers;
	bool insecure_ssl;
} HOSTOBJ;

typedef struct isam_authentication_policy_response_object
{
	int code;
	int success;
	char *payload;	
} POLICYRESPONSE;

typedef struct isam_authentication_policy_object
{
	HOSTOBJ *host;
	const char *policyid;
	const char *method;
	char *attributes;
	char *state;
	POLICYRESPONSE *response;
} POLICYOBJ;

typedef struct isam_global_states
{
	char *state_client;
	POLICYOBJ *policy;
	const char *username;
	time_t creation_time;
    struct isam_global_states *next;
} STATES;

static STATES *session_states;

static const char ISAM_SDK_NAME[] = "isam.c";
static const char OTP_SUCCESS_MESSAGE[] = "success";
static const char OTP_ERROR_MESSAGE[] = 
					"FBTOTP304E The submitted one-time password is not valid.";
static const char METHOD_PUT[] = "PUT";

static const int REQUEST_SIZE = 8196;

//ISAM policy functions
int ISAM_INIT(void);
void ISAM_SHUTDOWN(void);
HOSTOBJ *ISAM_HOST_SET(const char *protocol, const char *hostname, 
							int port, const char *junction, const char *apikey,
							const char **headers, bool insecure_ssl);
POLICYOBJ *ISAM_POLICY_SET(HOSTOBJ *hostobj, const char *policyid, 
		const char *method, char *attributes, char *state);
void ISAM_CALL_AUTH_POLICY(POLICYOBJ *policy);
void ISAM_STATES_PRINT(STATES *cursor);
void ISAM_POLICY_PRINT(POLICYOBJ *policy);
static void ISAM_STATES_CLEANUP(STATES *cursor);

//Session state thread
static pthread_mutex_t lock;
static void *ISAM_SESSION_CLEANUP_THREAD(void *arg);

static size_t WriteMemoryCallback(void *ptr, size_t size, 
                                                    size_t nmemb, void *data);
static size_t read_callback(void *ptr, size_t size, size_t nmemb, void *userp);
static POLICYRESPONSE *http_callout(const char *host, const char *protocol, 
                            int port, const char *path, const char **headers, 
                            const char *apikey, const char *method, 
                            const char *payload, bool insecure_ssl);
//Linked list state functions
STATES *create(char *state_client, POLICYOBJ *policy, 
					const char *username, time_t creation_time, STATES *next);
STATES* prepend(STATES *head, char *state_client, 
				POLICYOBJ *policy, const char *username, time_t creation_time);
STATES* append(STATES* head, char *state_client, 
				POLICYOBJ *policy, char *username, time_t creation_time);
STATES* insert_after(STATES *head, char *state_client, 
   POLICYOBJ *policy, char *username, time_t creation_time, STATES* prev);
STATES* insert_before(STATES *head, char *state_client,
    POLICYOBJ *policy, char *username, time_t creation_time, STATES* nxt);
STATES* insertion_sort(STATES* head);
STATES* reverse(STATES* head);
STATES* remove_front(STATES* head);
STATES* remove_back(STATES* head);
STATES* remove_any(STATES* head,STATES* nd);
static void dispose(STATES *head);
typedef void (*callback)(STATES *data);
static void traverse(STATES* head,callback f);
STATES *search(STATES *head, const char *username, 
													  const char *search_state);
int count_states(STATES *head);

// Random helper functions
int strcat_isam(char *s,const char *t);
char *find_json_element(const char *body, const char *property);
static void remove_quotes_isam_old(char *str);
static char *remove_char_isam(char *p, int ch);
