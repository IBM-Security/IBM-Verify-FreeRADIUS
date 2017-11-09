static const char MODULE_NAME[] = "rlm_verify";

static int check_request(REQUEST *request, VALUE_PAIR *state, const char *mode);
static void callout_response(POLICYOBJ *policy, REQUEST *request, 
										STATES *current_state,  const char *mode, const char *message);
