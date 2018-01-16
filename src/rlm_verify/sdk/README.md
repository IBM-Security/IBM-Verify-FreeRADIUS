# IBM Verify SDK for C

## Quick start
ISAM Verify SDK requires [libcurl](https://curl.haxx.se/libcurl/c/libcurl.html) and [cJSON](https://github.com/DaveGamble/cJSON)
```
#include <curl/curl.h>
#include "cJSON.h"
#include "isam.c"
```

## Interfaces 

int isam_initiate_policy_otp_simple(const char *host, const char *protocol, uint32_t port, const char *path, char const *apikey, char const *username, char const *additional);

## Policy response object methods

- Headers
- Code
- Success
- Body

## Contributing

## License 
Probably MIT since so much Open Source

