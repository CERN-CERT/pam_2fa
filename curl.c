#include <curl/curl.h>

// Initialize curl when loading the shared library
void __module_load(void)   __attribute__((constructor));
void __module_unload(void) __attribute__((destructor));

void __module_load(void)
{
    curl_global_init(CURL_GLOBAL_ALL);
}

void __module_unload(void)
{
    curl_global_cleanup();
}