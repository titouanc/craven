#include "craven.h"
#include "dsn.h"

#include <stdbool.h>
#include <string.h>
#include <stdlib.h>
#include <stdarg.h>
#include <stdio.h>
#include <time.h>

#include <curl/curl.h>

#define STORE_ENDPOINT_SIZE 3*DSN_FIELD_SIZE

struct CRaven {
    CRavenDsn dsn;
    CURL *curl;
};

static size_t craven_write_callback(char *p, size_t s, size_t n, void *u)
{
    return n;
}

CRaven *craven_connect(const char *dsn_string)
{
    CRavenDsn dsn;
    CRavenDsnError err = craven_dsn_parse(dsn_string, &dsn);
    if (err != CRAVEN_OK){
        fprintf(stderr, "Cannot parse DSN: %s\n", describe_dsn_error(err));
        return NULL;
    }

    CRaven *res = calloc(1, sizeof(CRaven));
    if (res == NULL){
        return NULL;
    }
    
    // Inactive client
    if (dsn.empty){
        return res;
    }

    memcpy(&res->dsn, &dsn, sizeof(CRavenDsn));

    curl_global_init(CURL_GLOBAL_ALL);
    res->curl = curl_easy_init();
    if (! res->curl){
        res->dsn.empty = true;
    } else {
        char store_endpoint[STORE_ENDPOINT_SIZE];
        craven_dsn_endpoint(&dsn, store_endpoint, STORE_ENDPOINT_SIZE);
        curl_easy_setopt(res->curl, CURLOPT_URL, store_endpoint);
        curl_easy_setopt(res->curl, CURLOPT_VERBOSE, 0L);
        curl_easy_setopt(res->curl, CURLOPT_WRITEFUNCTION, craven_write_callback);
    }

    return res;
}

void craven_event(CRaven *self,
                  const char *file, int line, const char *function,
                  const char *mesg, ...)
{
    va_list args;
    va_start(args, mesg);

    char *message = NULL;
    if (vasprintf(&message, mesg, args) <= 0){
        fprintf(stderr, "Cannot Allocate message string\n");
        return;
    }
    va_end(args);

    if (self == NULL){
        fprintf(stderr, "WARNING: INVALID CLIENT\n");
    }
    char sentry_auth[1024];
    snprintf(sentry_auth, sizeof(sentry_auth),
             "X-Sentry-Auth: Sentry sentry_version=7,"
             "sentry_timestamp=%d,"
             "sentry_key=%s,"
             "sentry_secret=%s,"
             "sentry_client=craven/1.0",
             (int) time(NULL), self->dsn.pubkey, self->dsn.privkey);

    struct curl_slist *headers = NULL;
    headers = curl_slist_append(headers, "User-Agent: craven/1.0");
    headers = curl_slist_append(headers, "Content-Type: application/json");
    headers = curl_slist_append(headers, sentry_auth);
    curl_easy_setopt(self->curl, CURLOPT_HTTPHEADER, headers);

    char *payload = NULL;
    asprintf(&payload,
             "{\"culprit\":\"%s\""
             ",\"stacktrace\":{\"frames\":["
             "{\"filename\":\"%s\""
             ",\"function\":\"%s\""
             ",\"module\":\"%s\""
             ",\"lineno\":%d}]}"
             ",\"message\":\"%s\"}",
             function, file, function, function, line, message);
    curl_easy_setopt(self->curl, CURLOPT_POSTFIELDS, payload);
    free(message);

    CURLcode res = curl_easy_perform(self->curl);
    if (res != CURLE_OK){
        fprintf(stderr, "CURL error when posting to sentry: %s\n",
                        curl_easy_strerror(res));
    }

    curl_slist_free_all(headers);
    free(payload);
}

void craven_close(CRaven *self)
{
    curl_easy_cleanup(self->curl);
    free(self);
}
