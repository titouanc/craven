#include "dsn.h"

#include <string.h>
#include <stdio.h>

const char *describe_dsn_error(CRavenDsnError err)
{
    switch (err){
        case CRAVEN_OK: return "OK";
        case CRAVEN_SYNTAX_ERROR: return "Syntax error";
        case CRAVEN_UNKNOWN_PROTOCOL: return "Unknown protocol";
        case CRAVEN_MISSING_PUBKEY: return "Missing public key";
        case CRAVEN_MISSING_PRIVKEY: return "Missing private key";
        case CRAVEN_MISSING_HOST: return "Missing host";
        case CRAVEN_MISSING_PROJECTID: return "Missing project id";
        default: return "Unknown error";
    }
}

static CRavenDsnError craven_dsn_validate(CRavenDsn *dsn)
{
    if (strcmp(dsn->protocol, "http") != 0 &&
        strcmp(dsn->protocol, "https") != 0){
        return CRAVEN_UNKNOWN_PROTOCOL;
    }

    if (strlen(dsn->pubkey) == 0){
        return CRAVEN_MISSING_PUBKEY;
    }

    if (strlen(dsn->privkey) == 0){
        return CRAVEN_MISSING_PRIVKEY;
    }

    if (strlen(dsn->host) == 0){
        return CRAVEN_MISSING_HOST;
    }

    return CRAVEN_OK;
}

CRavenDsnError craven_dsn_parse(const char *dsn, CRavenDsn *parsed)
{
    memset(parsed, 0, sizeof(CRavenDsn));

    if (strlen(dsn) == 0){
        parsed->empty = true;
        return CRAVEN_OK;
    }

    size_t pos = 0;
    while (pos < DSN_FIELD_SIZE-1 && dsn[pos] != '\0' && dsn[pos] != ':'){
        parsed->protocol[pos] = dsn[pos];
        pos++;
    }

    if (strncmp(dsn+pos, "://", 3) != 0){
        return CRAVEN_SYNTAX_ERROR;
    }

    size_t offset = pos+3;
    pos = 0;
    while (pos < DSN_FIELD_SIZE-1 && dsn[offset+pos] != '\0' && dsn[offset+pos] != ':'){
        parsed->pubkey[pos] = dsn[offset + pos];
        pos++;
    }

    if (dsn[offset + pos] != ':'){
        return CRAVEN_SYNTAX_ERROR;
    }

    offset += pos + 1;
    pos = 0;
    while (pos < DSN_FIELD_SIZE-1 && dsn[offset+pos] != '\0' && dsn[offset+pos] != '@'){
        parsed->privkey[pos] = dsn[offset + pos];
        pos++;
    }

    if (dsn[offset + pos] != '@'){
        return CRAVEN_SYNTAX_ERROR;
    }

    offset += pos + 1;
    pos = 0;
    while (pos < DSN_FIELD_SIZE-1 && dsn[offset+pos] != '\0' && dsn[offset+pos] != '/'){
        parsed->host[pos] = dsn[offset + pos];
        pos++;
    }

    if (dsn[offset + pos] != '/'){
        return CRAVEN_SYNTAX_ERROR;
    }

    offset += pos;
    pos = 0;
    while (pos < DSN_FIELD_SIZE-1 && dsn[offset+pos] != '\0'){
        parsed->path[pos] = dsn[offset + pos];
        pos++;
    }

    char *last_slash = strrchr(parsed->path, '/');
    if (last_slash[1] == '\0'){
        return CRAVEN_SYNTAX_ERROR;
    }

    char *endptr = last_slash + 1;
    parsed->project_id = strtol(last_slash+1, &endptr, 10);
    if (endptr == last_slash + 1){
        return CRAVEN_MISSING_PROJECTID;
    }
    last_slash[1] = '\0';

    return craven_dsn_validate(parsed);
}

void craven_dsn_endpoint(const CRavenDsn *dsn, char *endpoint, size_t n)
{
    snprintf(endpoint, n, "%s://%s%sapi/%d/store/",
                          dsn->protocol, dsn->host, dsn->path, dsn->project_id);
}

void craven_dsn_dump(const CRavenDsn *dsn)
{
    if (dsn->empty){
        printf("[EMPTY DSN]\n");
    } else {
        printf("DSN ::    protocol: %s\n"
               "    ::        host: %s\n"
               "    ::  public key: %s\n"
               "    :: private key: %s\n"
               "    ::        path: %s\n"
               "    ::  project ID: %d\n",
               dsn->protocol, dsn->host, dsn->pubkey,
               dsn->privkey, dsn->path, dsn->project_id);
    }
}
