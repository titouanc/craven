#ifndef DEFINE_CRAVEN_DSN_HEADER
#define DEFINE_CRAVEN_DSN_HEADER

#include <stdbool.h>
#include <stdlib.h>

#define DSN_FIELD_SIZE 256

typedef struct {
    bool empty;
    char protocol[DSN_FIELD_SIZE];
    char pubkey[DSN_FIELD_SIZE];
    char privkey[DSN_FIELD_SIZE];
    char host[DSN_FIELD_SIZE];
    char path[DSN_FIELD_SIZE];
    unsigned int project_id;
} CRavenDsn;

typedef enum {
    CRAVEN_OK=0,
    CRAVEN_SYNTAX_ERROR,
    CRAVEN_UNKNOWN_PROTOCOL,
    CRAVEN_MISSING_PUBKEY,
    CRAVEN_MISSING_PRIVKEY,
    CRAVEN_MISSING_HOST,
    CRAVEN_MISSING_PROJECTID
} CRavenDsnError;

/**
 * @brief Like strerror but for CRavenDsnError
 * 
 * @param err The error
 * @return A description string (should not be freed)
 */
const char *describe_dsn_error(CRavenDsnError err);

/**
 * @brief Parse and validate a DSN string into a DSN structure
 * 
 * @param dsn The DSN string
 * @param parsed An allocated DSN structure which will hold the result
 * 
 * @return CRAVEN_OK on success, or an error code. If an error code is returned
 *         the parsed structure shall be considered invalid
 */
CRavenDsnError craven_dsn_parse(const char *dsn, CRavenDsn *parsed);

/**
 * @brief Write the endpoint URI to send events to from a DSN structure
 * 
 * @param dsn A valid DSN structure
 * @param endpoint The resulting string
 * @param n The size of the resulting string
 */
void craven_dsn_endpoint(const CRavenDsn *dsn, char *endpoint, size_t n);

/**
 * @brief Print informations contained in a DSN structure on stdout
 * 
 * @param dsn The DSN structure
 */
void craven_dsn_dump(const CRavenDsn *dsn);

#endif
