#ifndef DEFINE_CRAVEN_HEADER
#define DEFINE_CRAVEN_HEADER

typedef struct CRaven CRaven;

/**
 * @brief Create a C Raven client
 * 
 * @param dsn The dsn provided to connect to your Sentry project instance.
 *            The returned pointer must be freed with `craven_close`
 * @return A pointer to an initialized client, or NULL on error
 */
CRaven *craven_connect(const char *dsn);

/**
 * @brief Emit an error to Sentry
 * 
 * @param self An initialized client pointer
 * @param file The file in which the error occured
 * @param line The line in the file
 * @param mesg The error message (a printf-like format string)
 * @param ... The formatting arguments
 */
void craven_event(CRaven *self,
                  const char *file, int line, const char *function,
                  const char *mesg, ...);

/**
 * @brief Close a client
 * 
 * @param self An initialized client pointer. Invalid after this call
 */
void craven_close(CRaven *self);

/**
 * @brief Emit an error to Sentry, automaticllay fills in the file, line and
 *        enclosing function from the preprocessor
 * 
 * @param mesg The error message (a printf-like format string)
 * @param ... The formatting arguments
 */
#define CRAVEN(client, msg, ...) \
  craven_event(client, __FILE__, __LINE__, __FUNCTION__, msg, ##__VA_ARGS__)

#endif
