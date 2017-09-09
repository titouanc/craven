# C Raven

A minimalist GNU C99 client for [Sentry](https://sentry.io/) on top of libcurl.

## Usage

```C
#include "craven.h"

const char *dsn = "<your Sentry DSN>";

int main(int argc, const char **argv)
{
    CRaven *client = craven_connect(dsn);
    CRAVEN(client, "This is an exception");
    craven_close(client);
    return 0;
}

```

## Philosophy

As it would be impractical to handle errors from an error-reporting library,
most of the errors are handled internally and will be reported on stderr.

CRaven is _(currently)_...

* **Synchronous**: emitting an error to Sentry will block until the event has
  been handled by the server
* **Single-stack frame**: the only visible scope is the function directly
  enclosing the error
* **Explicit**: there is no silver bullet in C, catching errors is mostly
  programmer's responsiblity, hard errors like SIGSEV or SIGFPE cannot be
  catched without affecting the program behaviour
