#include <stdlib.h>
#include "utils.h"

/* -1 -- not initialized
    0 -- logging is off
    1 -- logging is on
*/
int8_t _rnp_log_switch =
#ifdef NDEBUG
  -1 // lazy-initialize later
#else
  1 // always on in debug build
#endif
  ;

void
set_rnp_log_switch(int8_t value)
{
    _rnp_log_switch = value;
}

bool
rnp_log_switch()
{
    if (_rnp_log_switch < 0) {
        const char *var = getenv(RNP_LOG_CONSOLE);
        _rnp_log_switch = (var && strcmp(var, "0")) ? 1 : 0;
    }
    return !!_rnp_log_switch;
}
