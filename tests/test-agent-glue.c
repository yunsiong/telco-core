#include "telco-tests.h"

int telco_agent_test_script_dummy_global_to_trick_optimizer = 0;

guint
telco_agent_test_script_target_function (gint level, const gchar * message)
{
  guint bogus_result = 0, i;

  (void) level;
  (void) message;

  telco_agent_test_script_dummy_global_to_trick_optimizer += level;

  for (i = 0; i != 42; i++)
    bogus_result += i;

  telco_agent_test_script_dummy_global_to_trick_optimizer *= bogus_result;

  return bogus_result;
}

#ifdef HAVE_DARWIN

#include <gum/gumdarwin.h>

guint
telco_agent_test_script_get_current_thread_id (void)
{
  return pthread_mach_thread_np (pthread_self ());
}

void
telco_agent_test_script_thread_suspend (guint thread_id)
{
  thread_suspend (thread_id);
}

void
telco_agent_test_script_thread_resume (guint thread_id)
{
  thread_resume (thread_id);
}

#endif
