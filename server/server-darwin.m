#include "server-darwin.h"

#include "darwin/policyd.h"

#import <Foundation/Foundation.h>

static volatile BOOL telco_run_loop_running = NO;

void
_telco_server_start_run_loop (void)
{
  NSRunLoop * loop = [NSRunLoop mainRunLoop];

  telco_run_loop_running = YES;
  while (telco_run_loop_running && [loop runMode:NSDefaultRunLoopMode beforeDate:[NSDate distantFuture]])
    ;
}

void
_telco_server_stop_run_loop (void)
{
  telco_run_loop_running = NO;
  CFRunLoopStop ([[NSRunLoop mainRunLoop] getCFRunLoop]);
}

gint
_telco_server_policyd_main (void)
{
  return telco_policyd_main ();
}
