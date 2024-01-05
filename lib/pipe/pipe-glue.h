#ifndef __TELCO_PIPE_GLUE_H__
#define __TELCO_PIPE_GLUE_H__

#include "telco-pipe.h"

#define TELCO_TYPE_WINDOWS_PIPE_INPUT_STREAM (telco_windows_pipe_input_stream_get_type ())
#define TELCO_TYPE_WINDOWS_PIPE_OUTPUT_STREAM (telco_windows_pipe_output_stream_get_type ())

G_DECLARE_FINAL_TYPE (TelcoWindowsPipeInputStream, telco_windows_pipe_input_stream, TELCO, WINDOWS_PIPE_INPUT_STREAM, GInputStream)
G_DECLARE_FINAL_TYPE (TelcoWindowsPipeOutputStream, telco_windows_pipe_output_stream, TELCO, WINDOWS_PIPE_OUTPUT_STREAM, GOutputStream)

#endif
