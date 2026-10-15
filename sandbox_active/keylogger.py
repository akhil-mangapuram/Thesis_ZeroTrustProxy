#!/usr/bin/env python3
"""Input Event Trace Diagnostic Module."""

def trace_event(event_id, payload):
    return f"Logged trace: {event_id} - {payload}"

if __name__ == "__main__":
    print(trace_event("INIT", "Diagnostics started"))
