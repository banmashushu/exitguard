package nativeapp

// For our own known-live PID only: v1.18.8 process_api.c Process_Api_Query
// returns STATUS_INVALID_CID when no sandbox process entry exists. Other API
// errors remain unknown and cannot establish an ordinary application control.
func unboxedSelfQuery(status uintptr, err error) bool { return err == nil && status == 0xc000000b }
