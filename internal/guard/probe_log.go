package guard

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"runtime"
	"sync"
	"sync/atomic"
	"time"
)

const probeLogLimit = 1 << 20

type probeLogger struct {
	mu                sync.Mutex // Never acquired while the service mutex is held.
	path, processID   string
	lastHealthSuccess time.Time
	closed            bool
}

var diagnosticSequence atomic.Uint64

func diagnosticID() string {
	var b [12]byte
	if _, e := rand.Read(b[:]); e == nil {
		return hex.EncodeToString(b[:])
	}
	return fmt.Sprintf("%x-%x", time.Now().UnixNano(), diagnosticSequence.Add(1))
}
func newProbeLogger(config string) *probeLogger {
	return &probeLogger{path: config + ".diagnostics.jsonl", processID: diagnosticID()}
}
func (l *probeLogger) marker(event string) {
	// The only callers supply these fixed lifecycle events.
	if event != "process_start" && event != "process_stop" {
		return
	}
	l.write(probeRecord{Version: 1, Event: event, Time: time.Now().UTC().Format(time.RFC3339Nano), ProcessID: l.processID})
}
func safeProbeLogFile(path string) (os.FileInfo, error) {
	info, e := os.Lstat(path)
	if e == nil && (!info.Mode().IsRegular() || runtime.GOOS != "windows" && info.Mode().Perm()&0077 != 0) {
		return nil, os.ErrPermission
	}
	return info, e
}
func (l *probeLogger) write(record probeRecord) {
	if l == nil {
		return
	}
	data, e := json.Marshal(record)
	if e != nil || len(data) > 32<<10 {
		return
	}
	data = append(data, '\n')
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.closed {
		return
	}
	// Seal the persistence boundary even when the stop marker cannot be saved.
	// Detached HTTP callbacks and cancelled workers may unwind afterwards.
	if record.Event == "process_stop" {
		l.closed = true
	}
	if record.Operation == "health" && record.Outcome == "success" {
		if !l.lastHealthSuccess.IsZero() && time.Since(l.lastHealthSuccess) < 30*time.Second {
			return
		}
		l.lastHealthSuccess = time.Now()
	}
	// Atomic private replacement avoids opening any writable destination through
	// a symlink, including a link swapped in after the metadata check.
	path, e := probeLogDirectory(l.path)
	if e != nil {
		return
	}
	info, e := safeProbeLogFile(path)
	if e != nil && !os.IsNotExist(e) {
		return
	}
	if _, e := safeProbeLogFile(path + ".1"); e != nil && !os.IsNotExist(e) {
		return
	}
	var previous []byte
	if info != nil && info.Size()+int64(len(data)) <= probeLogLimit {
		f, e := openProbeLog(path)
		if e != nil {
			return
		}
		opened, statErr := f.Stat()
		if statErr != nil || !os.SameFile(info, opened) || !opened.Mode().IsRegular() {
			f.Close()
			return
		}
		previous, e = io.ReadAll(io.LimitReader(f, probeLogLimit+1))
		f.Close()
		if e != nil || len(previous)+len(data) > probeLogLimit {
			return
		}
	}
	if info != nil && info.Size()+int64(len(data)) > probeLogLimit {
		// Copy only a bounded, validated file into a private atomic backup.
		if info.Size() <= probeLogLimit {
			f, err := openProbeLog(path)
			if err != nil {
				return
			}
			opened, err := f.Stat()
			if err != nil || !os.SameFile(info, opened) {
				f.Close()
				return
			}
			backup, err := io.ReadAll(io.LimitReader(f, probeLogLimit+1))
			f.Close()
			if err != nil || len(backup) > probeLogLimit || writeCredentialFile(path+".1", backup) != nil {
				return
			}
		}
	}
	_ = writeCredentialFile(path, append(previous, data...))
}

func openProbeLog(path string) (*os.File, error) {
	if credentialPersistenceSupported {
		return openCredentialRecord(path)
	}
	return os.Open(path)
}
