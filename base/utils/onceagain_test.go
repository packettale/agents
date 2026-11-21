package utils

import (
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestOnceAgain(t *testing.T) {
	t.Parallel()

	const callers = 100
	var once OnceAgain
	var executions atomic.Int32

	for batch := range 10 {
		var callersDone sync.WaitGroup
		entered := make(chan struct{})
		release := make(chan struct{})

		callersDone.Go(func() {
			once.Do(func() {
				executions.Add(1)
				close(entered)
				<-release
			})
		})
		<-entered

		for range callers - 1 {
			callersDone.Go(func() {
				once.Do(func() { executions.Add(1) })
			})
		}

		// Let this execution finish once all callers have joined the same batch.
		deadline := time.Now().Add(5 * time.Second)
		for atomic.LoadInt32(&once.waiters) < callers && time.Now().Before(deadline) {
			time.Sleep(time.Millisecond)
		}
		joined := atomic.LoadInt32(&once.waiters)
		close(release)
		callersDone.Wait()

		if joined != callers {
			t.Fatalf("batch %d: got %d callers, want %d", batch+1, joined, callers)
		}
		if got, want := executions.Load(), int32(batch+1); got != want {
			t.Fatalf("batch %d: got %d executions, want %d", batch+1, got, want)
		}
	}
}
