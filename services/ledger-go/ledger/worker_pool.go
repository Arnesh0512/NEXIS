package ledger

import (
	"context"
	"fmt"
	"sync"
	"sync/atomic"
	"time"
)

// Job represents an asynchronous task dispatched to the worker pool.
type Job struct {
	ID        string
	Task      func(ctx context.Context) error
	CreatedAt time.Time
}

// WorkerPool manages a fixed set of goroutines consuming from a shared buffered channel.
type WorkerPool struct {
	maxWorkers      int
	jobQueue        chan Job
	wg              sync.WaitGroup
	ctx             context.Context
	cancel          context.CancelFunc
	activeWorkers   int32
	jobsCompleted   int64
	jobsFailed      int64
	isRunning       bool
	lifecycleMutex  sync.Mutex
}

// NewWorkerPool instantiates a worker pool with a given concurrency level.
func NewWorkerPool(workers int, queueCapacity int) *WorkerPool {
	ctx, cancel := context.WithCancel(context.Background())
	return &WorkerPool{
		maxWorkers: workers,
		jobQueue:   make(chan Job, queueCapacity),
		ctx:        ctx,
		cancel:     cancel,
	}
}

// Start spawns the worker goroutines.
func (wp *WorkerPool) Start() {
	wp.lifecycleMutex.Lock()
	defer wp.lifecycleMutex.Unlock()

	if wp.isRunning {
		return
	}
	wp.isRunning = true

	for i := 0; i < wp.maxWorkers; i++ {
		wp.wg.Add(1)
		go wp.workerRoutine(i)
	}
}

func (wp *WorkerPool) workerRoutine(workerID int) {
	defer wp.wg.Done()
	atomic.AddInt32(&wp.activeWorkers, 1)
	defer atomic.AddInt32(&wp.activeWorkers, -1)

	for {
		select {
		case <-wp.ctx.Done():
			return
		case job, ok := <-wp.jobQueue:
			if !ok {
				return
			}
			wp.executeJob(workerID, job)
		}
	}
}

func (wp *WorkerPool) executeJob(workerID int, job Job) {
	jobCtx, jobCancel := context.WithTimeout(wp.ctx, 30*time.Second)
	defer jobCancel()

	if err := job.Task(jobCtx); err != nil {
		atomic.AddInt64(&wp.jobsFailed, 1)
	} else {
		atomic.AddInt64(&wp.jobsCompleted, 1)
	}
}

// Submit enqueues a job into the worker pool.
func (wp *WorkerPool) Submit(id string, task func(ctx context.Context) error) error {
	if !wp.isRunning {
		return fmt.Errorf("worker pool is not running")
	}

	job := Job{
		ID:        id,
		Task:      task,
		CreatedAt: time.Now(),
	}

	select {
	case wp.jobQueue <- job:
		return nil
	default:
		return fmt.Errorf("job queue buffer is full")
	}
}

// Stop gracefully shuts down the worker pool, draining queued tasks.
func (wp *WorkerPool) Stop() {
	wp.lifecycleMutex.Lock()
	defer wp.lifecycleMutex.Unlock()

	if !wp.isRunning {
		return
	}

	close(wp.jobQueue)
	wp.cancel()
	wp.wg.Wait()
	wp.isRunning = false
}

// GetActiveWorkers returns current number of actively processing workers.
func (wp *WorkerPool) GetActiveWorkers() int32 {
	return atomic.LoadInt32(&wp.activeWorkers)
}

// GetStats returns telemetry metrics on worker throughput.
func (wp *WorkerPool) GetStats() map[string]interface{} {
	return map[string]interface{}{
		"max_workers":    wp.maxWorkers,
		"active_workers": atomic.LoadInt32(&wp.activeWorkers),
		"completed_jobs": atomic.LoadInt64(&wp.jobsCompleted),
		"failed_jobs":    atomic.LoadInt64(&wp.jobsFailed),
		"queue_capacity": cap(wp.jobQueue),
		"queue_depth":    len(wp.jobQueue),
	}
}
