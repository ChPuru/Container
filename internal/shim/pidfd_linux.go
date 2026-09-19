package shim

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"syscall"

	"golang.org/x/sys/unix"
)

// PidFD is a handle on a process that is immune to pid recycling.
//
// hull signals the container through this and never through kill(2): between
// reading a pid and signalling it, the process can exit and the kernel can
// hand the number to something else. With a pidfd the kernel guarantees the
// signal reaches that process or nothing at all (ESRCH).
//
// The same fd doubles as an exit notification: it becomes readable when the
// process dies, which lets the shim learn about the exit by polling rather
// than by racing its own SIGCHLD reaper for the wait status.
type PidFD struct {
	mu     sync.Mutex
	fd     int
	pid    int
	closed bool
}

// OpenPidFD opens a pidfd for pid. The process must still be alive; the shim
// opens it while the container's init is still parked in the runtime's create
// step, so there is no window in which the pid could be recycled.
func OpenPidFD(pid int) (*PidFD, error) {
	if pid <= 0 {
		return nil, fmt.Errorf("shim: cannot open a pidfd for pid %d", pid)
	}
	fd, err := unix.PidfdOpen(pid, 0)
	if err != nil {
		if errors.Is(err, unix.ENOSYS) {
			return nil, fmt.Errorf("shim: this kernel has no pidfd_open(2); hull needs Linux 5.3 or newer: %w", err)
		}
		return nil, fmt.Errorf("shim: pidfd_open(%d): %w", pid, err)
	}
	unix.CloseOnExec(fd)
	return &PidFD{fd: fd, pid: pid}, nil
}

// Pid reports the pid the handle was opened for. It is only meaningful while
// the process is alive.
func (p *PidFD) Pid() int { return p.pid }

// Signal delivers sig to the process. It returns an error wrapping
// unix.ESRCH once the process has been reaped.
func (p *PidFD) Signal(sig syscall.Signal) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.closed {
		return fmt.Errorf("shim: pidfd for %d is closed", p.pid)
	}
	if err := unix.PidfdSendSignal(p.fd, sig, nil, 0); err != nil {
		if errors.Is(err, unix.ENOSYS) {
			return fmt.Errorf("shim: this kernel has no pidfd_send_signal(2); hull needs Linux 5.1 or newer: %w", err)
		}
		return fmt.Errorf("shim: pidfd_send_signal(%d, %s): %w", p.pid, sig, err)
	}
	return nil
}

// Alive reports whether the process is still running, by sending signal 0.
func (p *PidFD) Alive() bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.closed {
		return false
	}
	err := unix.PidfdSendSignal(p.fd, 0, nil, 0)
	return err == nil
}

// Close releases the fd.
func (p *PidFD) Close() error {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.closed {
		return nil
	}
	p.closed = true
	if err := unix.Close(p.fd); err != nil {
		return fmt.Errorf("shim: close pidfd for %d: %w", p.pid, err)
	}
	return nil
}

// epollPollInterval bounds one epoll_wait so the watcher notices ctx
// cancellation promptly without a second wakeup fd.
const epollPollInterval = 250 // milliseconds

// WaitExit blocks until the process the pidfd refers to exits, or ctx is
// done.
//
// A pidfd signals EPOLLIN exactly once, when the process becomes a zombie or
// is reaped. Learning about the exit this way rather than from waitpid means
// the shim's continuously-running reaper cannot consume the notification out
// from under it — the reaper collects the status into its table, and the
// supervisor then looks it up.
func (p *PidFD) WaitExit(ctx context.Context) error {
	p.mu.Lock()
	fd, closed := p.fd, p.closed
	p.mu.Unlock()
	if closed {
		return fmt.Errorf("shim: pidfd for %d is closed", p.pid)
	}

	epfd, err := unix.EpollCreate1(unix.EPOLL_CLOEXEC)
	if err != nil {
		return fmt.Errorf("shim: epoll_create1: %w", err)
	}
	defer unix.Close(epfd)

	ev := unix.EpollEvent{Events: unix.EPOLLIN, Fd: int32(fd)}
	if err := unix.EpollCtl(epfd, unix.EPOLL_CTL_ADD, fd, &ev); err != nil {
		return fmt.Errorf("shim: epoll_ctl on pidfd for %d: %w", p.pid, err)
	}

	events := make([]unix.EpollEvent, 1)
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		n, err := unix.EpollWait(epfd, events, epollPollInterval)
		if err != nil {
			if errors.Is(err, unix.EINTR) {
				continue
			}
			return fmt.Errorf("shim: epoll_wait on pidfd for %d: %w", p.pid, err)
		}
		if n > 0 {
			return nil
		}
	}
}
