//go:build windows

package main

import (
	"fmt"
	"log"
	"os"
	"time"

	"github.com/nijosmsft/lablink/internal/security"
	"golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/eventlog"
	"golang.org/x/sys/windows/svc/mgr"
)

const serviceName = "LabLink Agent"
const serviceDisplayName = "LabLink Agent"
const serviceDescription = "gRPC agent for LabLink remote machine automation"

var legacyServiceNames = []string{"lablink-agent"}

// isWindowsService returns true if the process is running as a Windows service.
func isWindowsService() bool {
	ok, err := svc.IsWindowsService()
	if err != nil {
		return false
	}
	return ok
}

// agentService implements svc.Handler for running the agent as a Windows service.
type agentService struct {
	stopCh chan struct{}
}

func (s *agentService) Execute(args []string, r <-chan svc.ChangeRequest, changes chan<- svc.Status) (bool, uint32) {
	changes <- svc.Status{State: svc.StartPending}

	// Start the gRPC server in a goroutine.
	errCh := make(chan error, 1)
	go func() {
		errCh <- runServer()
	}()

	changes <- svc.Status{State: svc.Running, Accepts: svc.AcceptStop | svc.AcceptShutdown}

	for {
		select {
		case err := <-errCh:
			if err != nil {
				elog, _ := eventlog.Open(serviceName)
				if elog != nil {
					elog.Error(1, fmt.Sprintf("gRPC server failed: %v", err))
					elog.Close()
				}
				changes <- svc.Status{State: svc.StopPending}
				return false, 1
			}
			changes <- svc.Status{State: svc.StopPending}
			return false, 0
		case c := <-r:
			switch c.Cmd {
			case svc.Interrogate:
				changes <- c.CurrentStatus
			case svc.Stop, svc.Shutdown:
				changes <- svc.Status{State: svc.StopPending}
				close(s.stopCh)
				// Give the server a moment to shut down gracefully.
				time.Sleep(2 * time.Second)
				return false, 0
			}
		}
	}
}

// runAsService starts the agent as a Windows service.
// eventlogWriter wraps eventlog.Log to implement io.Writer for log.SetOutput.
type eventlogWriter struct {
	elog *eventlog.Log
}

func (w *eventlogWriter) Write(p []byte) (int, error) {
	err := w.elog.Info(1, string(p))
	return len(p), err
}

func runAsService() error {
	elog, err := eventlog.Open(serviceName)
	if err == nil {
		log.SetOutput(&eventlogWriter{elog: elog})
		defer elog.Close()
	}
	return svc.Run(serviceName, &agentService{stopCh: make(chan struct{})})
}

// installService registers the agent as a Windows service.
func installService(binPath string, port int, cfg security.ServerTransportConfig, tokenFile string) error {
	m, err := mgr.Connect()
	if err != nil {
		return fmt.Errorf("connect to service manager: %w", err)
	}
	defer m.Disconnect()

	// Check if service already exists.
	s, err := m.OpenService(serviceName)
	if err == nil {
		s.Close()
		return fmt.Errorf("service %q already exists — use --uninstall first", serviceName)
	}
	for _, legacyName := range legacyServiceNames {
		s, err := m.OpenService(legacyName)
		if err == nil {
			s.Close()
			return fmt.Errorf("legacy service %q already exists — uninstall it first before installing %q", legacyName, serviceName)
		}
	}

	exePath := binPath
	if exePath == "" {
		exePath, _ = os.Executable()
	}

	args := []string{"--listen", fmt.Sprintf(":%d", port), "--transport", string(cfg.Mode)}
	if tokenFile != "" {
		args = append(args, "--auth-token-file", tokenFile)
	}
	if cfg.Mode == security.TransportModeMTLS {
		args = append(args,
			"--tls-ca", cfg.CACertPath,
			"--tls-cert", cfg.CertPath,
			"--tls-key", cfg.KeyPath,
		)
	}

	s, err = m.CreateService(serviceName, exePath, mgr.Config{
		DisplayName: serviceDisplayName,
		Description: serviceDescription,
		StartType:   mgr.StartAutomatic,
	}, args...)
	if err != nil {
		return fmt.Errorf("create service: %w", err)
	}
	defer s.Close()

	// Create event log source.
	eventlog.InstallAsEventCreate(serviceName, eventlog.Error|eventlog.Warning|eventlog.Info)

	log.Printf("Service %q installed (auto-start, port %d)", serviceName, port)
	return nil
}

// uninstallService removes the Windows service.
func uninstallService() error {
	m, err := mgr.Connect()
	if err != nil {
		return fmt.Errorf("connect to service manager: %w", err)
	}
	defer m.Disconnect()

	candidates := append([]string{serviceName}, legacyServiceNames...)
	var (
		s           *mgr.Service
		serviceToRm string
	)
	for _, candidate := range candidates {
		s, err = m.OpenService(candidate)
		if err == nil {
			serviceToRm = candidate
			break
		}
	}
	if s == nil {
		return fmt.Errorf("open service: service %q not found", serviceName)
	}
	defer s.Close()

	// Stop if running.
	s.Control(svc.Stop)
	time.Sleep(2 * time.Second)

	if err := s.Delete(); err != nil {
		return fmt.Errorf("delete service: %w", err)
	}

	eventlog.Remove(serviceToRm)
	log.Printf("Service %q removed", serviceToRm)
	return nil
}
