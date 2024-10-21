// Windows service wrapper.

//go:build windows
// +build windows

package winsvc

import (
	"go.uber.org/zap"
	"golang.org/x/sys/windows/svc"
)

const (
	acceptedRequests = svc.AcceptStop | svc.AcceptShutdown | svc.AcceptPauseAndContinue
)

type Service struct {
	name string
	log  *zap.SugaredLogger
}

func NewService(name string, logger *zap.SugaredLogger) *Service {
	return &Service{
		name: name,
		log:  logger,
	}
}

func (s *Service) Execute(args []string, r <-chan svc.ChangeRequest, changes chan<- svc.Status) (bool, uint32) {
	s.log.Info("Service started")

	changes <- svc.Status{State: svc.Running, Accepts: acceptedRequests}

loop:
	for c := range r {
		switch c.Cmd {
		case svc.Interrogate:
			changes <- c.CurrentStatus
		case svc.Stop, svc.Shutdown:
			break loop
		case svc.Pause:
			changes <- svc.Status{State: svc.Paused, Accepts: acceptedRequests}
			s.log.Infof("Service paused")
		case svc.Continue:
			changes <- svc.Status{State: svc.Running, Accepts: acceptedRequests}
		default:
			s.log.Warnf("Unexpected control request #%d", c)
		}
	}

	changes <- svc.Status{State: svc.StopPending}
	s.log.Info("Service stopped")

	return false, 0
}

func (s *Service) Start() error {
	return svc.Run(s.name, s)
}
