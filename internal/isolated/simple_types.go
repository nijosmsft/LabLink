package isolated

import (
	"context"
	"errors"
	"fmt"

	"github.com/nijosmsft/lablink/internal/appliance"
)

const (
	MinimumApplianceSchema uint32 = 5
	MaximumApplianceSchema uint32 = 5
)

type DomainError struct {
	Code    string
	Message string
}

func (e *DomainError) Error() string {
	if e.Message == "" {
		return e.Code
	}
	return fmt.Sprintf("%s: %s", e.Code, e.Message)
}

func ErrorCode(err error) string {
	var domain *DomainError
	if errors.As(err, &domain) {
		return domain.Code
	}
	var store *appliance.StoreError
	if errors.As(err, &store) {
		return string(store.Code)
	}
	var compatibility *CompatibilityError
	if errors.As(err, &compatibility) {
		return compatibility.Code
	}
	return ""
}

type ApplianceClient interface {
	CheckReadiness(context.Context, string) (ApplianceReadiness, error)
	InspectApplianceState(context.Context, string) (ApplianceSnapshot, error)
	ConfigureStatic(
		context.Context,
		string,
		appliance.StaticConfig,
		[]appliance.RetiredNAT,
	) (ApplianceSnapshot, error)
	GetRelayStats(context.Context, string, string) (appliance.RelayStats, error)
	ValidateRelay(context.Context, string, string, bool) (RelayValidation, error)
}
