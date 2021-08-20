package charger

// Code generated by github.com/andig/cmd/tools/decorate.go. DO NOT EDIT.

import (
	"github.com/andig/evcc/api"
)

func decorateOpenWB(base *OpenWB, chargePhases func(int) error) api.Charger {
	switch {
	case chargePhases == nil:
		return base

	case chargePhases != nil:
		return &struct {
			*OpenWB
			api.ChargePhases
		}{
			OpenWB: base,
			ChargePhases: &decorateOpenWBChargePhasesImpl{
				chargePhases: chargePhases,
			},
		}
	}

	return nil
}

type decorateOpenWBChargePhasesImpl struct {
	chargePhases func(int) error
}

func (impl *decorateOpenWBChargePhasesImpl) Phases1p3p(phases int) error {
	return impl.chargePhases(phases)
}