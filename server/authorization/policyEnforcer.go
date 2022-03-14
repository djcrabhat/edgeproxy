package authorization

import (
	"github.com/casbin/casbin/v2"
	log "github.com/sirupsen/logrus"
)

type PolicyEnforcer struct {
	Enforcer *casbin.Enforcer
}

func NewPolicyEnforer() *PolicyEnforcer {

	e, casbinErr := casbin.NewEnforcer("resources/rbac_model.conf", "resources/basic_policy.csv")
	if casbinErr != nil {
		log.Fatalf("cannot lot casbin: %v", casbinErr)
	}
	pe := &PolicyEnforcer{
		Enforcer: e,
	}
	return pe
}
