package gorbac

import "sync"

func NewPermitDenyRole(id string) *PermitDenyRole {
	role := &PermitDenyRole{
		IDStr:       id,
		permissions: make(Permissions),
		denys:       NewStdRole(id),
	}
	return role
}

type PermitDenyRole struct {
	sync.RWMutex
	// IDStr is the identity of role
	IDStr       string `json:"id"`
	permissions Permissions
	denys       *StdRole
}

// ID returns the role's identity name.
func (role *PermitDenyRole) ID() string {
	return role.IDStr
}

// Assign a permission to the role.
func (role *PermitDenyRole) Assign(p Permission) error {
	role.Lock()
	role.permissions[p.ID()] = p
	role.Unlock()
	return nil
}

func (role *PermitDenyRole) Deny(p Permission) error {
	return role.denys.Assign(p)
}

// Permit returns true if the role has specific permission.
func (role *PermitDenyRole) Permit(p Permission) (rslt bool) {
	if p == nil {
		return false
	}
	if role.denys.reject(p) {
		return false
	}
	role.RLock()
	for _, rp := range role.permissions {
		if rp.Match(p) {
			rslt = true
			break
		}
	}
	role.RUnlock()
	return
}

// Revoke the specific permission.
func (role *PermitDenyRole) Revoke(p Permission) error {
	role.Lock()
	delete(role.permissions, p.ID())
	role.Unlock()
	return nil
}

// Permissions returns all permissions into a slice.
func (role *PermitDenyRole) Permissions() []Permission {
	role.RLock()
	result := make([]Permission, 0, len(role.permissions))
	for _, p := range role.permissions {
		result = append(result, p)
	}
	role.RUnlock()
	return result
}
