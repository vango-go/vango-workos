package workos

import "time"

// DisplayName returns "First Last", falling back to email if both are empty.
func (u *User) DisplayName() string {
	name := ""
	if u != nil {
		name = u.FirstName
		if u.LastName != "" {
			if name != "" {
				name += " "
			}
			name += u.LastName
		}
		if name == "" {
			return u.Email
		}
	}
	return name
}

func (i *Identity) IsExpired() bool {
	if i == nil {
		return true
	}
	return !i.ExpiresAt.IsZero() && time.Now().After(i.ExpiresAt)
}

func (i *Identity) HasPermission(perm string) bool {
	if i == nil || perm == "" {
		return false
	}
	for _, p := range i.Permissions {
		if p == perm {
			return true
		}
	}
	return false
}
