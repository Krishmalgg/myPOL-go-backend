package domain

import "fmt"

// Permission is what a canvas session may do, as carried in the token's `perm`
// claim. The vocabulary is fixed by the .NET issuer; Go enforces it but never
// derives it, because the permission model lives in Postgres where Go has no
// access.
type Permission string

const (
	PermissionView    Permission = "view"
	PermissionComment Permission = "comment"
	PermissionEdit    Permission = "edit"
	PermissionOwner   Permission = "owner"
)

// ParsePermission converts a claim value, rejecting anything unrecognised
// rather than defaulting. An unknown permission must never be treated as a
// usable one.
func ParsePermission(value string) (Permission, error) {
	switch Permission(value) {
	case PermissionView:
		return PermissionView, nil
	case PermissionComment:
		return PermissionComment, nil
	case PermissionEdit:
		return PermissionEdit, nil
	case PermissionOwner:
		return PermissionOwner, nil
	default:
		return "", fmt.Errorf("%w: %q", ErrInvalidPermission, value)
	}
}

// Valid reports whether the permission is one this service recognises.
func (p Permission) Valid() bool {
	_, err := ParsePermission(string(p))
	return err == nil
}

// CanDraw reports whether this permission may produce ink or move blocks.
// Viewers and commenters may observe a canvas and be present on it, but may not
// change it.
func (p Permission) CanDraw() bool {
	return p == PermissionEdit || p == PermissionOwner
}

func (p Permission) String() string { return string(p) }
