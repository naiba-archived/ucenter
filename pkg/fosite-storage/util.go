package storage

import (
	"github.com/ory/fosite"
)

// IsArgEqual 判断fosite参数是否相同
func IsArgEqual(a, b fosite.Arguments) bool {

	// If one is nil, the other must also be nil.
	if (a == nil) != (b == nil) {
		return false
	}

	if len(a) != len(b) {
		return false
	}

	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}

	return true
}
