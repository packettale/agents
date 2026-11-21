package fstree

import "github.com/packettale/agents/base/database/storage"

// Compile time interface checks.
var _ storage.Interface = &FSTree{}
