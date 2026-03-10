package cmd

// Register all built-in policy generators via side-effect imports.
// This file is the single source of truth for generator registration;
// all other cmd files rely on these init() calls having run.
import (
	_ "github.com/AdmissionVet/admissionvet/internal/policy/gatekeeper/manifestvet"
	_ "github.com/AdmissionVet/admissionvet/internal/policy/gatekeeper/networkvet"
	_ "github.com/AdmissionVet/admissionvet/internal/policy/gatekeeper/rbacvet"
	_ "github.com/AdmissionVet/admissionvet/internal/policy/kyverno/imagepolicy"
	_ "github.com/AdmissionVet/admissionvet/internal/policy/kyverno/manifestvet"
	_ "github.com/AdmissionVet/admissionvet/internal/policy/kyverno/networkvet"
	_ "github.com/AdmissionVet/admissionvet/internal/policy/kyverno/rbacvet"
)
