package rules

// Default returns the registry with every built-in rule pack loaded.
//
// Packs are independent slices so a caller (or a test) can load a subset, and
// so parallel work on a pack cannot silently change another pack's behaviour.
func Default() *Registry {
	r := NewRegistry()
	r.Add(SecretsRules()...)
	r.Add(InjectionRules()...)
	r.Add(CryptoRules()...)
	r.Add(AuthRules()...)
	r.Add(WebRules()...)
	r.Add(ConfigRules()...)
	r.Add(CIRules()...)
	r.Add(DependencyRules()...)
	r.Add(PackCRules()...)
	r.Add(AntiRERules()...)
	return r
}
