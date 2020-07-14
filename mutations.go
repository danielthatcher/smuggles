package main

// generateMutations returns a map of TE header mutations, indexed by name
func generateMutations() map[string]string {
	m := make(map[string]string, 0)
	m["standard"] = "Transfer-Encoding: chunked"
	m["lineprefix-space"] = " Transfer-Encoding: chunked"
	return m
}
