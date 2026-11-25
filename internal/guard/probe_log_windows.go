package guard

func probeLogDirectory(path string) (string, error) {
	path, parents, err := lockCredentialParents(path, true)
	if err == nil {
		parents.close()
	}
	return path, err
}
