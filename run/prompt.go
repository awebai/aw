package run

import "strings"

func IdentityPromptLabel(projectSlug string, canonicalOrigin string, repoOrigin string, alias string) string {
	projectSlug = strings.TrimSpace(projectSlug)
	shortRepo := ShortRepoName(canonicalOrigin, repoOrigin)
	alias = strings.TrimSpace(alias)
	if projectSlug == "" || alias == "" {
		return DefaultInputPromptLabel
	}
	if shortRepo == "" {
		return projectSlug + ":" + alias + "> "
	}
	return projectSlug + ":" + shortRepo + ":" + alias + "> "
}

func ShortRepoName(canonicalOrigin string, repoOrigin string) string {
	for _, candidate := range []string{canonicalOrigin, repoOrigin} {
		candidate = strings.TrimSpace(candidate)
		if candidate == "" {
			continue
		}
		candidate = strings.TrimSuffix(candidate, ".git")
		candidate = strings.TrimSuffix(candidate, "/")
		candidate = strings.TrimSuffix(candidate, ":")
		candidate = strings.ReplaceAll(candidate, "\\", "/")
		if idx := strings.LastIndex(candidate, "/"); idx >= 0 && idx < len(candidate)-1 {
			return candidate[idx+1:]
		}
		if idx := strings.LastIndex(candidate, ":"); idx >= 0 && idx < len(candidate)-1 {
			return candidate[idx+1:]
		}
	}
	return ""
}
