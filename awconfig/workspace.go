package awconfig

import (
	"errors"
	"os"
	"path/filepath"
	"strings"

	"gopkg.in/yaml.v3"
)

type WorktreeWorkspace struct {
	WorkspaceID     string `yaml:"workspace_id"`
	ProjectID       string `yaml:"project_id,omitempty"`
	ProjectSlug     string `yaml:"project_slug,omitempty"`
	RepoID          string `yaml:"repo_id,omitempty"`
	CanonicalOrigin string `yaml:"canonical_origin,omitempty"`
	Alias           string `yaml:"alias,omitempty"`
	HumanName       string `yaml:"human_name,omitempty"`
	Role            string `yaml:"role,omitempty"`
	Hostname        string `yaml:"hostname,omitempty"`
	WorkspacePath   string `yaml:"workspace_path,omitempty"`
	UpdatedAt       string `yaml:"updated_at,omitempty"`
}

func DefaultWorktreeWorkspaceRelativePath() string {
	return filepath.Join(".aw", "workspace.yaml")
}

func FindWorktreeWorkspacePath(startDir string) (string, error) {
	dir := filepath.Clean(startDir)
	for {
		awDir := filepath.Join(dir, ".aw")
		if info, err := os.Stat(awDir); err == nil && info.IsDir() {
			wsPath := filepath.Join(awDir, "workspace.yaml")
			if _, err := os.Stat(wsPath); err == nil {
				return wsPath, nil
			}
			return "", os.ErrNotExist
		}

		parent := filepath.Dir(dir)
		if parent == dir {
			break
		}
		dir = parent
	}
	return "", os.ErrNotExist
}

func LoadWorktreeWorkspaceFrom(path string) (*WorktreeWorkspace, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var state WorktreeWorkspace
	if err := yaml.Unmarshal(data, &state); err != nil {
		return nil, err
	}
	return &state, nil
}

func LoadWorktreeWorkspaceFromDir(startDir string) (*WorktreeWorkspace, string, error) {
	p, err := FindWorktreeWorkspacePath(startDir)
	if err != nil {
		return nil, "", err
	}
	state, err := LoadWorktreeWorkspaceFrom(p)
	if err != nil {
		return nil, "", err
	}
	return state, p, nil
}

func SaveWorktreeWorkspaceTo(path string, state *WorktreeWorkspace) error {
	if state == nil {
		return errors.New("nil workspace state")
	}

	data, err := yaml.Marshal(state)
	if err != nil {
		return err
	}

	return atomicWriteFile(path, append(bytesTrimRightNewlines(data), '\n'))
}

func WorktreeRootFromWorkspacePath(path string) string {
	if strings.TrimSpace(path) == "" {
		return ""
	}
	clean := filepath.Clean(path)
	base := filepath.Base(clean)
	if base == "workspace.yaml" {
		return filepath.Dir(filepath.Dir(clean))
	}
	return filepath.Dir(filepath.Dir(clean))
}
