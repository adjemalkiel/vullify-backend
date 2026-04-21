package webhook

import (
	"encoding/json"
	"fmt"
	"strings"
)

// ParseDockerHubPush extracts repository path and tag from Docker Hub webhook JSON.
func ParseDockerHubPush(body []byte) (repository, tag string, err error) {
	var p struct {
		PushData struct {
			Tag string `json:"tag"`
		} `json:"push_data"`
		Repository struct {
			RepoName string `json:"repo_name"`
		} `json:"repository"`
	}
	if err := json.Unmarshal(body, &p); err != nil {
		return "", "", err
	}
	repository = strings.TrimSpace(p.Repository.RepoName)
	tag = strings.TrimSpace(p.PushData.Tag)
	if repository == "" || tag == "" {
		return "", "", fmt.Errorf("dockerhub: missing repository or tag")
	}
	return repository, tag, nil
}

// ParseGitHubContainer extracts image coordinates from GitHub package / registry_package webhooks.
func ParseGitHubContainer(body []byte) (repository, tag string, err error) {
	var root map[string]json.RawMessage
	if err := json.Unmarshal(body, &root); err != nil {
		return "", "", err
	}

	if b, ok := root["registry_package"]; ok {
		var rp struct {
			Name string `json:"name"`
		}
		if err := json.Unmarshal(b, &rp); err == nil {
			repository = strings.TrimSpace(strings.ToLower(rp.Name))
		}
	}
	if repository == "" {
		if b, ok := root["package"]; ok {
			var pkg struct {
				PackageType string `json:"package_type"`
				Name        string `json:"name"`
			}
			if err := json.Unmarshal(b, &pkg); err == nil {
				if pkg.PackageType == "" || strings.EqualFold(pkg.PackageType, "container") {
					repository = strings.TrimSpace(strings.ToLower(pkg.Name))
				}
			}
		}
	}

	if b, ok := root["package_version"]; ok {
		var pv struct {
			Version  string          `json:"version"`
			Metadata json.RawMessage `json:"metadata"`
		}
		if err := json.Unmarshal(b, &pv); err == nil {
			tag = strings.TrimSpace(pv.Version)
			if len(pv.Metadata) > 0 {
				var meta struct {
					Container struct {
						Tags []string `json:"tags"`
					} `json:"container"`
				}
				if err := json.Unmarshal(pv.Metadata, &meta); err == nil && len(meta.Container.Tags) > 0 {
					tag = strings.TrimSpace(meta.Container.Tags[0])
				}
			}
		}
	}

	if repository == "" || tag == "" {
		return "", "", fmt.Errorf("github: could not parse container repository and tag")
	}
	return repository, tag, nil
}

// ParseGitLabContainer extracts repository path and tag from GitLab container registry hooks.
func ParseGitLabContainer(body []byte) (repository, tag string, err error) {
	var root map[string]any
	if err := json.Unmarshal(body, &root); err != nil {
		return "", "", err
	}

	if et, _ := root["event_type"].(string); strings.EqualFold(et, "container_image_push") {
		if meta, ok := root["metadata"].(map[string]any); ok {
			if s, ok := meta["registry_path"].(string); ok {
				repository = strings.TrimSpace(s)
			}
			if s, ok := meta["tag"].(string); ok {
				tag = strings.TrimSpace(s)
			}
		}
	}

	if repository != "" && tag != "" {
		return repository, tag, nil
	}

	if rep, ok := root["repository"].(map[string]any); ok {
		if s, ok := rep["name"].(string); ok && repository == "" {
			repository = strings.TrimSpace(s)
		}
		if s, ok := rep["tag"].(string); ok && tag == "" {
			tag = strings.TrimSpace(s)
		}
	}
	if proj, ok := root["project"].(map[string]any); ok {
		if s, ok := proj["path_with_namespace"].(string); ok && repository == "" {
			repository = strings.TrimSpace(s)
		}
	}
	if s, ok := root["tag"].(string); ok && tag == "" {
		tag = strings.TrimSpace(s)
	}

	if repository == "" || tag == "" {
		return "", "", fmt.Errorf("gitlab: could not parse container repository and tag")
	}
	return repository, tag, nil
}
