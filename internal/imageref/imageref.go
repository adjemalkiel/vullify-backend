package imageref

import (
	"net/url"
	"strings"
)

// BuildImagePullRef builds a docker pull reference from registry URL and image coordinates.
func BuildImagePullRef(registryURL, repository, tag string) string {
	repository = strings.Trim(strings.TrimSpace(repository), "/")
	tag = strings.TrimSpace(tag)
	u, err := url.Parse(strings.TrimSpace(registryURL))
	if err != nil || u.Host == "" {
		if repository == "" {
			return tag
		}
		return repository + ":" + tag
	}
	return u.Host + "/" + repository + ":" + tag
}
