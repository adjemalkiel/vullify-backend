package registry

import (
	"context"
	"encoding/base64"
	"fmt"
	"sort"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/ecr"
	"github.com/aws/aws-sdk-go-v2/service/ecr/types"
)

// ECRCredentials configures AWS ECR using static keys (or leave empty for default chain).
type ECRCredentials struct {
	Region          string `json:"region"`
	AccessKeyID     string `json:"access_key_id"`
	SecretAccessKey string `json:"secret_access_key"`
	SessionToken    string `json:"session_token,omitempty"`
}

// ECR implements RegistryConnector using aws-sdk-go-v2 ECR APIs.
type ECR struct {
	creds ECRCredentials
}

// NewECR returns an ECR connector.
func NewECR(c ECRCredentials) *ECR {
	return &ECR{creds: c}
}

func (e *ECR) awsConfig(ctx context.Context) (aws.Config, error) {
	opts := []func(*config.LoadOptions) error{
		config.WithRegion(e.creds.Region),
	}
	if e.creds.AccessKeyID != "" {
		opts = append(opts, config.WithCredentialsProvider(credentials.NewStaticCredentialsProvider(
			e.creds.AccessKeyID,
			e.creds.SecretAccessKey,
			e.creds.SessionToken,
		)))
	}
	return config.LoadDefaultConfig(ctx, opts...)
}

func (e *ECR) client(ctx context.Context) (*ecr.Client, error) {
	cfg, err := e.awsConfig(ctx)
	if err != nil {
		return nil, err
	}
	if strings.TrimSpace(e.creds.Region) == "" {
		return nil, fmt.Errorf("ecr: region required")
	}
	return ecr.NewFromConfig(cfg), nil
}

// TestConnection validates credentials via GetAuthorizationToken and ensures the
// returned base64 token decodes to a docker-style "AWS:password" pair (per AWS docs).
func (e *ECR) TestConnection(ctx context.Context) error {
	c, err := e.client(ctx)
	if err != nil {
		return err
	}
	out, err := c.GetAuthorizationToken(ctx, &ecr.GetAuthorizationTokenInput{})
	if err != nil {
		return err
	}
	if len(out.AuthorizationData) == 0 {
		return fmt.Errorf("ecr: empty authorization data")
	}
	token := aws.ToString(out.AuthorizationData[0].AuthorizationToken)
	if token == "" {
		return fmt.Errorf("ecr: empty authorization token")
	}
	raw, err := base64.StdEncoding.DecodeString(token)
	if err != nil {
		return fmt.Errorf("ecr: decode authorization token: %w", err)
	}
	parts := strings.SplitN(string(raw), ":", 2)
	if len(parts) != 2 || parts[0] != "AWS" || parts[1] == "" {
		return fmt.Errorf("ecr: unexpected registry credentials payload")
	}
	return nil
}

// ListRepositories returns ECR repository names in the account/region.
func (e *ECR) ListRepositories(ctx context.Context) ([]string, error) {
	c, err := e.client(ctx)
	if err != nil {
		return nil, err
	}
	var names []string
	p := ecr.NewDescribeRepositoriesPaginator(c, &ecr.DescribeRepositoriesInput{})
	for p.HasMorePages() {
		page, err := p.NextPage(ctx)
		if err != nil {
			return nil, err
		}
		for _, r := range page.Repositories {
			if r.RepositoryName != nil {
				names = append(names, *r.RepositoryName)
			}
		}
	}
	sort.Strings(names)
	return names, nil
}

// ListTags returns image tags present in the repository.
func (e *ECR) ListTags(ctx context.Context, repository string) ([]string, error) {
	c, err := e.client(ctx)
	if err != nil {
		return nil, err
	}
	if strings.TrimSpace(repository) == "" {
		return nil, fmt.Errorf("ecr: empty repository")
	}
	seen := map[string]struct{}{}
	p := ecr.NewListImagesPaginator(c, &ecr.ListImagesInput{
		RepositoryName: aws.String(repository),
	})
	for p.HasMorePages() {
		page, err := p.NextPage(ctx)
		if err != nil {
			return nil, err
		}
		for _, id := range page.ImageIds {
			if id.ImageTag != nil && *id.ImageTag != "" {
				seen[*id.ImageTag] = struct{}{}
			}
		}
	}
	out := make([]string, 0, len(seen))
	for t := range seen {
		out = append(out, t)
	}
	sort.Strings(out)
	return out, nil
}

// GetDigest returns the image digest for the given tag.
func (e *ECR) GetDigest(ctx context.Context, repository, tag string) (string, error) {
	c, err := e.client(ctx)
	if err != nil {
		return "", err
	}
	if repository == "" || tag == "" {
		return "", fmt.Errorf("ecr: repository and tag required")
	}
	out, err := c.DescribeImages(ctx, &ecr.DescribeImagesInput{
		RepositoryName: aws.String(repository),
		ImageIds:       []types.ImageIdentifier{{ImageTag: aws.String(tag)}},
	})
	if err != nil {
		return "", err
	}
	if len(out.ImageDetails) == 0 || out.ImageDetails[0].ImageDigest == nil {
		return "", fmt.Errorf("ecr: image not found")
	}
	return *out.ImageDetails[0].ImageDigest, nil
}
