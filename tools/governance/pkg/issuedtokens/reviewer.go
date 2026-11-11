package issuedtokens

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"gitlab.com/csning1998-lab/parent-group-governance/tools/governance/pkg/gitlabapi"
)

// ErrMissingProjects marks a publication refused because a listed project is absent from GitLab.
var ErrMissingProjects = errors.New("issuedtokens: listed projects are absent from GitLab")

// SecretReader reads one field of a KV v2 secret.
type SecretReader interface {
	ReadField(ctx context.Context, field VaultField) (string, error)
}

// ProjectVariableWriter checks a project and writes CI/CD variables of the project.
type ProjectVariableWriter interface {
	HasProject(ctx context.Context, projectPath string) (bool, error)
	UpsertProjectVariable(ctx context.Context, projectPath string, v gitlabapi.Variable) error
}

// CodeReviewerVariablesPublication writes the bot tokens into the variables of every listed project.
type CodeReviewerVariablesPublication struct {
	Config   CodeReviewerVariablesConfig
	Projects []string
	Vault    SecretReader
	GitLab   ProjectVariableWriter
}

// Run checks every listed project before any write and writes nothing while a listed project is absent.
func (p CodeReviewerVariablesPublication) Run(ctx context.Context) error {
	var missing []string
	for _, path := range p.Projects {
		found, err := p.GitLab.HasProject(ctx, path)
		if err != nil {
			return err
		}
		if !found {
			missing = append(missing, path)
		}
	}
	if len(missing) > 0 {
		return fmt.Errorf("%w: %s", ErrMissingProjects, strings.Join(missing, ", "))
	}
	variables, err := p.readVariables(ctx)
	if err != nil {
		return err
	}
	for _, path := range p.Projects {
		for _, v := range variables {
			if err := p.GitLab.UpsertProjectVariable(ctx, path, v); err != nil {
				return fmt.Errorf("issuedtokens: write %s into %s: %w", v.Key, path, err)
			}
		}
	}
	return nil
}

func (p CodeReviewerVariablesPublication) readVariables(ctx context.Context) ([]gitlabapi.Variable, error) {
	var variables []gitlabapi.Variable
	for _, bot := range p.Config.BotTokens {
		token, err := p.Vault.ReadField(ctx, bot.Vault)
		if err != nil {
			return nil, err
		}
		for _, key := range bot.VariableKeys {
			variables = append(variables, gitlabapi.Variable{Key: key, Value: token, Masked: true, Hidden: true, Raw: true})
		}
	}
	return variables, nil
}
