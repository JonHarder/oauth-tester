package pkce

import (
	"fmt"

	"github.com/JonHarder/oauth/internal/parameters"
	"github.com/JonHarder/oauth/internal/util"
)

// Convience struct used to store information
// specific to the PKCE extension to the authorization
// code flow.
type PKCE struct {
	CodeChallenge       string
	CodeChallengeMethod string
}

// ValidatePkce checks the code_verifier against the code_challenge using code_challenge_method
// returns a ValidationError when validation fails.
func ValidatePkce(pkce PKCE, verifier string) error {
	switch pkce.CodeChallengeMethod {
	case "S256":
		computedChallenge := util.S256CodeChallenge(verifier)
		if computedChallenge != pkce.CodeChallenge {
			return fmt.Errorf("PKCE computed code challenge using provided verifier: '%s' did not match challenge from auth req: %s", verifier, pkce.CodeChallenge)
		}
		break
	case "plain":
		if verifier != pkce.CodeChallenge {
			return fmt.Errorf(
				"PKCE plain method verification failed, provided verifier did not match initial challenge: %s",
				pkce.CodeChallenge,
			)
		}
		break
	default:
		return fmt.Errorf("unknown code_challenge_method: %s", pkce.CodeChallengeMethod)
	}
	return nil
}

func ParsePkce(p parameters.ParameterBag) (*PKCE, error) {
	var pkce *PKCE = nil
	codeChallenge, codeChallengeOk := p.Parameters["code_challenge"]
	if codeChallengeOk {
		codeChallengeMethod := p.Get("code_challenge_method", "plain")
		pkce = &PKCE{
			CodeChallenge:       codeChallenge,
			CodeChallengeMethod: codeChallengeMethod,
		}
	}
	return pkce, nil
}
