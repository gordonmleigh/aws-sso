package mcpproxy

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json/jsontext"
	"encoding/json/v2"
	"net/http"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	v4 "github.com/aws/aws-sdk-go-v2/aws/signer/v4"
)

// serviceAndRegion derives the SigV4 service and region from an endpoint host
// like `aws-mcp.us-east-1.api.aws`. The region is empty if it can't be found.
func serviceAndRegion(host string) (string, string) {
	parts := strings.Split(host, ".")
	if len(parts) == 4 && parts[2] == "api" && parts[3] == "aws" {
		return parts[0], parts[1]
	}
	return parts[0], ""
}

// injectMeta adds meta to the `_meta` of JSON-RPC params, without replacing
// anything that's already there.
func injectMeta(params jsontext.Value, meta map[string]string) (jsontext.Value, error) {
	if len(meta) == 0 {
		return params, nil
	}

	fields := map[string]jsontext.Value{}
	if len(params) > 0 {
		if params.Kind() != '{' {
			// only objects can have _meta
			return params, nil
		}
		if err := json.Unmarshal(params, &fields); err != nil {
			return nil, err
		}
	}

	existing := map[string]jsontext.Value{}
	if raw, ok := fields["_meta"]; ok {
		if err := json.Unmarshal(raw, &existing); err != nil {
			return nil, err
		}
	}
	for key, value := range meta {
		if _, ok := existing[key]; ok {
			continue
		}
		raw, err := json.Marshal(value)
		if err != nil {
			return nil, err
		}
		existing[key] = raw
	}

	raw, err := json.Marshal(existing)
	if err != nil {
		return nil, err
	}
	fields["_meta"] = raw
	return json.Marshal(fields)
}

type signer struct {
	service string
	region  string
	signer  *v4.Signer
}

func newSigner(service string, region string) *signer {
	return &signer{service: service, region: region, signer: v4.NewSigner()}
}

func (s *signer) sign(
	ctx context.Context,
	req *http.Request,
	body []byte,
	creds aws.Credentials,
) error {
	hash := sha256.Sum256(body)
	return s.signer.SignHTTP(
		ctx,
		creds,
		req,
		hex.EncodeToString(hash[:]),
		s.service,
		s.region,
		time.Now(),
	)
}
