package user_role_plugin

import (
	"crypto/tls"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"time"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
)

type UserRolePlugin struct {
	Next         caddyhttp.Handler `json:"-"`
	SolrURL      string            `json:"solr_url,omitempty"`
	SolrUsername string            `json:"solr_username,omitempty"`
	SolrPassword string            `json:"solr_password,omitempty"`
}

// ServeHTTP implements the caddyhttp.MiddlewareHandler interface.
func (p *UserRolePlugin) ServeHTTP(w http.ResponseWriter, r *http.Request) (int, error) {
	accessToken := r.Header.Get("Authorization")
	if accessToken == "" {
		http.Error(w, "missing Authorization header", http.StatusUnauthorized)
		return http.StatusUnauthorized, fmt.Errorf("missing Authorization header")
	}

	email := extractEmailFromToken(accessToken)
	if email == "" {
		http.Error(w, "invalid token, email claim missing", http.StatusUnauthorized)
		return http.StatusUnauthorized, fmt.Errorf("invalid token, email claim missing")
	}

	hasRoles, err := p.userHasRolesInSolr(email)
	if err != nil {
		http.Error(w, "error checking Solr roles", http.StatusInternalServerError)
		return http.StatusInternalServerError, fmt.Errorf("error checking Solr roles: %w", err)
	}
	if !hasRoles {
		http.Error(w, "user roles not found in Solr", http.StatusForbidden)
		return http.StatusForbidden, fmt.Errorf("user roles not found in Solr")
	}

	// Pass request to the next handler
	return p.Next.ServeHTTP(w, r)
}

func extractEmailFromToken(token string) string {
	// TODO: Implement real JWT parsing here
	// This is a placeholder:
	return "user@example.com"
}

// userHasRolesInSolr checks the user's roles in Solr using the configured Solr URL and credentials.
func (p *UserRolePlugin) userHasRolesInSolr(email string) (bool, error) {
	req, err := http.NewRequest("GET", p.SolrURL, nil)
	if err != nil {
		return false, fmt.Errorf("creating Solr request: %w", err)
	}

	// Use configured username and password
	req.SetBasicAuth(p.SolrUsername, p.SolrPassword)

	q := req.URL.Query()
	q.Add("q", fmt.Sprintf("email:%s", email))
	q.Add("fl", "userRoles")
	req.URL.RawQuery = q.Encode()

	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: true, // consider making this configurable for production
			},
		},
		Timeout: 10 * time.Second,
	}

	resp, err := client.Do(req)
	if err != nil {
		return false, fmt.Errorf("sending Solr request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return false, fmt.Errorf("Solr request failed with status: %s", resp.Status)
	}

	var solrResp struct {
		Response struct {
			Docs []struct {
				UserRoles []string `json:"userRoles"`
			} `json:"docs"`
		} `json:"response"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&solrResp); err != nil {
		return false, fmt.Errorf("parsing Solr response: %w", err)
	}

	if len(solrResp.Response.Docs) == 0 {
		return false, nil
	}

	for _, role := range solrResp.Response.Docs[0].UserRoles {
		if role == "desired_role" {
			return true, nil
		}
	}

	return false, nil
}

// Caddy module registration
func init() {
	caddy.RegisterModule(UserRolePlugin{})
}

// CaddyModule returns the Caddy module information.
func (UserRolePlugin) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "http.handlers.user_role_plugin",
		New: func() caddy.Module { return new(UserRolePlugin) },
	}
}

// UnmarshalCaddyfile configures the plugin from the Caddyfile.
func (p *UserRolePlugin) UnmarshalCaddyfile(d *caddyfile.Dispenser) error {
	for d.Next() {
		for d.NextBlock(0) {
			switch d.Val() {
			case "solr_url":
				if !d.NextArg() {
					return d.ArgErr()
				}
				p.SolrURL = d.Val()
			case "solr_username":
				if !d.NextArg() {
					return d.ArgErr()
				}
				p.SolrUsername = d.Val()
			case "solr_password":
				if !d.NextArg() {
					return d.ArgErr()
				}
				p.SolrPassword = d.Val()
			default:
				return d.Errf("unrecognized directive: %s", d.Val())
			}
		}
	}
	return nil
}
