package user_role_plugin

//updated by DJB

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
	SolrURL      string
	SolrUsername string
	SolrPassword string
}

// ServeHTTP implements caddyhttp.MiddlewareHandler.
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

	hasRoles, err := userHasRolesInSolr(email)
	if err != nil {
		http.Error(w, "error checking Solr roles", http.StatusInternalServerError)
		return http.StatusInternalServerError, fmt.Errorf("error checking Solr roles: %v", err)
	}
	if !hasRoles {
		http.Error(w, "user roles not found in Solr", http.StatusForbidden)
		return http.StatusForbidden, fmt.Errorf("user roles not found in Solr")
	}

	// Pass to the next handler in the chain
	err = p.Next.ServeHTTP(w, r)
	if err != nil {
		return 0, err
	}
	return 0, nil
}


func extractEmailFromToken(token string) string {
	// Simulate decoding the JWT token
	return "user@example.com" // Replace with actual logic
}

func userHasRolesInSolr(email string) (bool, error) {
	solrURL := "https://localhost:8983/solr/your_collection/select"
	req, err := http.NewRequest("GET", solrURL, nil)
	if err != nil {
		return false, fmt.Errorf("creating Solr request: %w", err)
	}

	username := "admin" + os.Getenv("GD_SITE_ID")
	password := os.Getenv("GD_SITE_ID")
	req.SetBasicAuth(username, password)

	q := req.URL.Query()
	q.Add("q", fmt.Sprintf("email:%s", email))
	q.Add("fl", "userRoles")
	req.URL.RawQuery = q.Encode()

	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: true,
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
	err = json.NewDecoder(resp.Body).Decode(&solrResp)
	if err != nil {
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

// UnmarshalCaddyfile configures the plugin from Caddyfile.
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
