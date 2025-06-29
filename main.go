package user_role_plugin

import (
	"fmt"
	"net/http"
	"strings"
	"encoding/json"
	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"golang.org/x/net/context"
	"os"
	"time"
	"golang.org/x/crypto/acme/autocert"
	"net/http/httputil"
)

type UserRolePlugin struct {
	// Add any configuration options here, like Solr URLs, etc.
	SolrURL      string
	SolrUsername string
	SolrPassword string
}

func (p *UserRolePlugin) ServeHTTP(w http.ResponseWriter, r *http.Request) (int, error) {
	// Extract the user email claim from the Access Token (OIDC)
	accessToken := r.Header.Get("Authorization")
	if accessToken == "" {
		return http.StatusUnauthorized, fmt.Errorf("missing Authorization header")
	}

	// Now, we will get the email from the OIDC claim
	email := extractEmailFromToken(accessToken)
	if email == "" {
		return http.StatusUnauthorized, fmt.Errorf("invalid token, email claim missing")
	}

	// Call SolrUtil to check if this user exists and has appropriate roles
	if !userHasRolesInSolr(email) {
		return http.StatusForbidden, fmt.Errorf("user roles not found in Solr")
	}

	// If everything checks out, continue with the request
	return caddyhttp.DefaultHandler(w, r)
}

func extractEmailFromToken(token string) string {
	// Simulate decoding JWT or other token types to extract the user email
	// In reality, you would use a JWT library to decode and parse claims
	// Here we're just simulating it for the sake of example
	return "user@example.com" // Replace with actual logic to parse token
}

func userHasRolesInSolr(email string) bool {
	// Perform Solr request to check if the user has roles
	// Solr request code here (using basic authentication)

	solrURL := "https://localhost:8983/solr/your_collection/select"
	req, err := http.NewRequest("GET", solrURL, nil)
	if err != nil {
		fmt.Println("Error creating Solr request:", err)
		return false
	}

	// Add Solr basic authentication headers
	username := "admin" + os.Getenv("GD_SITE_ID")
	password := os.Getenv("GD_SITE_ID")
	req.SetBasicAuth(username, password)

	q := req.URL.Query()
	q.Add("q", fmt.Sprintf("email:%s", email)) // Assuming you store email as part of the Solr document
	q.Add("fl", "userRoles")  // Assuming roles are stored in a field 'userRoles'
	req.URL.RawQuery = q.Encode()

	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: true, // Ignore cert verification (for self-signed certs)
			},
		},
		Timeout: 10 * time.Second,
	}

	resp, err := client.Do(req)
	if err != nil {
		fmt.Println("Error sending Solr request:", err)
		return false
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		fmt.Println("Solr request failed with status:", resp.Status)
		return false
	}

	// Parse the Solr response and check for roles
	var solrResp struct {
		Response struct {
			Docs []struct {
				UserRoles []string `json:"userRoles"`
			} `json:"docs"`
		} `json:"response"`
	}
	err = json.NewDecoder(resp.Body).Decode(&solrResp)
	if err != nil {
		fmt.Println("Error parsing Solr response:", err)
		return false
	}

	// Check if the user has any roles in Solr
	if len(solrResp.Response.Docs) == 0 {
		return false
	}

	// You can check specific roles if needed
	for _, role := range solrResp.Response.Docs[0].UserRoles {
		if role == "desired_role" {
			return true
		}
	}

	return false
}

func init() {
	caddy.RegisterModule(UserRolePlugin{})
}

func (UserRolePlugin) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "http.handlers.user_role_plugin",
		New: func() caddy.Module { return new(UserRolePlugin) },
	}
}
