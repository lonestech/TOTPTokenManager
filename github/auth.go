package github

import (
	"TOTPTokenManager/storage"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"time"

	"TOTPTokenManager/models"

	"github.com/google/go-github/v35/github"
	"golang.org/x/oauth2"
)

var (
	githubClientID     = getEnvOrDefault("GITHUB_CLIENT_ID", "你的github客户端id")
	githubClientSecret = getEnvOrDefault("GITHUB_CLIENT_SECRET", "你的客户端密钥")
	oauthConfig        = &oauth2.Config{
		ClientID:     githubClientID,
		ClientSecret: githubClientSecret,
		Scopes:       []string{"gist"},
		Endpoint: oauth2.Endpoint{
			AuthURL:  "https://github.com/login/oauth/authorize",
			TokenURL: "https://github.com/login/oauth/access_token",
		},
	}
)

func getEnvOrDefault(key, defaultValue string) string {
	value := os.Getenv(key)
	if value == "" {
		return defaultValue
	}
	return value
}
func HandleGithubAuth(w http.ResponseWriter, r *http.Request) {
	url := oauthConfig.AuthCodeURL("state", oauth2.AccessTypeOffline)
	http.Redirect(w, r, url, http.StatusTemporaryRedirect)
}
func CheckAuthStatus(w http.ResponseWriter, r *http.Request) {
	token := storage.GetGithubToken()
	status := map[string]bool{
		"authenticated": token != "",
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(status)
}
func HandleGithubCallback(w http.ResponseWriter, r *http.Request) {
	code := r.URL.Query().Get("code")
	token, err := oauthConfig.Exchange(context.Background(), code)
	if err != nil {
		http.Error(w, "Failed to exchange token", http.StatusInternalServerError)
		return
	}

	storage.SaveGithubToken(token.AccessToken)

	http.Redirect(w, r, "/", http.StatusTemporaryRedirect)
}

func UploadToGist(w http.ResponseWriter, r *http.Request) {
	token := storage.GetGithubToken()
	if token == "" {
		http.Error(w, "Not authenticated", http.StatusUnauthorized)
		return
	}

	var requestBody struct {
		Mode string `json:"mode"`
	}
	if err := json.NewDecoder(r.Body).Decode(&requestBody); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	ctx := context.Background()
	ts := oauth2.StaticTokenSource(
		&oauth2.Token{AccessToken: token},
	)
	tc := oauth2.NewClient(ctx, ts)
	client := github.NewClient(tc)

	totps := storage.GetAllTOTPs()
	content, _ := json.Marshal(totps)

	gist, err := findOrCreateBackupGist(ctx, client, requestBody.Mode == "create")
	if err != nil {
		http.Error(w, fmt.Sprintf("Failed to find or create backup gist: %v", err), http.StatusInternalServerError)
		return
	}

	gist.Files["totp_secret_backup.json"] = github.GistFile{
		Content: github.String(string(content)),
	}

	_, _, err = client.Gists.Edit(ctx, *gist.ID, gist)
	if err != nil {
		http.Error(w, "Failed to update gist", http.StatusInternalServerError)
		return
	}

	fmt.Fprintf(w, "Successfully uploaded to gist")
}

func RestoreFromGist(w http.ResponseWriter, r *http.Request) {
	token := storage.GetGithubToken()
	if token == "" {
		http.Error(w, "Not authenticated", http.StatusUnauthorized)
		return
	}

	ctx := context.Background()
	ts := oauth2.StaticTokenSource(
		&oauth2.Token{AccessToken: token},
	)
	tc := oauth2.NewClient(ctx, ts)
	client := github.NewClient(tc)

	gistID := r.URL.Query().Get("id")
	if gistID == "" {
		http.Error(w, "Gist ID is required", http.StatusBadRequest)
		return
	}

	gist, _, err := client.Gists.Get(ctx, gistID)
	if err != nil {
		http.Error(w, "Failed to get gist", http.StatusInternalServerError)
		return
	}

	content := *gist.Files["totp_secret_backup.json"].Content
	var totps []models.TOTP
	err = json.Unmarshal([]byte(content), &totps)
	if err != nil {
		http.Error(w, "Failed to parse gist content", http.StatusInternalServerError)
		return
	}

	storage.MergeTOTPs(totps)

	fmt.Fprintf(w, "Successfully restored from gist")
}

func ListBackupVersions(w http.ResponseWriter, r *http.Request) {
	token := storage.GetGithubToken()
	if token == "" {
		http.Error(w, "Not authenticated", http.StatusUnauthorized)
		return
	}

	ctx := context.Background()
	ts := oauth2.StaticTokenSource(
		&oauth2.Token{AccessToken: token},
	)
	tc := oauth2.NewClient(ctx, ts)
	client := github.NewClient(tc)

	gists, _, err := client.Gists.List(ctx, "", nil)
	if err != nil {
		http.Error(w, fmt.Sprintf("Failed to list gists: %v", err), http.StatusInternalServerError)
		return
	}

	var backupVersions []map[string]string
	for _, gist := range gists {
		if _, ok := gist.Files["totp_secret_backup.json"]; ok {
			backupVersions = append(backupVersions, map[string]string{
				"id":          *gist.ID,
				"description": *gist.Description,
				"created_at":  gist.CreatedAt.Format(time.RFC3339),
				"updated_at":  gist.UpdatedAt.Format(time.RFC3339),
			})
		}
	}

	json.NewEncoder(w).Encode(backupVersions)
}

func findOrCreateBackupGist(ctx context.Context, client *github.Client, createNew bool) (*github.Gist, error) {
	if !createNew {
		gists, _, err := client.Gists.List(ctx, "", nil)
		if err != nil {
			return nil, fmt.Errorf("failed to list gists: %v", err)
		}

		for _, gist := range gists {
			if _, ok := gist.Files["totp_secret_backup.json"]; ok {
				return gist, nil
			}
		}
	}

	newGist := &github.Gist{
		Description: github.String("TOTP Backup"),
		Public:      github.Bool(false),
		Files: map[github.GistFilename]github.GistFile{
			"totp_secret_backup.json": {
				Content: github.String("{}"),
			},
		},
	}

	createdGist, _, err := client.Gists.Create(ctx, newGist)
	if err != nil {
		return nil, fmt.Errorf("failed to create new gist: %v", err)
	}

	return createdGist, nil
}
func DeleteBackupGist(w http.ResponseWriter, r *http.Request) {
	token := storage.GetGithubToken()
	if token == "" {
		http.Error(w, "Not authenticated", http.StatusUnauthorized)
		return
	}

	gistID := r.URL.Query().Get("id")
	if gistID == "" {
		http.Error(w, "Gist ID is required", http.StatusBadRequest)
		return
	}

	ctx := context.Background()
	ts := oauth2.StaticTokenSource(
		&oauth2.Token{AccessToken: token},
	)
	tc := oauth2.NewClient(ctx, ts)
	client := github.NewClient(tc)

	// 获取Gist详情
	gist, _, err := client.Gists.Get(ctx, gistID)
	if err != nil {
		http.Error(w, fmt.Sprintf("Failed to get gist: %v", err), http.StatusInternalServerError)
		return
	}

	// 验证Gist是否属于当前用户
	user, _, err := client.Users.Get(ctx, "")
	if err != nil {
		http.Error(w, fmt.Sprintf("Failed to get user info: %v", err), http.StatusInternalServerError)
		return
	}
	if *gist.Owner.Login != *user.Login {
		http.Error(w, "You don't have permission to delete this gist", http.StatusForbidden)
		return
	}

	// 验证Gist的内容是否为TOTP备份
	file, ok := gist.Files["totp_secret_backup.json"]
	if !ok {
		http.Error(w, "This gist is not a TOTP backup", http.StatusBadRequest)
		return
	}

	// 可以进一步验证文件内容，例如：
	var totps []models.TOTP
	err = json.Unmarshal([]byte(*file.Content), &totps)
	if err != nil {
		http.Error(w, "Invalid TOTP backup content", http.StatusBadRequest)
		return
	}

	// 删除Gist
	_, err = client.Gists.Delete(ctx, gistID)
	if err != nil {
		http.Error(w, fmt.Sprintf("Failed to delete gist: %v", err), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]string{"message": "Successfully deleted gist"})
}
