package main

import (
	"TOTPTokenManager/github"
	"TOTPTokenManager/handlers"
	"github.com/gorilla/mux"
	"log"
	"net/http"
)

func main() {
	r := mux.NewRouter()

	// 静态文件服务
	r.PathPrefix("/static/").Handler(http.StripPrefix("/static/", http.FileServer(http.Dir("static"))))

	// 添加 favicon.ico 路由
	r.HandleFunc("/favicon.ico", func(w http.ResponseWriter, r *http.Request) {
		http.ServeFile(w, r, "static/favicon.ico")
	})

	// API路由
	r.HandleFunc("/api/totp", handlers.AddTOTP).Methods("POST")
	r.HandleFunc("/api/totp", handlers.GetAllTOTPs).Methods("GET")
	r.HandleFunc("/api/totp/{id}", handlers.DeleteTOTP).Methods("DELETE")
	r.HandleFunc("/api/totp/{id}/generate", handlers.GenerateToken).Methods("GET")
	r.HandleFunc("/api/totp/{id}/export", handlers.ExportTOTP).Methods("GET")
	r.HandleFunc("/api/totp/clear-all", handlers.ClearAllTOTPs).Methods("POST")
	r.HandleFunc("/api/totp/import", handlers.ImportTOTP).Methods("POST")

	// GitHub相关路由
	r.HandleFunc("/api/github/auth", github.HandleGithubAuth).Methods("GET")
	r.HandleFunc("/api/github/auth-status", github.CheckAuthStatus).Methods("GET")
	r.HandleFunc("/api/github/callback", github.HandleGithubCallback).Methods("GET")
	r.HandleFunc("/api/github/upload", github.UploadToGist).Methods("POST")
	r.HandleFunc("/api/github/restore", github.RestoreFromGist).Methods("GET")
	r.HandleFunc("/api/github/versions", github.ListBackupVersions).Methods("GET")
	r.HandleFunc("/api/github/delete-backup", github.DeleteBackupGist).Methods("DELETE")

	// 主页
	r.HandleFunc("/", handlers.HomePage)

	log.Fatal(http.ListenAndServe(":8080", r))
}
