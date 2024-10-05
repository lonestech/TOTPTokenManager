package handlers

import (
	"TOTPTokenManager/models"
	"TOTPTokenManager/storage"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/gorilla/mux"
)

func HomePage(w http.ResponseWriter, r *http.Request) {
	http.ServeFile(w, r, "static/index.html")
}

func AddTOTP(w http.ResponseWriter, r *http.Request) {
	var totp models.TOTP
	err := json.NewDecoder(r.Body).Decode(&totp)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	totp.ID = uuid.New().String()
	totp.Created = time.Now()
	totp.Secret = strings.ReplaceAll(totp.Secret, " ", "") // 移除密钥中的所有空格
	storage.AddTOTP(totp)
	json.NewEncoder(w).Encode(totp)
}

func GetAllTOTPs(w http.ResponseWriter, r *http.Request) {
	totps := storage.GetAllTOTPs()
	json.NewEncoder(w).Encode(totps)
}

func DeleteTOTP(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	id := vars["id"]
	storage.DeleteTOTP(id)
	w.WriteHeader(http.StatusOK)
}

func GenerateToken(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	id := vars["id"]
	totp, err := storage.GetTOTP(id)
	if err != nil {
		http.Error(w, "TOTP not found", http.StatusNotFound)
		return
	}
	if totp.Secret == "" {
		json.NewEncoder(w).Encode(map[string]string{"error": "密钥已被清空，无法生成令牌"})
		return
	}
	token, err := totp.GenerateToken()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	json.NewEncoder(w).Encode(map[string]string{"token": token})
}

func ExportTOTP(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	id := vars["id"]
	totp, err := storage.GetTOTP(id)
	if err != nil {
		http.Error(w, "TOTP not found", http.StatusNotFound)
		return
	}

	uri := fmt.Sprintf("otpauth://totp/%s?secret=%s&issuer=TOTPTokenManager",
		url.QueryEscape(totp.UserInfo), totp.Secret)

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"uri": uri})
}

func ClearAllTOTPs(w http.ResponseWriter, r *http.Request) {
	storage.ClearAllTOTPs()
	w.WriteHeader(http.StatusOK)
}
func ImportTOTP(w http.ResponseWriter, r *http.Request) {

	var request struct {
		QRData string `json:"qrData"`
	}
	err := json.NewDecoder(r.Body).Decode(&request)
	if err != nil {
		fmt.Printf("Error decoding request body: %v\n", err)
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	totps, err := models.ParseQRData(request.QRData)
	if err != nil {
		fmt.Printf("Error parsing QR data: %v\n", err)
		data := strings.TrimPrefix(request.QRData, "otpauth-migration://offline?data=")
		decodedData, _ := url.QueryUnescape(data)
		rawData, _ := base64.StdEncoding.DecodeString(decodedData)
		fmt.Printf("Raw decoded data: %v\n", rawData)
		for i, b := range rawData {
			fmt.Printf("Byte %d: %d (0x%02x)\n", i, b, b)
		}
		json.NewEncoder(w).Encode(map[string]interface{}{
			"success": false,
			"error":   err.Error(),
		})
		return
	}

	for i, totp := range totps {
		totp.ID = uuid.New().String()
		totp.Created = time.Now()
		storage.AddTOTP(totp)
		fmt.Printf("Added TOTP %d: UserInfo=%s, Secret=%s\n", i+1, totp.UserInfo, totp.Secret)
	}

	json.NewEncoder(w).Encode(map[string]interface{}{
		"success": true,
		"count":   len(totps),
	})
}
