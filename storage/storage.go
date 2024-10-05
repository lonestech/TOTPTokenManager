package storage

import (
	"TOTPTokenManager/models"
	"errors"
	"sync"
)

var (
	totps       = make(map[string]models.TOTP)
	mutex       = &sync.Mutex{}
	githubToken string
)

func AddTOTP(totp models.TOTP) {
	mutex.Lock()
	defer mutex.Unlock()
	totps[totp.ID] = totp
}

// 添加这个新函数
func GetTOTP(id string) (models.TOTP, error) {
	mutex.Lock()
	defer mutex.Unlock()
	if totp, exists := totps[id]; exists {
		return totp, nil
	}
	return models.TOTP{}, errors.New("TOTP not found")
}
func GetAllTOTPs() []models.TOTP {
	mutex.Lock()
	defer mutex.Unlock()
	result := make([]models.TOTP, 0, len(totps))
	for _, totp := range totps {
		result = append(result, totp)
	}
	return result
}

func DeleteTOTP(id string) {
	mutex.Lock()
	defer mutex.Unlock()
	delete(totps, id)
}
func ClearAllTOTPs() {
	mutex.Lock()
	defer mutex.Unlock()
	totps = make(map[string]models.TOTP)
}
func SaveGithubToken(token string) {
	githubToken = token
}

func GetGithubToken() string {
	return githubToken
}

func MergeTOTPs(newTOTPs []models.TOTP) {
	mutex.Lock()
	defer mutex.Unlock()
	for _, newTOTP := range newTOTPs {
		if _, exists := totps[newTOTP.ID]; !exists {
			totps[newTOTP.ID] = newTOTP
		}
	}
}
