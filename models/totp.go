package models

import (
	"encoding/base32"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"github.com/pquerna/otp/totp"
	"net/url"
	"strings"
	"time"
)

type TOTP struct {
	ID       string    `json:"id"`
	UserInfo string    `json:"userInfo"`
	Secret   string    `json:"secret"`
	Created  time.Time `json:"created"`
}

func (t *TOTP) GenerateToken() (string, error) {
	return totp.GenerateCode(t.Secret, time.Now())
}

func (t *TOTP) ValidateToken(token string) bool {
	return totp.Validate(token, t.Secret)
}

func ParseQRData(qrData string) ([]TOTP, error) {
	if strings.HasPrefix(qrData, "otpauth-migration://offline?data=") {
		return parseGoogleAuthenticatorExport(qrData)
	}

	totp, err := ParseTOTPUri(qrData)
	if err != nil {
		return nil, err
	}
	return []TOTP{totp}, nil
}

func ParseTOTPUri(uri string) (TOTP, error) {
	u, err := url.Parse(uri)
	if err != nil {
		return TOTP{}, err
	}

	if u.Scheme != "otpauth" || u.Host != "totp" {
		return TOTP{}, fmt.Errorf("无效的TOTP URI")
	}

	query := u.Query()
	secret := query.Get("secret")
	if secret == "" {
		return TOTP{}, fmt.Errorf("TOTP URI中缺少secret")
	}

	issuer := query.Get("issuer")
	userInfo := strings.TrimPrefix(u.Path, "/")

	// 如果有 issuer，将其添加到 userInfo 中
	if issuer != "" {
		userInfo = fmt.Sprintf("%s (%s)", userInfo, issuer)
	}

	return TOTP{
		UserInfo: userInfo,
		Secret:   secret,
	}, nil
}

func parseGoogleAuthenticatorExport(qrData string) ([]TOTP, error) {
	data := strings.TrimPrefix(qrData, "otpauth-migration://offline?data=")

	decodedData, err := url.QueryUnescape(data)
	if err != nil {
		return nil, fmt.Errorf("failed to URL decode data: %v", err)
	}

	rawData, err := base64.StdEncoding.DecodeString(decodedData)
	if err != nil {
		return nil, fmt.Errorf("failed to decode base64 data: %v", err)
	}

	var totps []TOTP
	index := 0

	for index < len(rawData) {
		if index+1 >= len(rawData) {
			break
		}

		fieldNumber := int(rawData[index] >> 3)
		wireType := int(rawData[index] & 0x07)
		index++

		switch wireType {
		case 0: // Varint
			_, bytesRead := decodeVarint(rawData[index:])
			index += bytesRead
		case 1: // 64-bit
			if index+8 > len(rawData) {
				return nil, fmt.Errorf("insufficient data for 64-bit field")
			}
			value := binary.LittleEndian.Uint64(rawData[index : index+8])
			index += 8
			fmt.Printf("64-bit value: %d\n", value)
		case 2: // Length-delimited
			length, bytesRead := decodeVarint(rawData[index:])
			index += bytesRead
			if index+int(length) > len(rawData) {
				return nil, fmt.Errorf("invalid length-delimited field length")
			}
			fieldData := rawData[index : index+int(length)]
			index += int(length)

			if fieldNumber == 1 {
				totp, err := parseTOTPEntry(fieldData)
				if err != nil {
					fmt.Printf("Warning: failed to parse TOTP entry: %v\n", err)
				} else {
					totps = append(totps, totp)
				}
			}
		case 5: // 32-bit
			if index+4 > len(rawData) {
				return nil, fmt.Errorf("insufficient data for 32-bit field")
			}
			value := binary.LittleEndian.Uint32(rawData[index : index+4])
			index += 4
			fmt.Printf("32-bit value: %d\n", value)
		default:
			return nil, fmt.Errorf("unknown wire type: %d", wireType)
		}
	}

	if len(totps) == 0 {
		return nil, fmt.Errorf("no valid TOTP entries found")
	}

	return totps, nil
}

func parseTOTPEntry(data []byte) (TOTP, error) {
	var totp TOTP
	index := 0

	for index < len(data) {
		if index+1 >= len(data) {
			break
		}

		fieldNumber := int(data[index] >> 3)
		wireType := int(data[index] & 0x07)
		index++

		switch wireType {
		case 0: // Varint
			_, bytesRead := decodeVarint(data[index:])
			index += bytesRead
		case 1: // 64-bit
			if index+8 > len(data) {
				return TOTP{}, fmt.Errorf("insufficient data for 64-bit field")
			}
			value := binary.LittleEndian.Uint64(data[index : index+8])
			index += 8
			fmt.Printf("TOTP 64-bit value: %d\n", value)
		case 2: // Length-delimited
			length, bytesRead := decodeVarint(data[index:])
			index += bytesRead
			if index+int(length) > len(data) {
				return TOTP{}, fmt.Errorf("invalid length-delimited field length")
			}
			fieldData := data[index : index+int(length)]
			index += int(length)

			switch fieldNumber {
			case 1: // Secret
				totp.Secret = base32.StdEncoding.EncodeToString(fieldData)
			case 2: // Name
				totp.UserInfo = string(fieldData)
			case 3: // Issuer
				issuer := string(fieldData)
				if issuer != "" {
					totp.UserInfo = fmt.Sprintf("%s (%s)", totp.UserInfo, issuer)
				}
			}
		case 5: // 32-bit
			if index+4 > len(data) {
				return TOTP{}, fmt.Errorf("insufficient data for 32-bit field")
			}
			value := binary.LittleEndian.Uint32(data[index : index+4])
			index += 4
			fmt.Printf("TOTP 32-bit value: %d\n", value)
		default:
			return TOTP{}, fmt.Errorf("unknown wire type: %d", wireType)
		}
	}

	return totp, nil
}

func decodeVarint(buf []byte) (uint64, int) {
	var x uint64
	var s uint
	for i, b := range buf {
		if b < 0x80 {
			if i > 9 || i == 9 && b > 1 {
				return 0, i + 1
			}
			return x | uint64(b)<<s, i + 1
		}
		x |= uint64(b&0x7f) << s
		s += 7
	}
	return 0, len(buf)
}
