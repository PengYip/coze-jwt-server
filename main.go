package main

import (
	"bytes"
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"math/rand"
	"net/http"
	"os"
	"path/filepath"
	"time"
)

// 读取私钥文件
func readPrivateKey(keyPath string) ([]byte, error) {
	keyData, err := os.ReadFile(keyPath)
	if err != nil {
		return nil, err
	}
	return keyData, nil
}

// 生成随机字符串
func generateRandomString(length int) string {
	const charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	seededRand := rand.New(rand.NewSource(time.Now().UnixNano()))
	b := make([]byte, length)
	for i := range b {
		b[i] = charset[seededRand.Intn(len(charset))]
	}
	return string(b)
}

// 生成 JWT
func generateJWT(iss, kid string, privateKey []byte) (string, error) {
	// 解析PEM格式的私钥
	block, _ := pem.Decode(privateKey)
	if block == nil {
		return "", fmt.Errorf("failed to decode PEM block containing private key")
	}
	parsedKey, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return "", fmt.Errorf("failed to parse private key: %v", err)
	}
	// Header
	header := map[string]interface{}{
		"alg": "RS256",
		"typ": "JWT",
		"kid": kid,
	}
	headerJSON, err := json.Marshal(header)
	if err != nil {
		return "", err
	}
	encodedHeader := base64.RawURLEncoding.EncodeToString(headerJSON)
	// Payload
	now := time.Now().Unix()
	exp := now + 15*60
	jti := generateRandomString(32)
	payload := map[string]interface{}{
		"iss": iss,
		"aud": "api.coze.cn",
		"iat": now,
		"exp": exp,
		"jti": jti,
	}
	payloadJSON, err := json.Marshal(payload)
	if err != nil {
		return "", err
	}
	encodedPayload := base64.RawURLEncoding.EncodeToString(payloadJSON)
	// Signature
	unsignedToken := fmt.Sprintf("%s.%s", encodedHeader, encodedPayload)
	h := sha256.New()
	h.Write([]byte(unsignedToken))
	hashed := h.Sum(nil)
	rsaPrivateKey, ok := parsedKey.(*rsa.PrivateKey)
	if !ok {
		return "", fmt.Errorf("parsed key is not an RSA private key")
	}
	signature, err := rsa.SignPKCS1v15(nil, rsaPrivateKey, crypto.SHA256, hashed)
	if err != nil {
		return "", err
	}
	encodedSignature := base64.RawURLEncoding.EncodeToString(signature)

	// 拼接 JWT
	jwtToken := fmt.Sprintf("%s.%s.%s", encodedHeader, encodedPayload, encodedSignature)
	return jwtToken, nil
}

// 获取访问令牌
func getAccessToken(jwtToken string) (string, error) {
	url := "https://api.coze.cn/api/permission/oauth2/token"

	// 添加请求体
	requestBody := map[string]interface{}{
		"grant_type":       "urn:ietf:params:oauth:grant-type:jwt-bearer",
		"duration_seconds": 86399,
	}
	bodyData, err := json.Marshal(requestBody)
	if err != nil {
		return "", fmt.Errorf("failed to marshal request body: %v", err)
	}

	req, err := http.NewRequest("POST", url, bytes.NewBuffer(bodyData))
	if err != nil {
		return "", fmt.Errorf("failed to create request: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+jwtToken)

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return "", fmt.Errorf("request failed: %v", err)
	}
	defer resp.Body.Close()

	// 检查HTTP状态码
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("unexpected status code: %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("failed to read response body: %v", err)
	}

	var result map[string]interface{}
	err = json.Unmarshal(body, &result)
	if err != nil {
		return "", fmt.Errorf("failed to unmarshal response: %v", err)
	}

	accessToken, ok := result["access_token"].(string)
	if !ok {
		return "", fmt.Errorf("access_token not found in response: %v", result)
	}
	return accessToken, nil
}

// 新增处理 token 请求的处理器
func handleGetToken(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "仅支持 GET 请求", http.StatusMethodNotAllowed)
		return
	}

	// 获取当前目录
	dir, _ := os.Getwd()
	privateKeyPath := filepath.Join(dir, "private_key.pem")
	iss := "1130835961702"
	kid := "-Y2SZ6HJ7DzLisDjJE37GxOy1KfDIjbOaOPWF_-dccU"

	// 读取私钥
	privateKey, err := readPrivateKey(privateKeyPath)
	if err != nil {
		http.Error(w, "读取私钥失败: "+err.Error(), http.StatusInternalServerError)
		return
	}

	// 生成 JWT
	jwtToken, err := generateJWT(iss, kid, privateKey)
	if err != nil {
		http.Error(w, "生成 JWT 失败: "+err.Error(), http.StatusInternalServerError)
		return
	}

	// 获取访问令牌
	accessToken, err := getAccessToken(jwtToken)
	if err != nil {
		http.Error(w, "获取访问令牌失败: "+err.Error(), http.StatusInternalServerError)
		return
	}

	// 返回 JSON 响应
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{
		"access_token": accessToken,
	})
}

func main() {
	// 注册路由
	http.HandleFunc("/getToken", handleGetToken)

	// 启动服务器
	port := ":8080"
	fmt.Printf("服务器启动在 http://localhost%s\n", port)
	if err := http.ListenAndServe(port, nil); err != nil {
		fmt.Printf("服务器启动失败: %v\n", err)
	}
}
