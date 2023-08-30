package main

import (
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"net/url"
	"os"
	"strings"
)

func loadEnv() {
	fileBody, _ := os.ReadFile("../.env")
	file := string(fileBody)
	keyValuePairs := strings.Split(file, "\n")
	for _, pair := range keyValuePairs {
		items := strings.SplitN(pair, "=", 2)
		key, value := items[0], items[1]
		if value[0] == '"' && value[len(value)-1] == '"' {
			value = value[1 : len(value)-1]
		}
		os.Setenv(key, value)
	}
}

func main() {
	loadEnv()
	http.HandleFunc("/", func(responseWrite http.ResponseWriter, request *http.Request) {
		if request.URL.Path != "/" {
			http.NotFound(responseWrite, request)
			return
		}
		message := "/login/github to login with Github!"
		responseWrite.Write([]byte(message))
	})
	http.HandleFunc("/login/github", handleAuthorization)
	http.HandleFunc("/login/github/callback", handleCallback)
	fmt.Println("Starting server on port 3000...")
	err := http.ListenAndServe(":3000", nil)
	fmt.Println(err)
}

func generateRandomString(length int) string {
	const alphabet = "1234567890abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
	result := ""
	for len(result) <= length {
		randomIndex, _ := rand.Int(rand.Reader, big.NewInt(int64(len(alphabet))))
		result += string(alphabet[randomIndex.Int64()])
	}
	return result
}

func handleAuthorization(responseWrite http.ResponseWriter, request *http.Request) {
	state := generateRandomString(41)

	authorizationURLQuery := url.Values{}
	authorizationURLQuery.Set("state", state)
	authorizationURLQuery.Set("client_id", getEnvVarOrPanic("GITHUB_CLIENT_ID"))
	authorizationURLQuery.Set("response_type", "code")
	authorizationURL := "https://github.com/login/oauth/authorize?" + authorizationURLQuery.Encode()
	responseWrite.Header().Set("Location", authorizationURL)

	stateCookie := http.Cookie{Name: "state", Value: state, HttpOnly: true, Path: "/", MaxAge: 60 * 60}
	responseWrite.Header().Set("Set-Cookie", stateCookie.String())
	responseWrite.WriteHeader(302)
}

func handleCallback(response http.ResponseWriter, request *http.Request) {
	query := request.URL.Query()
	state := query.Get("state")
	stateCookie, err := request.Cookie("state")
	if err != nil {
		response.WriteHeader(403)
		return
	}
	if stateCookie.Value != state {
		response.WriteHeader(403)
		return
	}
	accessToken, err := exchangeAuthorizationCode(query.Get("code"))
	if err != nil {
		fmt.Println(err)
		response.WriteHeader(500)
		return
	}
	githubUser, err := getGithubUser(accessToken)
	if err != nil {
		fmt.Println(err)
		response.WriteHeader(500)
		return
	}
	response.Write([]byte(fmt.Sprintf("User ID: %v\nUsername: %v", githubUser.UserId, githubUser.Username)))
}

func exchangeAuthorizationCode(code string) (string, error) {
	type AccessTokenResult struct {
		AccessToken string `json:"access_token"`
	}

	bodyData := url.Values{}
	bodyData.Set("client_id", getEnvVarOrPanic("GITHUB_CLIENT_ID"))
	bodyData.Set("grant_type", "code")
	bodyData.Set("client_secret", getEnvVarOrPanic("GITHUB_CLIENT_SECRET"))
	bodyData.Set("code", code)

	accessTokenRequest, _ := http.NewRequest("POST", "https://github.com/login/oauth/access_token", strings.NewReader(bodyData.Encode()))
	accessTokenRequest.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	accessTokenRequest.Header.Set("Accept", "application/json")
	accessTokenResponse, err := http.DefaultClient.Do(accessTokenRequest)
	if err != nil || accessTokenResponse.StatusCode != 200 {
		fmt.Println(err)
		return "", errors.New("invalid request")
	}
	accessTokenResponseBody, _ := io.ReadAll(accessTokenResponse.Body)
	var accessTokenResult AccessTokenResult
	err = json.Unmarshal(accessTokenResponseBody, &accessTokenResult)
	if err != nil {
		return "", err
	}
	if len(accessTokenResult.AccessToken) < 1 {
		return "", errors.New("invalid_authorization_code")
	}
	return accessTokenResult.AccessToken, nil
}

func getGithubUser(accessToken string) (*GithubUser, error) {
	request, _ := http.NewRequest("GET", "https://api.github.com/user", nil)
	request.Header.Set("Authorization", "Bearer "+accessToken)
	response, err := http.DefaultClient.Do(request)
	if err != nil || response.StatusCode != 200 {
		fmt.Println(err)
		return nil, errors.New("invalid request")
	}
	responseBody, _ := io.ReadAll(response.Body)
	var user GithubUser
	json.Unmarshal(responseBody, &user)
	return &user, nil
}

type GithubUser struct {
	UserId   int    `json:"id"`
	Username string `json:"login"`
}

func getEnvVarOrPanic(key string) string {
	value := os.Getenv(key)
	if value == "" {
		panic(fmt.Sprintf("Missing env var %v", value))
	}
	return value
}
