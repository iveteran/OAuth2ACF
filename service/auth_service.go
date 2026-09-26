package service

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"golang.org/x/oauth2"

	"github.com/iveteran/OAuth2ACF/model"
	"github.com/iveteran/OAuth2ACF/util"
)

type AuthService struct {
	DB     *sql.DB
	tokens map[string]*oauth2.Token // userId -> oauth2 token
}

func (s *AuthService) InitDB() error {
	if err := model.InitClientsTable(s.DB); err != nil {
		return err
	}
	return model.InitTokenTable(s.DB)
}

// 生成授权 URL
func (s *AuthService) GetAuthURL(provider, userID, platform, scheme, cacheMode string,
) (string, error) {
	client, err := model.GetOAuthClient(s.DB, provider)
	if err != nil {
		return "", err
	}
	conf := client.ToConfig()
	state := fmt.Sprintf("%s:%s:%s:%s:%s",
		provider, userID, platform, scheme, cacheMode)

	return conf.AuthCodeURL(
		state,
		oauth2.AccessTypeOffline,
		oauth2.ApprovalForce,
		oauth2.SetAuthURLParam("login_hint", userID),
	), nil
}

// 处理回调
func (s *AuthService) HandleCallback(provider, userID, code string) error {
	client, err := model.GetOAuthClient(s.DB, provider)
	if err != nil {
		return err
	}
	conf := client.ToConfig()

	token, err := conf.Exchange(context.Background(), code)
	if err != nil {
		return err
	}

	if token.RefreshToken == "" {
		return fmt.Errorf("no refresh_token received")
	}

	enc, err := util.Encrypt([]byte(token.RefreshToken))
	if err != nil {
		return err
	}

	return model.SaveToken(s.DB, &model.Token{
		Provider:     provider,
		UserID:       userID,
		RefreshToken: enc,
		UpdatedAt:    time.Now(),
	})
}

// 获取 access_token
func (s *AuthService) GetAccessToken(provider, userID string) (*oauth2.Token, error) {
	client, err := model.GetOAuthClient(s.DB, provider)
	if err != nil {
		return nil, err
	}
	conf := client.ToConfig()

	t, err := model.GetToken(s.DB, provider, userID)
	if err != nil {
		return nil, err
	}
	refreshTokenBytes, err := util.Decrypt(t.RefreshToken)
	if err != nil {
		return nil, err
	}

	src := conf.TokenSource(
		context.Background(),
		&oauth2.Token{
			RefreshToken: string(refreshTokenBytes),
		})
	newToken, err := src.Token()
	if err != nil {
		return nil, err
	}

	// 更新 refresh_token（如果 provider 返回了新的）
	if newToken.RefreshToken != "" && newToken.RefreshToken != string(refreshTokenBytes) {
		enc, _ := util.Encrypt([]byte(newToken.RefreshToken))
		_ = model.SaveToken(
			s.DB,
			&model.Token{
				Provider:     provider,
				UserID:       userID,
				RefreshToken: enc,
				UpdatedAt:    time.Now(),
			})
	}

	return newToken, nil
}

// 处理回调
func (s *AuthService) HandleCallbackWithoutStore(provider, userID, code string) error {
	client, err := model.GetOAuthClient(s.DB, provider)
	if err != nil {
		return err
	}
	conf := client.ToConfig()

	token, err := conf.Exchange(context.Background(), code)
	if err != nil {
		return err
	}

	if s.tokens == nil {
		s.tokens = make(map[string]*oauth2.Token)
	}
	s.tokens[userID] = token

	return nil
}

// 获取 access_token
func (s *AuthService) GetAccessTokenWithoutStore(provider, userID string) (*oauth2.Token, error) {

	if token, exists := s.tokens[userID]; exists {
		delete(s.tokens, userID)
		return token, nil
	}

	return nil, errors.New("The user not login")
}
