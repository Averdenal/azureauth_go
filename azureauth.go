package azureauth

import (
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/MicahParks/keyfunc"
	"github.com/golang-jwt/jwt/v4"
)

// AzureAuth définit l'interface pour l'authentification Azure AD
type AzureAuth interface {
	// ValidateToken valide un token JWT Azure AD
	ValidateToken(tokenString string) (*ValidationResult, error)

	// recuperer le OID d'un utilisateur à partir d'un token JWT
	GetOIDUser(tokenString string) (string, error)

	// GetUserGraphData récupère les données utilisateur depuis Microsoft Graph API
	GetUserGraphData(oid string, selectFields []string) (*GraphUserData, error)

	// RefreshJWKS force le rafraîchissement des clés JWKS
	RefreshJWKS() error

	// IsTokenExpired vérifie si un token est expiré
	IsTokenExpired(claims jwt.MapClaims) bool
}

// NewAzureAuthService crée une nouvelle instance du service d'authentification Azure AD
func NewAzureAuthService(config Config) (AzureAuth, error) {
	service := &azureAuthService{
		config:          config,
		graphTokenCache: &tokenCache{},
	}

	// Initialiser JWKS
	if err := service.initJWKS(); err != nil {
		return nil, fmt.Errorf("erreur lors de l'initialisation JWKS: %w", err)
	}

	return service, nil
}

// initJWKS initialise les clés JWKS depuis Azure AD
func (s *azureAuthService) initJWKS() error {
	jwksURL := fmt.Sprintf("https://login.microsoftonline.com/%s/discovery/v2.0/keys", s.config.TenantID)

	jwks, err := keyfunc.Get(jwksURL, keyfunc.Options{
		RefreshErrorHandler: func(err error) {
			log.Printf("Erreur lors du rafraîchissement JWKS: %v", err)
		},
		RefreshInterval:   time.Hour * 12,
		RefreshRateLimit:  time.Minute * 5,
		RefreshTimeout:    time.Second * 10,
		RefreshUnknownKID: true,
	})
	if err != nil {
		return err
	}

	s.jwksMutex.Lock()
	s.jwks = jwks
	s.jwksMutex.Unlock()

	return nil
}

func (s *azureAuthService) GetOIDUser(tokenString string) (string, error) {
	s.jwksMutex.RLock()
	jwks := s.jwks
	s.jwksMutex.RUnlock()
	if jwks == nil {
		return "", fmt.Errorf("jwks non initialisé")
	}
	// Supprimer le préfixe "Bearer " si présent
	tokenString = strings.TrimPrefix(tokenString, "Bearer ")
	// Parser le token
	token, err := jwt.Parse(tokenString, jwks.Keyfunc)
	if err != nil {
		return "", fmt.Errorf("erreur lors du parsing du token: %v", err)
	}
	if !token.Valid {
		return "", fmt.Errorf("token invalide")
	}
	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		return "", fmt.Errorf("claims invalides")
	}
	// Récupérer l'OID
	oid, ok := claims["oid"].(string)
	if !ok {
		return "", fmt.Errorf("oid manquant")
	}
	return oid, nil
}

// RefreshJWKS force le rafraîchissement des clés JWKS
func (s *azureAuthService) RefreshJWKS() error {
	s.jwksMutex.RLock()
	jwks := s.jwks
	s.jwksMutex.RUnlock()

	if jwks == nil {
		return s.initJWKS()
	}

	// Le rafraîchissement est automatique avec keyfunc
	return nil
}

// ValidateToken valide un token JWT Azure AD
func (s *azureAuthService) ValidateToken(tokenString string) (*ValidationResult, error) {
	result := &ValidationResult{}

	// Supprimer le préfixe "Bearer " si présent
	tokenString = strings.TrimPrefix(tokenString, "Bearer ")

	s.jwksMutex.RLock()
	jwks := s.jwks
	s.jwksMutex.RUnlock()

	if jwks == nil {
		result.Error = "JWKS non initialisé"
		return result, fmt.Errorf(result.Error)
	}

	// Parser le token
	token, err := jwt.Parse(tokenString, jwks.Keyfunc)
	if err != nil {
		result.Error = fmt.Sprintf("Erreur lors du parsing du token: %v", err)
		return result, err
	}

	if !token.Valid {
		result.Error = "Token invalide"
		return result, fmt.Errorf(result.Error)
	}

	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		result.Error = "Claims invalides"
		return result, fmt.Errorf(result.Error)
	}

	result.Claims = claims

	// Vérifier l'audience
	aud, ok := claims["aud"].(string)
	if !ok || (aud != s.config.ClientID && aud != "api://"+s.config.ClientID) {
		result.Error = "Audience invalide"
		return result, fmt.Errorf(result.Error)
	}

	// Vérifier l'issuer
	expectedIssuer := fmt.Sprintf("https://sts.windows.net/%s/", s.config.TenantID)
	if iss, ok := claims["iss"].(string); !ok || iss != expectedIssuer {
		result.Error = "Issuer invalide"
		return result, fmt.Errorf(result.Error)
	}

	// Vérifier si c'est un token d'application (client credentials)
	if appID, ok := claims["appid"].(string); ok {
		if sub, ok := claims["sub"].(string); ok {
			if oid, ok := claims["oid"].(string); ok && sub == oid {
				result.IsApp = true
				result.AppID = appID
				result.Oid = oid

				// Extraire les rôles
				if roles, ok := claims["roles"].([]interface{}); ok {
					for _, r := range roles {
						if roleStr, ok := r.(string); ok {
							result.Roles = append(result.Roles, roleStr)
						}
					}
				}

				result.Valid = true
				return result, nil
			}
		}
	}

	// Token utilisateur
	oid, ok := claims["oid"].(string)
	if !ok {
		result.Error = "OID manquant"
		return result, fmt.Errorf(result.Error)
	}

	result.Oid = oid
	result.IsApp = false

	// Extraire les rôles
	if roles, ok := claims["roles"].([]interface{}); ok {
		for _, r := range roles {
			if roleStr, ok := r.(string); ok {
				result.Roles = append(result.Roles, roleStr)
			}
		}
	}

	result.Valid = true
	return result, nil
}

// IsTokenExpired vérifie si un token est expiré
func (s *azureAuthService) IsTokenExpired(claims jwt.MapClaims) bool {
	if exp, ok := claims["exp"].(float64); ok {
		return time.Now().Unix() > int64(exp)
	}
	return true
}

// getGraphToken récupère un token d'accès pour Microsoft Graph API
func (s *azureAuthService) getGraphToken() (string, error) {
	// Vérifier le cache
	s.graphTokenCache.mutex.RLock()
	if s.graphTokenCache.token != "" && time.Now().Unix() < s.graphTokenCache.expiration {
		token := s.graphTokenCache.token
		s.graphTokenCache.mutex.RUnlock()
		return token, nil
	}
	s.graphTokenCache.mutex.RUnlock()

	tokenURL := fmt.Sprintf("https://login.microsoftonline.com/%s/oauth2/v2.0/token", s.config.TenantID)

	// Créer les données au format application/x-www-form-urlencoded
	data := url.Values{}
	data.Set("grant_type", "client_credentials")
	data.Set("client_id", s.config.ClientID)
	data.Set("client_secret", s.config.ClientSecret)
	data.Set("scope", "https://graph.microsoft.com/.default")

	req, err := http.NewRequest("POST", tokenURL, strings.NewReader(data.Encode()))
	if err != nil {
		return "", fmt.Errorf("erreur lors de la création de la requête: %w", err)
	}

	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return "", fmt.Errorf("erreur lors de la requête HTTP: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("erreur lors de la lecture de la réponse: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("erreur d'authentification (status %d): %s", resp.StatusCode, string(body))
	}

	var tokenResp graphTokenResponse
	if err := json.Unmarshal(body, &tokenResp); err != nil {
		return "", fmt.Errorf("erreur lors du décodage de la réponse: %w", err)
	}

	if tokenResp.Error != "" {
		return "", fmt.Errorf("erreur d'authentification: %s - %s", tokenResp.Error, tokenResp.ErrorDesc)
	}

	if tokenResp.AccessToken == "" {
		return "", fmt.Errorf("token d'accès manquant dans la réponse")
	}

	// Mettre à jour le cache (expire dans ExpiresIn secondes, on met une marge de 5 minutes)
	s.graphTokenCache.mutex.Lock()
	s.graphTokenCache.token = tokenResp.AccessToken
	s.graphTokenCache.expiration = time.Now().Unix() + int64(tokenResp.ExpiresIn) - 300
	s.graphTokenCache.mutex.Unlock()

	return tokenResp.AccessToken, nil
}

// GetUserGraphData récupère les données utilisateur depuis Microsoft Graph API
func (s *azureAuthService) GetUserGraphData(oid string, selectFields []string) (*GraphUserData, error) {
	token, err := s.getGraphToken()
	if err != nil {
		return nil, fmt.Errorf("erreur lors de l'obtention du token Graph: %w", err)
	}

	graphURL := fmt.Sprintf(
		"https://graph.microsoft.com/v1.0/users/%s?$select=%s",
		oid,
		strings.Join(selectFields, ","),
	)

	req, err := http.NewRequest("GET", graphURL, nil)
	if err != nil {
		return nil, fmt.Errorf("erreur lors de la création de la requête Graph: %w", err)
	}

	req.Header.Set("Authorization", "Bearer "+token)

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("erreur lors de la requête Graph: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("erreur lors de la lecture de la réponse Graph: %w", err)
	}

	var userData GraphUserData
	userData.HTTPStatusCode = resp.StatusCode

	if resp.StatusCode != http.StatusOK {
		userData.ErrorMessage = string(body)
		return &userData, nil
	}

	if err := json.Unmarshal(body, &userData); err != nil {
		return nil, fmt.Errorf("erreur lors du décodage des données Graph: %w", err)
	}

	return &userData, nil
}
