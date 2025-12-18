package azureauth

import (
	"fmt"
	"sync"

	"github.com/MicahParks/keyfunc"
	"github.com/golang-jwt/jwt/v4"
)

// Config contient la configuration pour l'authentification Azure AD
type Config struct {
	TenantID     string
	ClientID     string
	ClientSecret string
}

// azureAuthService implémente l'interface AzureAuth
type azureAuthService struct {
	config          Config
	jwks            *keyfunc.JWKS
	jwksMutex       sync.RWMutex
	graphTokenCache *tokenCache
}

// tokenCache gère le cache du token Graph API
type tokenCache struct {
	token      string
	expiration int64
	mutex      sync.RWMutex
}

// TokenClaims représente les claims d'un token JWT Azure AD
type TokenClaims struct {
	Aud        string   `json:"aud"`
	Iss        string   `json:"iss"`
	Oid        string   `json:"oid"`
	Sub        string   `json:"sub"`
	AppID      string   `json:"appid"`
	Roles      []string `json:"roles"`
	Name       string   `json:"name"`
	GivenName  string   `json:"given_name"`
	FamilyName string   `json:"family_name"`
	Email      string   `json:"unique_name"`
	OnpremSid  string   `json:"onprem_sid"`
}

// ValidationResult contient le résultat de la validation d'un token
type ValidationResult struct {
	Valid  bool
	Claims jwt.MapClaims
	IsApp  bool
	Oid    string
	AppID  string
	Roles  []string
	Error  string
}

// GraphUserData représente les données utilisateur récupérées depuis Microsoft Graph API
type GraphUserData struct {
	ID                string   `json:"id"`
	Department        string   `json:"department"`
	MobilePhone       string   `json:"mobilePhone"`
	BusinessPhones    []string `json:"businessPhones"`
	JobTitle          string   `json:"jobTitle"`
	Mail              string   `json:"mail"`
	UserPrincipalName string   `json:"userPrincipalName"`
	Surname           string   `json:"surname"`
	GivenName         string   `json:"givenName"`
	DisplayName       string   `json:"displayName"`
	OtherMails        []string `json:"otherMails"`
	ProxyAddresses    []string `json:"proxyAddresses"`
	HTTPStatusCode    int      `json:"httpStatusCode"` // Code de statut HTTP de la réponse
	ErrorMessage      string   `json:"errorMessage"`   // Message d'erreur si applicable
}

// GraphTokenResponse représente la réponse de l'API de token OAuth2
type graphTokenResponse struct {
	AccessToken string `json:"access_token"`
	TokenType   string `json:"token_type"`
	ExpiresIn   int    `json:"expires_in"`
	Error       string `json:"error"`
	ErrorDesc   string `json:"error_description"`
}

// UserNotFoundError est retournée lorsque l'utilisateur n'existe pas dans Azure AD
type UserNotFoundError struct {
	OID string
}

func (e *UserNotFoundError) Error() string {
	return fmt.Sprintf("utilisateur non trouvé dans Azure AD: %s", e.OID)
}
