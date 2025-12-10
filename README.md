# Azure Auth Go Module

Module Go pour gérer l'authentification Azure AD et les interactions avec Microsoft Graph API.

## Installation

```bash
go get github.com/Averdenal/azureauth_go
```

## Utilisation

### Configuration

```go
import "github.com/Averdenal/azureauth_go"

config := azureauth.Config{
    TenantID:     "votre-tenant-id",
    ClientID:     "votre-client-id",
    ClientSecret: "votre-client-secret",
}

authService, err := azureauth.NewAzureAuthService(config)
if err != nil {
    log.Fatal(err)
}
```

### Validation de token

```go
// Valider un token JWT Azure AD
result, err := authService.ValidateToken(tokenString)
if err != nil {
    log.Printf("Erreur de validation: %v", err)
    return
}

if !result.Valid {
    log.Printf("Token invalide: %s", result.Error)
    return
}

// Vérifier si c'est un token d'application
if result.IsApp {
    log.Printf("Token d'application: %s", result.AppID)
} else {
    log.Printf("Token utilisateur: %s", result.Oid)
}

// Accéder aux rôles
for _, role := range result.Roles {
    log.Printf("Rôle: %s", role)
}
```

### Récupération des données utilisateur depuis Graph API

```go
// Récupérer les données d'un utilisateur
userData, err := authService.GetUserGraphData(oid)
if err != nil {
    log.Printf("Erreur lors de la récupération des données: %v", err)
    return
}

log.Printf("Utilisateur: %s %s", userData.GivenName, userData.Surname)
log.Printf("Email: %s", userData.Mail)
log.Printf("Département: %s", userData.Department)
log.Printf("Fonction: %s", userData.JobTitle)
log.Printf("Téléphone mobile: %s", userData.MobilePhone)
```

## Fonctionnalités

- ✅ Validation de tokens JWT Azure AD
- ✅ Support des tokens utilisateur et d'application (client credentials)
- ✅ Vérification automatique de l'audience et de l'issuer
- ✅ Extraction des rôles depuis les claims
- ✅ Récupération des données utilisateur depuis Microsoft Graph API
- ✅ Cache automatique du token Graph API
- ✅ Rafraîchissement automatique des clés JWKS
- ✅ Gestion thread-safe avec mutex

## Structures de données

### ValidationResult

Résultat de la validation d'un token :

```go
type ValidationResult struct {
    Valid  bool              // Token valide ou non
    Claims jwt.MapClaims     // Claims du token
    IsApp  bool              // Token d'application
    Oid    string            // Object ID de l'utilisateur/application
    AppID  string            // Application ID (si IsApp=true)
    Roles  []string          // Rôles de l'utilisateur/application
    Error  string            // Message d'erreur si Valid=false
}
```

### GraphUserData

Données utilisateur récupérées depuis Graph API :

```go
type GraphUserData struct {
    ID                string
    Department        string
    MobilePhone       string
    BusinessPhones    []string
    JobTitle          string
    Mail              string
    UserPrincipalName string
    Surname           string
    GivenName         string
    DisplayName       string
    OtherMails        []string
    ProxyAddresses    []string
}
```

## Exemple complet avec Gin

```go
import (
    "github.com/Averdenal/azureauth_go"
    "github.com/gin-gonic/gin"
)

var authService azureauth.AzureAuth

func init() {
    config := azureauth.Config{
        TenantID:     os.Getenv("AZURE_TENANT_ID"),
        ClientID:     os.Getenv("AZURE_CLIENT_ID"),
        ClientSecret: os.Getenv("AZURE_CLIENT_SECRET"),
    }
    
    var err error
    authService, err = azureauth.NewAzureAuthService(config)
    if err != nil {
        log.Fatal(err)
    }
}

func AzureAuthMiddleware() gin.HandlerFunc {
    return func(c *gin.Context) {
        authHeader := c.GetHeader("Authorization")
        if authHeader == "" {
            c.AbortWithStatusJSON(401, gin.H{"error": "Token manquant"})
            return
        }
        
        result, err := authService.ValidateToken(authHeader)
        if err != nil || !result.Valid {
            c.AbortWithStatusJSON(401, gin.H{"error": "Token invalide"})
            return
        }
        
        c.Set("validation_result", result)
        c.Set("oid", result.Oid)
        c.Set("is_app", result.IsApp)
        c.Set("roles", result.Roles)
        
        c.Next()
    }
}
```

## Licence

MIT
