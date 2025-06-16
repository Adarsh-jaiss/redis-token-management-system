package auth

import (
	"fmt"
	"net/http"

	"time"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
)

func GenerateAccessToken(userID int, email string) (string, error) {
	claims := jwt.MapClaims{
		"user_id": userID,
		"email":   email,
		"exp":     time.Now().Add(time.Minute * 5).Unix(), // Token expires in 5 mins
	}

	fmt.Println(claims)

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString([]byte("makeyourownsecretandmakeitsecure"))
}

func GenerateRefreshToken(userID int, email string) (string, error) {
	claims := jwt.MapClaims{
		"user_id":    userID,
		"email":      email,
		"exp":        time.Now().Add(time.Hour * 24 * 7).Unix(), // Expires in 7 days
		"iat":        time.Now().Unix(),                         // Issued at time
		"session_id": uuid.New().String(),                       // Random session ID
	}

	fmt.Println(claims)
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString([]byte("makeyourownsecretandmakeitsecure"))
}

func AuthMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		token := c.GetHeader("Authorization")
		if token == "" {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Authorization header is required"})
			c.Abort()
			return
		}

		claims, err, _ := ValidateToken(token)
		if err != nil {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid or expired token "})
			c.Abort()
			return
		}

		c.Set("user", claims)
		c.Next()
	}
}

func ValidateToken(tokenString string) (*jwt.Token, error, bool) {
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		// Validate the signing method is HMAC
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return []byte("makeyourownsecretandmakeitsecure"), nil
	})

	if err != nil {
		return nil, err, false
	}

	if !token.Valid {
		return nil, fmt.Errorf("invalid token"), false
	}

	return token, nil, true
}

func IsExpired(token *jwt.Token) (bool, error) {
	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		return true, fmt.Errorf("invalid token claims")
	}

	exp, ok := claims["exp"].(float64)
	if !ok {
		return true, fmt.Errorf("invalid expiration claim")
	}

	fmt.Println("Now      :", time.Now().Unix())
	fmt.Println("Token exp:", int64(exp))

	return time.Now().Unix() >= int64(exp), nil
}

// Session Storage
// Key: sessions:<user_id>
// Type: Set
// Purpose: Track all active session IDs per user

func ExtractUserID() gin.HandlerFunc {
	return func(c *gin.Context) {
		userValue, exists := c.Get("user")
		if !exists {
			c.AbortWithStatusJSON(401, gin.H{"error": "unauthorized"})
			return
		}
		user, ok := userValue.(*jwt.Token)
		if !ok {
			c.AbortWithStatusJSON(401, gin.H{"error": "invalid token"})
			return
		}
		claims := user.Claims.(jwt.MapClaims)
		userID := int(claims["user_id"].(float64))

		// Store user ID in context
		c.Set("user_id", userID)

		c.Next()
	}
}

func ExtractClaims(token string) (map[string]interface{}, error) {
	claims, err, _ := ValidateToken(token)
	if err != nil {
		return nil, fmt.Errorf("failed to parse token: %v", err)
	}

	tokenClaims, ok := claims.Claims.(jwt.MapClaims)
	if !ok {
		return nil, fmt.Errorf("failed to parse token claims")
	}

	// Extract claims from the token
	userId := int(tokenClaims["user_id"].(float64))
	exp := int64(tokenClaims["exp"].(float64))
	iat := int64(tokenClaims["iat"].(float64))
	sessionId := tokenClaims["session_id"].(string)
	expiresAt := time.Unix(exp, 0)
	issuedAt := time.Unix(iat, 0)
	clientIP := tokenClaims["client_ip"]
	userAgent := tokenClaims["user_agent"]

	return map[string]interface{}{
		"user_id":    userId,
		"session_id": sessionId,
		"email":      tokenClaims["email"].(string),
		"issued_at":  issuedAt.Format(time.RFC3339),
		"expires_at": expiresAt.Format(time.RFC3339),
		"client_ip":  clientIP,
		"user_agent": userAgent,
	}, nil

}
