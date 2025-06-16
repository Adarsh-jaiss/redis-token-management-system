package auth

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	"github.com/redis/go-redis/v9"
)

func SaveTokenToDB(token string, rdb *redis.Client, c *gin.Context) error {
	// Parse the token to get claims
	claims, err, _ := ValidateToken(token)
	if err != nil {
		return fmt.Errorf("failed to parse token: %v", err)
	}

	isExpired, _ := IsExpired(claims)
	if isExpired {
		return fmt.Errorf("token is expired")
	}

	// Get claims from token and type assert to jwt.MapClaims
	tokenClaims, ok := claims.Claims.(jwt.MapClaims)
	if !ok {
		return fmt.Errorf("failed to parse token claims")
	}

	// Extract claims from the token
	userId := int64(tokenClaims["user_id"].(float64))
	exp := int64(tokenClaims["exp"].(float64))
	iat := int64(tokenClaims["iat"].(float64))
	sessionId := tokenClaims["session_id"].(string)
	expiresAt := time.Unix(exp, 0)
	issuedAt := time.Unix(iat, 0)

	// Hash the refresh token
	tokenHash := sha256.Sum256([]byte(token))
	tokenHashStr := hex.EncodeToString(tokenHash[:])

	// Store refresh token details
	refreshKey := fmt.Sprintf("refresh:%s", tokenHashStr)
	refreshData := map[string]interface{}{
		"user_id":        userId,
		"session_id":     sessionId,
		"issued_at":      issuedAt.Format(time.RFC3339),
		"expires_at":     expiresAt.Format(time.RFC3339),
		"client_ip":      c.ClientIP(),          // Get client IP from gin context
		"user_agent":     c.Request.UserAgent(), // Get user agent from request
		"blacklisted_at": nil,
	}

	// Store session ID for user
	sessionKey := fmt.Sprintf("sessions:%d", userId)

	// Store refresh token hash for user
	userTokenKey := fmt.Sprintf("user_refresh_tokens:%d", userId)

	// Execute commands in pipeline
	pipe := rdb.Pipeline()
	pipe.HSet(c, refreshKey, refreshData)
	pipe.Expire(c, refreshKey, time.Until(expiresAt))
	// pipe.SAdd(c, sessionKey, sessionId)
	// pipe.SAdd(c, userTokenKey, tokenHashStr)

	// Store session ID and token hash in ZSETs with expiry time as score
	// rdb.Del(c, fmt.Sprintf("sessions:%d", userId))
	// rdb.Del(c, fmt.Sprintf("user_refresh_tokens:%d", userId))

	pipe.ZAdd(c, sessionKey, redis.Z{
		Score:  float64(exp),
		Member: sessionId,
	})
	pipe.ZAdd(c, userTokenKey, redis.Z{
		Score:  float64(exp),
		Member: tokenHashStr,
	})

	_, err = pipe.Exec(c)
	return err
}

func HashToken(token string) string {
	tokenHash := sha256.Sum256([]byte(token))
	return hex.EncodeToString(tokenHash[:])
}

func CleanupExpiredTokens(rdb *redis.Client, userId int, c *gin.Context) {
	now := float64(time.Now().Unix())

	sessionKey := fmt.Sprintf("sessions:%d", userId)
	userTokenKey := fmt.Sprintf("user_refresh_tokens:%d", userId)

	rdb.ZRemRangeByScore(c, sessionKey, "0", fmt.Sprintf("%f", now))
	rdb.ZRemRangeByScore(c, userTokenKey, "0", fmt.Sprintf("%f", now))
}
