package main

import (
	"fmt"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	"github.com/token-management/auth"
	"github.com/token-management/types"

	"net/http"
)

func HandleAuth(c *gin.Context) {
	var authRequestBody types.UserAuth
	err := c.ShouldBindJSON(&authRequestBody)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	if authRequestBody.Email != "adarsh@gmail.com" && authRequestBody.Password != "123123123" {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "wrong credentials"})
		return
	}

	userId := 1

	accessToken, err := auth.GenerateAccessToken(userId, authRequestBody.Email)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error(), "message": "error generating access token"})
		return
	}
	refreshToken, err := auth.GenerateRefreshToken(1, authRequestBody.Email)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error(), "message": "error generating refresh token"})
		return
	}

	err = auth.SaveTokenToDB(refreshToken, rdb, c)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error(), "message": "error saving refresh token to db"})
		return
	}

	auth.CleanupExpiredTokens(rdb, userId, c)

	c.SetCookie("refresh_token", refreshToken, 7*24*60*60, "/", "", false, true)

	c.JSON(http.StatusOK, gin.H{
		"token": accessToken,
	})
}

type ReqBody struct {
	RefreshToken string `json:"refresh_token"`
}

func RegenerateAccessToken(c *gin.Context) {
	refreshToken, err := c.Cookie("refresh_token")
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "refresh token not found"})
		return
	}

	if refreshToken == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "token not found"})
	}

	fmt.Println("token sent from client:", refreshToken)

	claims, err, ok := auth.ValidateToken(refreshToken)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": fmt.Errorf("invalid or expired refresh token : %v", err)})
		return
	}
	if !ok {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid token"})
	}

	tokenClaims, ok := claims.Claims.(jwt.MapClaims)
	if !ok {
		c.JSON(http.StatusInternalServerError, gin.H{
			"message": fmt.Sprintf("failed to parse token claims:%v", err),
		})
		return
	}
	sessionId := tokenClaims["session_id"].(string)
	// hashedRefreshToken := auth.HashToken(refreshToken)
	// fmt.Println("hashedRefreshToken:", hashedRefreshToken)

	exists, err := rdb.Exists(c, "refresh:"+sessionId).Result()
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "error checking refresh token", "err": err.Error()})
		return
	}
	if exists == 0 {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "refresh token not found in database, login again"})
		return
	}

	// fetching the ttl
	refreshTokenTTL, err := rdb.TTL(c, "refresh:"+sessionId).Result()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": "ttl not found fot the refresh token", "token": refreshToken,
		})
		return
	}
	fmt.Println("refresh token ttl- ", refreshTokenTTL)

	refreshTokenTTLInSeconds, err := time.ParseDuration(refreshTokenTTL.String())
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": "failed to parse ttl",
		})
	}
	fmt.Println("rt ttl in sec:", refreshTokenTTLInSeconds.Seconds())

	res, err := auth.ExtractClaims(refreshToken)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": "failed to extract claims from refresh token",
		})
		return
	}
	fmt.Println("res from extract claims:", res)
	if res["user_id"] == nil || res["email"] == nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": "user_id or email not found in refresh token",
		})
		return
	}
	if res["user_id"].(int) <= 0 || res["email"].(string) == "" {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": "invalid user_id or email in refresh token",
		})
		return
	}

	var newRefreshToken string
	if refreshTokenTTLInSeconds.Seconds() < 300 {
		newRefreshToken, err = auth.GenerateRefreshToken(res["user_id"].(int), res["email"].(string))
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error(), "message": "error generating new refresh token"})
			return
		}

		if newRefreshToken == "" {
			c.JSON(http.StatusInternalServerError, gin.H{
				"error": "new refresh token is empty",
			})
			return
		}
		err = auth.SaveTokenToDB(newRefreshToken, rdb, c)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error(), "message": "error saving new refresh token to db"})
			return
		}
		c.SetCookie("refresh_token", newRefreshToken, 7*24*60*60, "/", "", false, true)
	}

	newAccessToken, err := auth.GenerateAccessToken(res["user_id"].(int), res["email"].(string))
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error(), "message": "error generating new access token"})
		return
	}

	refreshTokenGenerated := false
	if newRefreshToken != "" {
		refreshTokenGenerated = true
	}

	c.JSON(http.StatusOK, gin.H{
		"token":                   newAccessToken,
		"message":                 "access token regenerated successfully",
		"refresh_token_generated": refreshTokenGenerated,
	})
}
