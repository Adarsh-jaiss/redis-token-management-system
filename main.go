package main

import (
	"fmt"
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/redis/go-redis/v9"
	"github.com/token-management/auth"
)

var rdb *redis.Client

func main() {
	rdb = redis.NewClient(&redis.Options{
		Addr:     "localhost:6380",
		Password: "test@123",
		DB:       0,
	})
	fmt.Println(rdb)

	api := gin.Default()

	api.POST("/auth", HandleAuth)

	ping := api.Group("ping")
	ping.Use(auth.AuthMiddleware()) // Add authentication middleware

	ping.GET("", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{
			"message": "pong",
		})
	})

	api.POST("/new",RegenerateAccessToken)

	api.Run()
}

// eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJlbWFpbCI6ImFkYXJzaEBnbWFpbC5jb20iLCJleHAiOjE3NDk1MzM4OTgsImlhdCI6MTc0ODkyOTA5OCwic2Vzc2lvbl9pZCI6ImQ0NjcyZWEyLWJhZWItNDQyNS1hYThjLWFiZjczNDhhZjY3MSIsInVzZXJfaWQiOjF9.UB659-BBYR0xz9NrjGPMFq2i8suweRtXx0ybfzxwnDA