package main

import (
	"context"
	"log"
	"os"
	"time"

	"trackmyhabbits/internal/app"
	"trackmyhabbits/internal/logic"
	"trackmyhabbits/internal/storage"

	"github.com/gin-gonic/gin"
)

func main() {
	ctx := context.Background()

	// Инициализация хранилища

	mongoURI := os.Getenv("MONGO_URI")
	if mongoURI == "" {
		mongoURI = "mongodb://localhost:27017"
	}

	mongoStore, err := store.NewMongoStore(
		ctx,
		mongoURI,
		os.Getenv("MONGO_DB"),
		os.Getenv("MONGO_COLLECTION"),
	)
	if err != nil {
		log.Fatalf("Failed to connect to MongoDB: %v", err)
	}
	defer func() {
		if err := mongoStore.Close(ctx); err != nil {
			log.Printf("Error closing MongoDB connection: %v", err)
		}
	}()

	r := gin.Default()
	r.Use(app.DatabaseMiddleware(mongoStore.Client))

	r.POST("/register", app.Register)
	r.POST("/login", app.Login)

	// Защищенные маршруты
	authGroup := r.Group("/api")
	authGroup.Use(app.AuthMiddleware())
	{
		authGroup.POST("/habits", app.AddHabit)
		authGroup.GET("/habits", app.GetHabits)
		authGroup.GET("/users", app.GetUsers)
		authGroup.PATCH("/habits", app.PATCHHabit)
	}

	go logic.DelHabit(context.WithValue(context.Background(), "mongoClient", mongoStore.Client), 24*time.Hour)
	r.Run(":8080")

}
