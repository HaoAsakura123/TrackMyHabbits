package logic

import (
	"context"
	"fmt"
	"log"
	"os"
	"time"

	//"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	"github.com/joho/godotenv"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
	"golang.org/x/crypto/bcrypt"
)

func GenerateToken(userID string, email string, name string, surname string) (string, error) {
	err := godotenv.Load()
	if err != nil {
		log.Fatal("Error loading .env file")
	}

	JWTSecretKey := os.Getenv("JWTSecretKey")
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"user_id": userID,                                // ID пользователя
		"email":   email,                                 // Email
		"name":    name,                                  // Имя
		"surname": surname,                               // Фамилия
		"exp":     time.Now().Add(24 * time.Hour).Unix(), // Срок действия
	})
	return token.SignedString([]byte(JWTSecretKey))
}

func ParseToken(tokenString string) (*jwt.Token, error) {
	err := godotenv.Load()
	if err != nil {
		log.Fatal("Error loading .env file")
	}
	JWTSecretKey := os.Getenv("JWTSecretKey")
	return jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return []byte(JWTSecretKey), nil
	})
}

func HashPassword(password string) (string, error) {
	bytes, err := bcrypt.GenerateFromPassword([]byte(password), 14)
	return string(bytes), err
}

func CheckPasswordHash(password, hash string) bool {
	err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(password))
	return err == nil
}

func DelHabit(ctx context.Context, interval time.Duration) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	if err := doHabitDelete(ctx); err != nil {
		log.Printf("Cannot delete unused habit\n")
	}

	for {
		select {
		case <-ctx.Done():
			log.Printf("Procces DelHabit was stopped by context\n")
		case <-ticker.C:
			if err := doHabitDelete(ctx); err != nil {
				log.Printf("Cannot delete unused habit\n")
			}
		}

	}
}

func doHabitDelete(ctx context.Context) error {
	client := ctx.Value("mongoClient").(*mongo.Client)
	collection := client.Database("MongoDB").Collection("habits")

	cutoffTime := time.Now().Add(24 * time.Hour)

	filter := bson.M{
		"updatedAt": bson.M{"$lt": cutoffTime},
	}

	result, err := collection.DeleteMany(context.TODO(), filter)
	if err != nil {
		return err
	}

	println("Deleted", result.DeletedCount, "documents")
	return nil
}
