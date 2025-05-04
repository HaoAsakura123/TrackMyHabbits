package app

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"
	"trackmyhabbits/internal/logic"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	"github.com/joho/godotenv"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

func DatabaseMiddleware(client *mongo.Client) gin.HandlerFunc {
	return func(c *gin.Context) {
		// Можно передать сам клиент или конкретную базу данных
		c.Set("mongoClient", client)

		c.Next()
	}
}

func GetUsers(c *gin.Context) {
	client := c.MustGet("mongoClient").(*mongo.Client)
	collection := client.Database("MongoDB").Collection("users")

	// Параметры пагинации из query-строки
	page, _ := strconv.Atoi(c.DefaultQuery("page", "1"))
	perPage, _ := strconv.Atoi(c.DefaultQuery("per_page", "5"))

	opts := options.Find().
		SetSort(bson.M{"age": 1}).
		SetSkip(int64((page - 1) * perPage)).
		SetLimit(int64(perPage))

	cursor, err := collection.Find(context.TODO(), bson.D{}, opts)
	if err != nil {
		c.JSON(500, gin.H{"error": err.Error()})
		return
	}
	defer cursor.Close(context.TODO())

	var results []bson.M
	if err = cursor.All(context.TODO(), &results); err != nil {
		c.JSON(500, gin.H{"error": err.Error()})
		return
	}

	c.JSON(200, gin.H{
		"page":    page,
		"perPage": perPage,
		"data":    results,
	})
}

func AddUser(c *gin.Context) {
	client := c.MustGet("mongoClient").(*mongo.Client)

	collection := client.Database("MongoDB").Collection("users")
	var user struct {
		Name    string `json:"name"`
		Surname string `json:"surname"`
		Age     string `json:"age"`
	}
	if err := c.ShouldBindJSON(&user); err != nil {
		c.JSON(400, gin.H{"error": "Invalid JSON"})
		return
	}
	insertResult, err := collection.InsertOne(context.TODO(), bson.M{
		"name":      user.Name,
		"surname":   user.Surname,
		"age":       user.Age,
		"createdAt": time.Now(),
	})

	if err != nil {
		c.JSON(500, gin.H{"error": err.Error()})
	}

	c.JSON(200, gin.H{
		"status":      "success",
		"created idx": insertResult.InsertedID,
	})

}

func AuthMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		err := godotenv.Load()
		if err != nil {
			log.Fatal("Error loading .env file")
		}

		JWTSecretKey := os.Getenv("JWTSecretKey")
		// 1. Получаем заголовок Authorization
		authHeader := c.GetHeader("Authorization")
		if authHeader == "" {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "Authorization header required"})
			return
		}

		// 2. Проверяем формат Bearer
		tokenString := strings.TrimPrefix(authHeader, "Bearer ")
		if tokenString == authHeader { // Если префикс не был удалён
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "Authorization format must be 'Bearer <token>'"})
			return
		}

		// 3. Парсим токен
		token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
			if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
				return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
			}
			return []byte(JWTSecretKey), nil
		})

		if err != nil {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "Invalid token", "details": err.Error()})
			return
		}

		// 4. Проверяем claims
		claims, ok := token.Claims.(jwt.MapClaims)
		if !ok || !token.Valid {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "Invalid token claims"})
			return
		}

		// 5. Сохраняем claims в контекст под ключом "userClaims"
		c.Set("userClaims", claims)
		c.Next() // Передаём управление следующему обработчику
	}
}

func Register(c *gin.Context) {
	client := c.MustGet("mongoClient").(*mongo.Client)
	collection := client.Database("MongoDB").Collection("users")

	var user struct {
		Name     string `json:"name" binding:"required"`
		Surname  string `json:"surname" binding:"required"`
		Age      string `json:"age"`
		Email    string `json:"email" binding:"required,email"`
		Password string `json:"password" binding:"required,min=8"`
	}

	if err := c.ShouldBindJSON(&user); err != nil {
		log.Printf("Validation error: %v", err)
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	var existingUser bson.M
	err := collection.FindOne(context.TODO(), bson.M{"email": user.Email}).Decode(&existingUser)
	if err == nil {
		c.JSON(http.StatusConflict, gin.H{"error": "User already exists"})
		return
	}

	hashedPassword, err := logic.HashPassword(user.Password)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Could not hash password"})
		return
	}

	// Создание нового пользователя
	newUser := bson.M{
		"name":      user.Name,
		"surname":   user.Surname,
		"age":       user.Age,
		"email":     user.Email,
		"password":  hashedPassword,
		"createdAt": time.Now(),
		"updatedAt": time.Now(),
		"roles":     []string{"user"},
	}

	insertResult, err := collection.InsertOne(context.TODO(), newUser)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Could not create user"})
		return
	}

	c.JSON(http.StatusCreated, gin.H{
		"status": "success",
		"userId": insertResult.InsertedID,
	})
}

func Login(c *gin.Context) {
	client := c.MustGet("mongoClient").(*mongo.Client)
	collection := client.Database("MongoDB").Collection("users")

	var credentials struct {
		Email    string `json:"email" binding:"required,email"`
		Password string `json:"password" binding:"required"`
	}

	if err := c.ShouldBindJSON(&credentials); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// Поиск пользователя
	var user bson.M
	err := collection.FindOne(context.TODO(), bson.M{"email": credentials.Email}).Decode(&user)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid credentials"})
		return
	}

	// Проверка пароля
	if !logic.CheckPasswordHash(credentials.Password, user["password"].(string)) {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid credentials"})
		return
	}

	// Генерация токена
	token, err := logic.GenerateToken(
		user["_id"].(primitive.ObjectID).Hex(),
		user["email"].(string),
		user["name"].(string),
		user["surname"].(string),
	)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Could not generate token"})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"token": token,
		"user": gin.H{
			"id":      user["_id"],
			"name":    user["name"],
			"surname": user["surname"],
			"email":   user["email"],
		},
	})
}

func AddHabit(c *gin.Context) {
	// 1. Получаем клиент MongoDB из контекста
	client := c.MustGet("mongoClient").(*mongo.Client)
	collection := client.Database("MongoDB").Collection("habits")
	collectionUSER := client.Database("MongoDB").Collection("users")
	// 2. Извлекаем данные пользователя из JWT токена
	userClaims, exists := c.Get("userClaims")
	if !exists {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "User claims not found"})
		return
	}

	claims, ok := userClaims.(jwt.MapClaims)
	if !ok {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Invalid token claims format"})
		return
	}

	// 3. Извлекаем конкретные поля из claims
	email, ok := claims["email"].(string)
	if !ok || email == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Email not found in token"})
		return
	}

	name, _ := claims["name"].(string)
	surname, _ := claims["surname"].(string)

	// 4. Парсим JSON с данными привычки
	var request struct {
		Habit string `json:"habit" binding:"required"`
	}

	if err := c.ShouldBindJSON(&request); err != nil {
		log.Printf("Validation error: %v", err)
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	if request.Habit == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Habit is required"})
		return
	}

	// 5. Проверяем, существует ли пользователь
	var existingUser bson.M
	err := collectionUSER.FindOne(context.TODO(), bson.M{"email": email}).Decode(&existingUser)
	if err != nil {
		if err == mongo.ErrNoDocuments {
			c.JSON(http.StatusNotFound, gin.H{"error": "User not found"})
		} else {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Database error"})
		}
		return
	}

	// 6. Проверяем, есть ли уже такая привычка
	err = collection.FindOne(context.TODO(), bson.M{
		"email": email,
		"habit": request.Habit,
	}).Decode(&existingUser)

	if err == nil {
		c.JSON(http.StatusConflict, gin.H{"error": "User already has this habit"})
		return
	} else if err != mongo.ErrNoDocuments {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Database error"})
		return
	}

	// 7. Создаём новую привычку
	_, err = collection.InsertOne(context.TODO(), bson.M{
		"name":      name,
		"surname":   surname,
		"email":     email,
		"habit":     request.Habit,
		"updatedAt": time.Now(),
		"createdAt": time.Now(),
	})

	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Could not create habit"})
		return
	}

	c.JSON(http.StatusCreated, gin.H{
		"status": "success",
		"habit":  request.Habit,
		"email":  email,
	})
}

func GetHabits(c *gin.Context) {
	// получить клиента
	client := c.MustGet("mongoClient").(*mongo.Client)
	// получить коллекцию
	collection := client.Database("MongoDB").Collection("habits")
	// получить запись исходя из токена userClaims
	userClaims, exists := c.Get("userClaims")
	if !exists {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "User claims not found"})
		return
	}
	//result := collection.Find(context.TODO(), userClaims[""])
	claims, ok := userClaims.(jwt.MapClaims)
	if !ok {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "cannot claim info from token"})
		return
	}
	email, ok := claims["email"].(string)
	if !ok {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "cannot get email from token"})
		return
	}

	cursor, err := collection.Find(context.TODO(), bson.M{"email": email})
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "cannot get information from DB"})
		return
	}
	var results []bson.M
	if err = cursor.All(context.TODO(), &results); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "cannot use cursor"})
		return
	}
	max := 0
	toret := make([]bson.M, 0)
	for iter, elem := range results {
		max = iter
		toret = append(toret, bson.M{"habit": elem["habit"].(string)})
	}
	c.JSON(http.StatusAccepted, gin.H{
		"status":   "access",
		"email":    email,
		"habits":   toret,
		"quantity": max,
	})
}

func PATCHHabit(c *gin.Context) {

	client := c.MustGet("mongoClient").(*mongo.Client)

	collection := client.Database("MongoDB").Collection("habits")

	userClaims, exists := c.Get("userClaims")
	if !exists {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "unauthorized user"})
		return
	}

	claims, ok := userClaims.(jwt.MapClaims)
	if !ok {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Invalid token claims format"})
		return
	}

	// 3. Извлекаем конкретные поля из claims
	email, ok := claims["email"].(string)
	if !ok || email == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Email not found in token"})
		return
	}
	//Берем из хеадера
	var request struct {
		Habit string `json:"habit" binding:"required"`
	}

	if err := c.ShouldBindJSON(&request); err != nil {
		log.Printf("Validation error: %v", err)
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	if request.Habit == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Habit is required"})
		return
	}
	//

	// Сначала находим и обновляем документ одной операцией
	var updatedDoc struct {
		Name    string    `json:"name" bson:"name"`
		Surname string    `json:"surname" bson:"surname"`
		Email   string    `json:"email" bson:"email"`
		Habit   string    `json:"habit" bson:"habit"`
		Updated time.Time `json:"updatedat" bson:"updatedat"`
		Created time.Time `json:"createdat" bson:"createdat"`
	}
	err := collection.FindOneAndUpdate(
		context.Background(),
		bson.M{"email": email, "habit": request.Habit},
		bson.M{"$set": bson.M{"updatedAt": time.Now()}},
		options.FindOneAndUpdate().SetReturnDocument(options.After), // Возвращает обновленный документ
	).Decode(&updatedDoc)

	if err != nil {
		if err == mongo.ErrNoDocuments {
			c.JSON(http.StatusNotFound, gin.H{"error": "User with this habit doesn't exist"})
			return
		}
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Database error"})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"status": "access",
		"result": updatedDoc,
	})
	//result := collection.FindOne(context.Background(), bson.D{})

}
