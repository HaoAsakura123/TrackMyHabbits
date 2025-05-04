package store

import (
	"context"
	"log"
	"time"

	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

const (
    TokenExpiration = 24 * time.Hour
)

type Storage interface {
	GetCollection() *mongo.Collection
	Close(ctx context.Context) error
	// Другие методы...
}

// MongoStore представляет хранилище MongoDB
type MongoStore struct {
	Client     *mongo.Client
	Database   string
	collection string
}

// NewMongoStore создает новое подключение к MongoDB
func NewMongoStore(ctx context.Context, uri, dbName, collectionName string) (*MongoStore, error) {
	ctx, cancel := context.WithTimeout(ctx, 10 * time.Second)
	defer cancel()

	client, err := mongo.Connect(ctx, options.Client().ApplyURI(uri))
	if err != nil {
		return nil, err
	}

	if err = client.Ping(ctx, nil); err != nil {
		return nil, err
	}

	log.Println("Connected to MongoDB!")

	return &MongoStore{
		Client:     client,
		Database:   dbName,
		collection: collectionName,
	}, nil
}

// Close закрывает подключение к MongoDB
func (s *MongoStore) Close(ctx context.Context) error {
	if s.Client != nil {
		return s.Client.Disconnect(ctx)
	}
	return nil
}

// GetCollection возвращает коллекцию для работы
func (s *MongoStore) GetCollection() *mongo.Collection {
	return s.Client.Database(s.Database).Collection(s.collection)
}

