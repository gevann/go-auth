package jwt

import (
	"errors"
	"fmt"

	"gorm.io/driver/sqlite"
	"gorm.io/gorm"

	"github.com/google/uuid"
)

var db *gorm.DB

// RefreshToken represents a refresh token in the databaseh
type RefreshToken struct {
	// ID is the ID of the refresh token
	ID uuid.UUID `gorm:"primary_key;type:uuid;"`
	// FamilyId is the ID of the refresh token family that this refresh token belongs to.
	// All refresh tokens in the same family are invalidated when one refresh token is invalidated.
	// Unique by AuthToken.
	Content string `gorm:"unique"`
	// AuthToken is the auth token that the refresh token is associated with.
	// All refresh tokens are either decendants of another refresh token or are
	// the first refresh token in a family directly related to the auth token that
	// it is associated with.
	AuthToken string `gorm:"index:idx_auth_token"`
	// Valid is whether or not the refresh token is valid.
	// When a refresh token is invalidated, all refresh tokens in the same family are invalidated.
	Valid bool `gorm:"default:true"`
}

// InsertRefreshTokenNewFamily inserts a new refresh token into the database
// with a new family ID.
// This is used when a new refresh token is generated from a new sign in.
//
// param content: The content of the refresh token
// param authToken: The auth token that the refresh token is associated with
// returns: The ID of the new refresh token
func InsertRefreshTokenNewFamily(content string, authToken string) (id uuid.UUID, err error) {
	id = uuid.New()

	refreshToken := RefreshToken{
		ID:        id,
		Content:   content,
		AuthToken: authToken,
	}

	db.Create(&refreshToken)

	return id, nil
}

// InsertRefreshTokenExistingFamily inserts a new refresh token into the database
// with the same family ID as the refresh token with the given ID.
// This is used when a refresh token is used to generate a new refresh token.
func InsertRefreshTokenExistingFamily(content string, authToken string) (id uuid.UUID, err error) {
	var existing RefreshToken
	db.First(&existing, "AuthToken = ?", authToken)

	if existing.ID == uuid.Nil {
		return uuid.Nil, errors.New("Refresh token family not found")
	}

	refreshToken := RefreshToken{
		ID:        uuid.New(),
		AuthToken: existing.AuthToken,
		Content:   content,
	}

	db.Create(&refreshToken)

	return refreshToken.ID, nil
}

// GetRefreshTokenByContents returns a refresh token found by its content.
// Typically used to check if a refresh token is valid.
func GetRefreshTokenByContents(contents string) (RefreshToken, error) {
	var refreshToken RefreshToken

	db.First(&refreshToken, "Content = ?", contents)

	if refreshToken == (RefreshToken{}) {
		return refreshToken, errors.New("Refresh token not found")
	}

	return refreshToken, nil
}

// invalidateRefreshTokenTree invalidates all refresh tokens in the family tree
func InvalidateRefreshTokenTree(authToken string) error {
	db.Model(&RefreshToken{}).Where("AuthToken = ?", authToken).Update("Valid", false)

	return nil
}

// init initializes the database connection
/*
func init() {
	configureDatabase("jwt-service.db")
}
*/

func ConfigureDatabase(dbName string) {
	var err error
	db, err = gorm.Open(sqlite.Open(dbName), &gorm.Config{})
	if err != nil {
		panic(fmt.Sprintf("Failed to connect to database %s: %s", dbName, err))
	}

	fmt.Printf("CONNECTED TO DATABASE %s\n", dbName)

	// Migrate the schema
	err = db.AutoMigrate(&RefreshToken{})
	if err != nil {
		panic(err)
	}

	seed()
}

func seed() {
	seededId, err := uuid.Parse("ddbe6b88-863a-492f-9c30-ee5908c09694")
	if err != nil {
		panic(err)
	}

	// Check if the seeded refresh token exists
	var seeded RefreshToken
	db.First(&seeded, "ID = ?", seededId)

	if seeded == (RefreshToken{}) {
		fmt.Printf("Seeding database %s with refresh token", db.Name())
		_, err := InsertRefreshTokenNewFamily("test", "auth-token")
		if err != nil {
			panic(err)
		}
	}
}
