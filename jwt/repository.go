package jwt

import (
	"errors"
	"fmt"

	"gorm.io/driver/sqlite"
	"gorm.io/gorm"

	"github.com/google/uuid"
)

var db *gorm.DB

type RefreshToken struct {
	ID       uuid.UUID `gorm:"primary_key;type:uuid;"`
	FamilyId uuid.UUID `gorm:"index"`
	Content  string    `gorm:"unique"`
	Valid    bool      `gorm:"default:true"`
}

func InsertRefreshTokenNewFamily(content string) (id uuid.UUID, err error) {
	id = uuid.New()
	familyId := uuid.New()

	refreshToken := RefreshToken{
		ID:       id,
		FamilyId: familyId,
		Content:  content,
	}

	db.Create(&refreshToken)

	return id, nil
}

func InsertRefreshTokenExistingFamily(content string, familyId string) (id uuid.UUID, err error) {
	var existing RefreshToken
	db.First(&existing, "ID = ?", familyId)

	if existing.ID == uuid.Nil {
		return uuid.Nil, errors.New("Refresh token family not found")
	}

	refreshToken := RefreshToken{
		ID:       uuid.New(),
		FamilyId: existing.FamilyId,
		Content:  content,
	}

	db.Create(&refreshToken)

	return refreshToken.ID, nil
}

func GetRefreshTokenByContents(contents string) (RefreshToken, error) {
	return RefreshToken{}, nil
}

// invalidateRefreshTokenTree invalidates all refresh tokens that are children of the given refresh token
func InvalidateRefreshTokenTree(refreshToken RefreshToken) error {
	return nil
}

// init initializes the database connection
func init() {
	configureDatabase()
}

func configureDatabase() {
	var err error
	db, err = gorm.Open(sqlite.Open("jwt-service.db"), &gorm.Config{})
	if err != nil {
		panic("failed to connect database")
	}

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
		fmt.Println("Seeding database")
		_, err := InsertRefreshTokenNewFamily("test")
		if err != nil {
			panic(err)
		}
	}
}
