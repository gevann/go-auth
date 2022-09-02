package user

import (
	"log"
	"time"

	"github.com/google/uuid"
	"golang.org/x/crypto/bcrypt"
)

type dbData struct {
	ID        uuid.UUID `json:"id" gorm:"primary_key;type:uuid;"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

type pii struct {
	Email    string `json:"email" gorm:"uniqueIndex"`
	FullName string `json:"fullName"`
	Role     int    `json:"role"`
}

type passwordProtected struct {
	Hash string `json:"passwordHash" gorm:"not null"`
}

type User struct {
	DbData   dbData            `gorm:"embedded"`
	Pii      pii               `gorm:"embedded"`
	Password passwordProtected `gorm:"embedded"`
}

func HashPassword(password string) string {
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		log.Fatal(err)
	}
	return string(hash)
}

// InsertUser inserts a new user into the database.
// If the user already exists, it will return an error.
// Returns the added user object and any errors.
func InsertUser(email, fullName, password string, role int) (User, error) {
	// call repository function to insert user
	user := User{
		Pii: pii{
			Email:    email,
			FullName: fullName,
			Role:     role,
		},
		Password: passwordProtected{
			Hash: HashPassword(password),
		},
	}

	_, err := insertUser(user)

	if err != nil {
		return User{}, err
	}

	return user, nil
}

// GetUserByEmail returns a user object from the database.
// If the user does not exist, it will return a blank user object.
// Returns the user object and any errors.
func GetUserByEmail(email string) (User, error) {
	// call repository function to get user
	user, err := getUserByEmail(email)

	if err != nil {
		return User{}, err
	}

	return user, nil
}

// GetUserById returns a user object from the database.
// If the user does not exist, it will return a blank user object.
// Returns the user object and any errors.
func GetUserById(id uuid.UUID) (User, error) {
	// call repository function to get user
	user, err := getUserById(id)

	if err != nil {
		return User{}, err
	}

	return user, nil
}

func (instance *User) ValidatePasswordHash(cleartext string) bool {
	return bcrypt.CompareHashAndPassword([]byte(instance.Password.Hash), []byte(cleartext)) == nil
}
