package user

import (
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"os"
	"time"

	"github.com/google/uuid"
	"golang.org/x/crypto/bcrypt"
)

type dbData struct {
	ID        uuid.UUID `json:"id"`
	CreatedAt int64     `json:"created_at"`
}

type pii struct {
	Email    string `json:"email"`
	FullName string `json:"fullName"`
	Role     int    `json:"role"`
}

type passwordProtected struct {
	Hash string `json:"passwordHash"`
}

type User struct {
	DbData   dbData
	Pii      pii
	Password passwordProtected
}

var users = []User{}
var usersJsonFile string

func init() {
	// Set the users json file path from the environment variable
	usersJsonFile = os.Getenv("USERS_JSON_FILE")
	// unmarshal users from json file
	file, err := os.Open(usersJsonFile)
	defer file.Close()
	if os.IsNotExist(err) {
		file, err = os.Create(usersJsonFile)
		defer file.Close()
	}
	if err != nil {
		panic(err)
	}

	decoder := json.NewDecoder(file)

	err = decoder.Decode(&users)
	if err != nil {
		if err.Error() == "EOF" {
			users = []User{}
		} else {
			panic(err)
		}
	}

	// Seed an existing admin user for testing
	if len(users) == 0 {
		hashedPassword := HashPassword("password")
		user, err := AddUserObject("existinguser@email.com", "Existing Admin User", hashedPassword, 0)

		if err != nil {
			panic(err)
		}

		users = append(users, user)
	}
}

func HashPassword(password string) string {
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		log.Fatal(err)
	}
	return string(hash)
}

func GetUserObject(email string) (User, error) {
	for _, user := range users {
		if user.Pii.Email == email {
			return user, nil
		}
	}

	return User{}, errors.New("User not found")
}

func GetUserById(id uuid.UUID) (User, error) {
	for _, user := range users {
		if user.DbData.ID == id {
			return user, nil
		}
	}

	return User{}, errors.New("User not found")
}

func (instance *User) ValidatePasswordHash(cleartext string) bool {
	return bcrypt.CompareHashAndPassword([]byte(instance.Password.Hash), []byte(cleartext)) == nil
}

// AddUserObject adds a new user to the application.
// If the user already exists, it will return an error.
// Returns the added user object and any errors.
func AddUserObject(email, fullname, passwordHash string, role int) (User, error) {
	newUser := User{
		DbData: dbData{
			ID:        uuid.New(),
			CreatedAt: time.Now().Unix(),
		},
		Pii: pii{
			Email:    email,
			FullName: fullname,
			Role:     role,
		},
		Password: passwordProtected{
			Hash: passwordHash,
		},
	}

	existingUser, _ := GetUserObject(email)

	if existingUser != (User{}) {
		fmt.Printf("User already exists: %v\n", existingUser)
		return existingUser, errors.New("User already exists")
	}

	users = append(users, newUser)

	// marshal users to json file
	file, err := os.Create(usersJsonFile)

	defer file.Close()

	if err != nil {
		panic(err)
	}

	encoder := json.NewEncoder(file)

	err = encoder.Encode(users)

	if err != nil {
		panic(err)
	}

	return newUser, nil
}
