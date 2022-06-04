package user

import (
	"encoding/json"
	"errors"
	"os"
	"time"

	"github.com/google/uuid"
)

type dbData struct {
	ID        uuid.UUID `json:"id"`
	CreatedAt int64     `json:"created_at"`
}

type pii struct {
	Email        string `json:"email"`
	PasswordHash string `json:"passwordHash"`
	FullName     string `json:"fullName"`
	Role         int    `json:"role"`
}

type user struct {
	dbData
	pii
}

var users = []user{}

func init() {
	// unmarshal users from json file
	file, err := os.Open("users.json")
	defer file.Close()
	if err != nil {
		panic(err)
	}

	decoder := json.NewDecoder(file)

	err = decoder.Decode(&users)
	if err != nil {
		if err.Error() == "EOF" {
			users = []user{}
		} else {
			panic(err)
		}
	}

	// Seed an existing admin user for testing
	if len(users) == 0 {
		user, err := AddUserObject("existinguser@email.com", "Existing Admin User", "password", 0)

		if err != nil {
			panic(err)
		}

		users = append(users, user)
	}
}

func GetUserObject(email string) (user, error) {
	for _, user := range users {
		if user.Email == email {
			return user, nil
		}
	}

	return user{}, errors.New("User not found")
}

func (instance *user) ValidatePasswordHash(pwsdhash string) bool {
	return instance.PasswordHash == pwsdhash
}

func AddUserObject(email, fullname, passwordHash string, role int) (user, error) {
	newUser := user{
		dbData: dbData{
			ID:        uuid.New(),
			CreatedAt: time.Now().Unix(),
		},
		pii: pii{
			Email:        email,
			PasswordHash: passwordHash,
			FullName:     fullname,
			Role:         role,
		},
	}

	existingUser, err := GetUserObject(email)

	if err == nil {
		return existingUser, errors.New("User already exists")
	}

	users = append(users, newUser)

	// marshal users to json file
	file, err := os.Create("users.json")

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
