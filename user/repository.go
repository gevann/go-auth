package user

import (
	"fmt"

	"gorm.io/driver/sqlite"
	"gorm.io/gorm"

	"github.com/google/uuid"
)

var db *gorm.DB

func insertUser(user User) (id uuid.UUID, err error) {
	id = uuid.New()
	user.DbData.ID = id

	// Check if email already exists
	existing, err := getUserByEmail(user.Pii.Email)

	if err != nil {
		return uuid.Nil, err
	}

	if existing != (User{}) {
		return uuid.Nil, fmt.Errorf("Email already exists")
	}

	db.Create(&user)

	return id, nil
}

func getUserByEmail(email string) (User, error) {
	var user User
	db.First(&user, "Email = ?", email)

	return user, nil
}

func getUserById(id uuid.UUID) (User, error) {
	var user User
	db.First(&user, "ID = ?", id)

	return user, nil
}

func init() {
	configureDatabase()
}

func configureDatabase() {
	var err error
	db, err = gorm.Open(sqlite.Open("user-service.db"), &gorm.Config{})
	if err != nil {
		panic("failed to connect database")
	}

	// Migrate the schema
	err = db.AutoMigrate(&User{})
	if err != nil {
		panic(err)
	}

	seed()
}

func seed() {
	// Check if the seeded refresh token exists
	email := "user@example.com"
	var seeded User
	db.First(&seeded, "Email = ?", email)

	if seeded == (User{}) {
		fmt.Println("Seeding database")
		_, err := insertUser(User{
			DbData: dbData{},
			Pii: pii{
				Email:    email,
				FullName: "User Example",
				Role:     0,
			},
			Password: passwordProtected{
				Hash: HashPassword("password"),
			},
		})

		if err != nil {
			panic(err)
		}
	}
}
