package user

import (
	"reflect"
	"testing"

	"github.com/google/uuid"
)

func TestGetUserObject(t *testing.T) {
	type args struct {
		email string
	}
	tests := []struct {
		name    string
		args    args
		want    user
		wantErr bool
	}{
		{
			name: "With an existing user",
			args: args{
				email: "existinguser@email.com",
			},
			want: user{
				dbData: dbData{
					ID:        uuid.Nil,
					CreatedAt: 0,
				},
				pii: pii{
					Email:        "existinguser@email.com",
					PasswordHash: "password",
					FullName:     "Existing Admin User",
					Role:         0,
				},
			},

			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := GetUserObject(tt.args.email)
			if (err != nil) != tt.wantErr {
				t.Errorf("GetUserObject() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if !reflect.DeepEqual(got.pii, tt.want.pii) {
				t.Errorf("GetUserObject() got = %v, want %v", got.pii, tt.want.pii)
			}
		})
	}
}
