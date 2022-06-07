package user

import (
	"reflect"
	"testing"
)

func TestGetUserObject(t *testing.T) {
	type args struct {
		email string
	}
	tests := []struct {
		name    string
		args    args
		want    User
		wantErr bool
	}{
		{
			name: "With an existing user",
			args: args{
				email: "existinguser@email.com",
			},
			want: User{
				DbData: dbData{},
				Pii: pii{
					Email:    "existinguser@email.com",
					FullName: "Existing Admin User",
					Role:     0,
				},
				Password: passwordProtected{},
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

			if !reflect.DeepEqual(got.Pii, tt.want.Pii) {
				t.Errorf("GetUserObject() got = %v, want %v", got.Pii, tt.want.Pii)
			}

			if !got.ValidatePasswordHash("password") {
				t.Errorf("GetUserObject() got = %v, want %v", got.Pii, tt.want.Pii)
			}
		})
	}
}
