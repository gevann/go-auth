package jwt

import (
	"os"
	"testing"
)

func TestMain(m *testing.M) {
	configureDatabase("jwt-service.test.db")
	exitVal := m.Run()
	os.Remove("jwt-service.test.db")

	os.Exit(exitVal)
}

func TestGenerate(t *testing.T) {
	type args struct {
		payloadMap map[string]string
		secret     string
	}
	type tokens struct {
		access  string
		refresh string
	}

	tests := []struct {
		name    string
		args    args
		want    tokens
		wantErr bool
	}{
		{
			name: "With valid inputs",
			args: args{
				payloadMap: map[string]string{"email": "foo@bar.com", "role": "0"},
				secret:     "secret",
			},
			want: tokens{
				access:  "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJlbWFpbCI6ImZvb0BiYXIuY29tIiwicm9sZSI6IjAifQ==.7qIvfw2PCfu5DfbbsaGBJFoXvyEWpsCm460nMjC3yuk=",
				refresh: "foobar",
			},
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			accessToken, _, err := Generate(tt.args.payloadMap, tt.args.secret)
			if (err != nil) != tt.wantErr {
				t.Errorf("Generate() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if accessToken != tt.want.access {
				t.Errorf("Generate().accessToken = %s, want %s", accessToken, tt.want.access)
			}
			//TODO: check refresh token
		})
	}
}
