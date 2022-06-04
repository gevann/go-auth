package jwt

import "testing"

func TestGenerate(t *testing.T) {
	type args struct {
		payloadMap map[string]string
		secret     string
	}
	tests := []struct {
		name    string
		args    args
		want    string
		wantErr bool
	}{
		{
			name: "With valid inputs",
			args: args{
				payloadMap: map[string]string{"email": "foo@bar.com", "role": "0"},
				secret:     "secret",
			},
			want:    "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJlbWFpbCI6ImZvb0BiYXIuY29tIiwicm9sZSI6IjAifQ==.7qIvfw2PCfu5DfbbsaGBJFoXvyEWpsCm460nMjC3yuk=",
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := Generate(tt.args.payloadMap, tt.args.secret)
			if (err != nil) != tt.wantErr {
				t.Errorf("Generate() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if got != tt.want {
				t.Errorf("Generate() = %s, want %s", got, tt.want)
			}
		})
	}
}
