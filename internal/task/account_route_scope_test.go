package task

import "testing"

func TestJoinAccountRouteScope(t *testing.T) {
	cases := []struct {
		name       string
		oauth      bool
		invitation bool
		want       bool
	}{
		{name: "initial invitation uses mother route", oauth: false, invitation: false, want: false},
		{name: "invitation pending uses mother route", oauth: true, invitation: false, want: false},
		{name: "oauth authorization pins target route", oauth: true, invitation: true, want: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := joinUsesAccountRoute(JoinTarget{OAuthAuthorized: tc.oauth, InvitationConfirmed: tc.invitation}); got != tc.want {
				t.Fatalf("join route scope=%v, want %v", got, tc.want)
			}
		})
	}
}
