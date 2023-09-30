package session

import (
	"context"
	"net/http"
	"time"

	"github.com/gokutils/uuid"
)

type User interface {
	GetUserID() uuid.UUID
	GetUsername() string
	AdminType() string
}

type TokenManager interface {
	GetTokenFromUser(u User, security string, duration time.Duration, Extra map[string]string) (string, error)
	GetUserFromToken(tokenString string, security string) (User, error)
	Delete(tokenString string) error
}

type SessionStore interface {
	Save(id uuid.UUID, userId uuid.UUID, expireAt time.Time) error
	Valid(id uuid.UUID, userID uuid.UUID) bool
	Delete(id uuid.UUID) error
}

type SessionManager interface {
	MoveUserToRequestCtx(req *http.Request) *http.Request
	SetUser(ctx context.Context, usr User, extra map[string]string) error
	HaveUserInContext(ctx context.Context) bool
	GetUserFromAuthorizationHeader(ctx context.Context) (User, error)
	GetUserToken(ctx context.Context, usr User, extra map[string]string) (string, error)
	GetUser(ctx context.Context) (User, error)
	Disconnect(ctx context.Context) error
	GetHeaderForCookieFromRequest(req *http.Request, usr User, extra map[string]string) (string, error)
}
