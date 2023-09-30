package session

import (
	"errors"
	"fmt"
	"time"

	"log/slog"

	"github.com/gokutils/uuid"
	"github.com/golang-jwt/jwt"
)

var (
	SessionBadSecret = errors.New("error.session.bad_secret")
	SessionNotFound  = errors.New("error.session.not_found")
)

type JWT struct {
	secret       []byte
	issuer       string
	sessionStore SessionStore
}

func NewJWTTokenManager(secret []byte, issuer string, sessionStore SessionStore) (*JWT, error) {
	if len(secret) == 0 {
		return nil, SessionBadSecret
	}
	return &JWT{secret: secret, sessionStore: sessionStore, issuer: issuer}, nil
}

type CustomClaim struct {
	jwt.StandardClaims
	Security string            `json:"security,omitempty"`
	Username string            `json:"username,omitempty"`
	Extra    map[string]string `json:"extra,omitempty"`
}

func (claim CustomClaim) GetSessionID() uuid.UUID {
	return uuid.ParseOrNil(claim.Id)
}

func (claim CustomClaim) GetUserID() uuid.UUID {
	return uuid.ParseOrNil(claim.Subject)
}

func (claim CustomClaim) GetUsername() string {
	return claim.Username
}

func (claim CustomClaim) GetExtra() map[string]string {
	return claim.Extra
}

func (claim CustomClaim) AdminType() string {
	if v, ok := claim.Extra["admin"]; ok {
		if len(v) == 0 {
			return ""
		}
		return v
	}
	return ""
}

func (claim CustomClaim) LogValue() slog.Value {
	return slog.StringValue(claim.GetUserID().String())
}

func (impl JWT) GetTokenFromUser(u User, security string, duration time.Duration, extra map[string]string) (string, error) {
	var (
		now        = jwt.TimeFunc()
		expiration = now.Add(duration * time.Second)
		id         = uuid.New()
	)
	if extra == nil {
		extra = map[string]string{}
	}
	extra["admin"] = string(u.AdminType())

	claims := CustomClaim{
		StandardClaims: jwt.StandardClaims{
			ExpiresAt: expiration.Unix(),
			Id:        id.String(),
			IssuedAt:  now.Unix(),
			Issuer:    impl.issuer,
			NotBefore: now.Unix(),
			Subject:   u.GetUserID().String(),
		},
		Security: security,
		Username: u.GetUsername(),
		Extra:    extra,
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	ss, err := token.SignedString(impl.secret)
	if err != nil {
		return "", err
	}
	if impl.sessionStore != nil {
		err = impl.sessionStore.Save(id, u.GetUserID(), expiration)
	}
	return ss, err
}

func (impl JWT) decodeToken(tokenString string) (CustomClaim, error) {
	token, err := jwt.ParseWithClaims(tokenString, &CustomClaim{}, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("Unexpected signing method: %v", token.Header["alg"])
		}
		return impl.secret, nil
	})
	if err != nil {
		return CustomClaim{}, err
	}
	claims, ok := token.Claims.(*CustomClaim)
	if !ok {
		return CustomClaim{}, errors.New("Unable to convert claims")
	}

	if !token.Valid {
		return CustomClaim{}, err
	}
	return *claims, nil
}

func (impl JWT) GetUserFromToken(tokenString string, security string) (User, error) {
	claims, err := impl.decodeToken(tokenString)
	if err != nil {
		return nil, err
	}
	if impl.sessionStore != nil {
		if impl.sessionStore.Valid(claims.GetSessionID(), claims.GetUserID()) {
			return claims, nil
		} else {
			return nil, SessionNotFound
		}
	} else {
		return claims, nil
	}
}

func (impl JWT) Delete(tokenString string) error {
	claims, err := impl.decodeToken(tokenString)
	if err != nil {
		return err
	}
	if impl.sessionStore == nil {
		return nil
	}
	return impl.sessionStore.Delete(claims.GetSessionID())
}
