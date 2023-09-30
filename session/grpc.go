package session

import (
	"context"
	"crypto/sha1"
	"encoding/base64"
	"errors"
	"net/http"
	"strings"

	"google.golang.org/grpc"
	"google.golang.org/grpc/metadata"
)

const sessionDuration = 86400 // 24h
const cookieName = "user-session"

type UserContextTypKey string

const UserInContext UserContextTypKey = "user-session-context"

var UserNotFound = errors.New("error.user.not_found")

type GrpcSession struct {
	TokenManager TokenManager
}

func (impl GrpcSession) GetSecurity(md metadata.MD) (string, error) {
	var (
		_hash = sha1.New()
		datas = []string{}
	)
	datas = append(datas, md.Get("accept-encoding")...)
	datas = append(datas, md.Get("accept-language")...)
	datas = append(datas, md.Get("user-agent")...)
	datas = append(datas, md.Get("origin")...)
	if _, err := _hash.Write([]byte(strings.Join(datas, ":"))); err != nil {
		return "", err
	}
	sum := _hash.Sum([]byte{})
	return base64.StdEncoding.EncodeToString(sum), nil
}

func (impl GrpcSession) GetSecurityFromRequest(req *http.Request) (string, error) {
	var (
		_hash = sha1.New()
		datas = []string{}
	)
	datas = append(datas, req.Header.Get("accept-encoding"))
	datas = append(datas, req.Header.Get("accept-language"))
	datas = append(datas, req.Header.Get("user-agent"))
	datas = append(datas, req.Header.Get("origin"))
	if _, err := _hash.Write([]byte(strings.Join(datas, ":"))); err != nil {
		return "", err
	}
	sum := _hash.Sum([]byte{})
	return base64.StdEncoding.EncodeToString(sum), nil
}

func (impl GrpcSession) SetUser(ctx context.Context, usr User, extra map[string]string) error {
	return impl.SetUserHasHeader(ctx, "Set-Cookie", usr, extra)
}

func (impl GrpcSession) SetUserHasHeader(ctx context.Context, header string, usr User, extra map[string]string) error {
	md, ok := metadata.FromIncomingContext(ctx)
	if !ok {
		return UserNotFound
	}
	securityKey, err := impl.GetSecurity(md)
	if err != nil {
		return UserNotFound
	}
	token, err := impl.TokenManager.GetTokenFromUser(usr, securityKey, sessionDuration, extra)
	if err != nil {
		return err
	}

	cookie := &http.Cookie{
		Name:   cookieName,
		Value:  token,
		MaxAge: sessionDuration,
		Secure: true,
		// SameSite: http.SameSiteLaxMode,
		Path:     "/",
		HttpOnly: true,
	}

	return grpc.SetHeader(ctx, metadata.MD{
		header: []string{cookie.String()},
	})
}
func (impl GrpcSession) GetUserToken(ctx context.Context, usr User, extra map[string]string) (string, error) {
	md, ok := metadata.FromIncomingContext(ctx)
	if !ok {
		return "", UserNotFound
	}
	securityKey, err := impl.GetSecurity(md)
	if err != nil {
		return "", UserNotFound
	}
	token, err := impl.TokenManager.GetTokenFromUser(usr, securityKey, sessionDuration, extra)
	if err != nil {
		return "", err
	}
	return token, nil
}

func (impl GrpcSession) GetHeaderForCookieFromRequest(req *http.Request, usr User, extra map[string]string) (string, error) {
	securityKey, err := impl.GetSecurityFromRequest(req)
	if err != nil {
		return "", UserNotFound
	}
	token, err := impl.TokenManager.GetTokenFromUser(usr, securityKey, sessionDuration, extra)
	if err != nil {
		return "", err
	}

	cookie := &http.Cookie{
		Name:   cookieName,
		Value:  token,
		MaxAge: sessionDuration,
		Secure: true,
		// SameSite: http.SameSiteLaxMode,
		Path:     "/",
		HttpOnly: true,
	}
	return cookie.String(), nil
}

func (impl GrpcSession) MoveUserToRequestCtx(req *http.Request) *http.Request {
	cookie, err := req.Cookie(cookieName)
	if err != nil {
		return req
	}
	securityKey, err := impl.GetSecurityFromRequest(req)
	if err != nil {
		return req
	}
	usr, err := impl.TokenManager.GetUserFromToken(cookie.Value, securityKey)
	if err != nil {
		return req
	}

	return req.WithContext(context.WithValue(req.Context(), UserInContext, usr))
}

func GetUserContextKey() UserContextTypKey {
	return UserInContext
}

func (impl GrpcSession) GetUser(ctx context.Context) (User, error) {
	if _usr := ctx.Value(UserInContext); _usr != nil {
		return _usr.(User), nil
	}
	md, ok := metadata.FromIncomingContext(ctx)
	if !ok {
		return nil, UserNotFound
	}
	securityKey, err := impl.GetSecurity(md)
	if err != nil {
		return nil, UserNotFound
	}
	values := md.Get("cookie")
	header := http.Header{"Cookie": values}
	req := http.Request{Header: header}
	cookie, err := req.Cookie(cookieName)
	if err != nil {
		return nil, UserNotFound
	}
	return impl.TokenManager.GetUserFromToken(cookie.Value, securityKey)
}

func (impl GrpcSession) GetUserFromAuthorizationHeader(ctx context.Context) (User, error) {
	if _usr := ctx.Value(UserInContext); _usr != nil {
		return _usr.(User), nil
	}
	md, ok := metadata.FromIncomingContext(ctx)
	if !ok {
		return nil, UserNotFound
	}
	values := md.Get("authorization")
	if len(values) == 1 {
		return impl.TokenManager.GetUserFromToken(values[0], "")
	}
	return nil, UserNotFound
}

func (impl GrpcSession) GetExtra(ctx context.Context, key string) (string, bool) {
	usr, err := impl.GetUser(ctx)
	if err != nil {
		return "", false
	}
	if v, ok := usr.(CustomClaim); ok {
		valueOfKey, ok := v.Extra[key]
		return valueOfKey, ok
	}
	return "", false
}

func (impl GrpcSession) Disconnect(ctx context.Context) error {
	cookie := &http.Cookie{
		Name:   cookieName,
		Value:  "deleted",
		MaxAge: -1,
		// SameSite: http.SameSiteLaxMode,
		Secure:   true,
		Path:     "/",
		HttpOnly: true,
	}
	return grpc.SetHeader(ctx, metadata.MD{
		"Set-Cookie": []string{cookie.String()},
	})
}

func (inpl GrpcSession) HaveUserInContext(ctx context.Context) bool {
	if _usr := ctx.Value(UserInContext); _usr != nil {
		return true
	} else {
		return false
	}
}

func GetUserContext(ctx context.Context) User {
	if _usr := ctx.Value(UserInContext); _usr != nil {
		return _usr.(User)
	} else {
		return nil
	}
}

func NewSession(secret []byte, issuer string, sessionStore SessionStore) (SessionManager, error) {
	jwt, err := NewJWTTokenManager(secret, issuer, sessionStore)
	if err != nil {
		return nil, err
	}
	return &GrpcSession{
		TokenManager: jwt,
	}, nil
}
