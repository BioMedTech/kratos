package session

import (
	"context"
	"golang.org/x/oauth2"
	"net/http"
	"time"

	"github.com/pkg/errors"

	"github.com/ory/x/sqlcon"

	"github.com/ory/herodot"

	"github.com/ory/kratos/x"
)

type TokenRefresher interface {
	RefreshToken(context.Context, *oauth2.Token, string) (*oauth2.Token, error)
}

type (
	ManagerHTTPOIDC struct {
		c              managerHTTPConfiguration
		cookieName     string
		r              managerHTTPDependencies
		tokenRefresher TokenRefresher
	}
)

func NewManagerHTTPOIDC(
	c managerHTTPConfiguration,
	r managerHTTPDependencies,
	tokenRefresher TokenRefresher,
) *ManagerHTTPOIDC {
	return &ManagerHTTPOIDC{
		c:              c,
		r:              r,
		cookieName:     DefaultSessionCookieName,
		tokenRefresher: tokenRefresher,
	}
}

func (s *ManagerHTTPOIDC) CreateToRequest(ctx context.Context, w http.ResponseWriter, r *http.Request, ss *Session) error {
	if err := s.r.SessionPersister().CreateSession(ctx, ss); err != nil {
		return err
	}

	if err := s.SaveToRequest(ctx, w, r, ss); err != nil {
		return err
	}

	return nil
}

func (s *ManagerHTTPOIDC) SaveToRequest(ctx context.Context, w http.ResponseWriter, r *http.Request, session *Session) error {
	_ = s.r.CSRFHandler().RegenerateToken(w, r)
	cookie, _ := s.r.CookieManager().Get(r, s.cookieName)
	if s.c.SessionDomain() != "" {
		cookie.Options.Domain = s.c.SessionDomain()
	}

	if s.c.SessionPath() != "" {
		cookie.Options.Path = s.c.SessionPath()
	}

	if s.c.SessionSameSiteMode() != 0 {
		cookie.Options.SameSite = s.c.SessionSameSiteMode()
	}

	cookie.Options.MaxAge = 0
	if s.c.SessionPersistentCookie() {
		cookie.Options.MaxAge = int(s.c.SessionLifespan().Seconds())
	}

	cookie.Values["sid"] = session.ID.String()
	if err := cookie.Save(r, w); err != nil {
		return errors.WithStack(err)
	}
	// Set OIDC id token in authorization header
	if len(session.IdToken) > 0 {
		r.Header.Add("Authorization", session.IdToken)
	}
	return nil
}

func (s *ManagerHTTPOIDC) FetchFromRequest(ctx context.Context, r *http.Request) (*Session, error) {
	cookie, err := s.r.CookieManager().Get(r, s.cookieName)
	if err != nil {
		return nil, errors.WithStack(ErrNoActiveSessionFound.WithWrap(err).WithDebugf("%s", err))
	}

	sid, ok := cookie.Values["sid"].(string)
	if !ok {
		return nil, errors.WithStack(ErrNoActiveSessionFound)
	}

	se, err := s.r.SessionPersister().GetSession(ctx, x.ParseUUID(sid))
	if err != nil {
		if errors.Is(err, herodot.ErrNotFound) || errors.Is(err, sqlcon.ErrNoRows) {
			return nil, errors.WithStack(ErrNoActiveSessionFound)
		}
		return nil, err
	}

	if se.ExpiresAt.Before(time.Now()) {
		if len(se.RefreshToken) == 0 || s.tokenRefresher == nil || len(se.OIDCProvider) == 0 {
			return nil, errors.WithStack(ErrNoActiveSessionFound)
		}

		// If id_token is presented, try to update access and id tokens
		token, err := s.tokenRefresher.RefreshToken(ctx, &oauth2.Token{
			AccessToken:  se.AccessToken,
			RefreshToken: se.RefreshToken,
			Expiry:       se.ExpiresAt,
		}, se.OIDCProvider)

		if err != nil {
			return nil, errors.WithStack(ErrNoActiveSessionFound)
		}
		se.AccessToken = token.AccessToken
		se.ExpiresAt = token.Expiry
		se.IdToken = token.Extra("id_token").(string)
		err = s.r.SessionPersister().CreateSession(ctx, se)

		if err != nil {
			return nil, err
		}
	}

	se.Identity = se.Identity.CopyWithoutCredentials()

	return se, nil
}

func (s *ManagerHTTPOIDC) PurgeFromRequest(ctx context.Context, w http.ResponseWriter, r *http.Request) error {
	cookie, _ := s.r.CookieManager().Get(r, s.cookieName)
	cookie.Options.MaxAge = -1
	if err := cookie.Save(r, w); err != nil {
		return errors.WithStack(err)
	}
	return nil
}
