package session

import (
	"golang.org/x/oauth2"
	"time"

	"github.com/gofrs/uuid"

	"github.com/ory/kratos/identity"
	"github.com/ory/kratos/x"
)

// swagger:model session
type Session struct {
	// required: true
	ID uuid.UUID `json:"sid" faker:"-" db:"id"`

	// required: true
	ExpiresAt time.Time `json:"expires_at" db:"expires_at" faker:"time_type"`

	// required: true
	AuthenticatedAt time.Time `json:"authenticated_at" db:"authenticated_at" faker:"time_type"`

	// required: true
	IssuedAt time.Time `json:"issued_at" db:"issued_at" faker:"time_type"`

	IdToken string `json:"id_token" faker:"-" db:"id_token"`

	AccessToken string `json:"access_token" faker:"-" db:"access_token"`

	RefreshToken string `json:"refresh_token" faker:"-" db:"refresh_token"`

	OIDCProvider string `json:"oidc_provider"  faker:"-" db:"oidc_provider"`

	// required: true
	Identity *identity.Identity `json:"identity" faker:"identity" db:"-" belongs_to:"identities" fk_id:"IdentityID"`

	// IdentityID is a helper struct field for gobuffalo.pop.
	IdentityID uuid.UUID `json:"-" faker:"-" db:"identity_id"`

	// CreatedAt is a helper struct field for gobuffalo.pop.
	CreatedAt time.Time `json:"-" faker:"-" db:"created_at"`

	// UpdatedAt is a helper struct field for gobuffalo.pop.
	UpdatedAt time.Time `json:"-" faker:"-" db:"updated_at"`
}

func (s Session) TableName() string {
	return "sessions"
}

func NewSession(i *identity.Identity, c interface {
	SessionLifespan() time.Duration
}, authenticatedAt time.Time) *Session {
	return &Session{
		ID:              x.NewUUID(),
		ExpiresAt:       authenticatedAt.Add(c.SessionLifespan()),
		AuthenticatedAt: authenticatedAt,
		IssuedAt:        time.Now().UTC(),
		Identity:        i,
		IdentityID:      i.ID,
	}
}

func NewOIDCSession(i *identity.Identity, token *oauth2.Token, authenticatedAt time.Time, provider string) *Session {
	idToken := token.Extra("id_token").(string)

	return &Session{
		ID:              x.NewUUID(),
		ExpiresAt:       token.Expiry,
		AuthenticatedAt: authenticatedAt,
		IdToken:         idToken,
		OIDCProvider:    provider,
		AccessToken:     token.AccessToken,
		RefreshToken:    token.RefreshToken,
		IssuedAt:        time.Now().UTC(),
		Identity:        i,
		IdentityID:      i.ID,
	}
}

type Device struct {
	UserAgent string      `json:"user_agent"`
	SeenAt    []time.Time `json:"seen_at" faker:"time_types"`
}

func (s *Session) Declassify() *Session {
	s.Identity = s.Identity.CopyWithoutCredentials()
	return s
}
