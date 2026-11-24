package graphql

import (
	"context"
	"errors"
	"testing"

	"github.com/geniusrabbit/blaze-api/pkg/context/session"
	"github.com/geniusrabbit/blaze-api/server/graphql/models"
)

func TestTokenMutationsDeniedForDirectTokenSession(t *testing.T) {
	t.Parallel()

	resolver := NewQueryResolver(nil)
	ctx := session.WithAuthorizerCode(context.Background(), session.AuthorizerCodeDirectToken)

	if _, err := resolver.Generate(ctx, nil, "", nil); !errors.Is(err, session.ErrDirectTokenSessionForbidden) {
		t.Fatalf("generate err = %v, want %v", err, session.ErrDirectTokenSessionForbidden)
	}
	if _, err := resolver.Revoke(ctx, models.DirectAccessTokenListFilter{}); !errors.Is(err, session.ErrDirectTokenSessionForbidden) {
		t.Fatalf("revoke err = %v, want %v", err, session.ErrDirectTokenSessionForbidden)
	}
}
