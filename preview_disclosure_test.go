package informationquery_test

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	iq "github.com/StuHelper/stuhelper-information-query"
	"github.com/StuHelper/stuhelper-platform/account"
)

func TestBatchPreviewEchoAndLengthForEveryLeadKind(t *testing.T) {
	for _, kind := range []string{"account", "name", "student_id", "staff_id", "qq"} {
		t.Run(kind, func(t *testing.T) {
			s, audits, grants, _, q := fixture()
			grants.caps["information-query.batch.read"] = true
			s.Resolvers = map[string]iq.Resolver{kind: batchResolver{}}
			s.Providers = nil
			boundary := " " + strings.Repeat("测", 254) + " "
			over := boundary + "测"
			if kind == "account" {
				boundary = account.Principal{Issuer: "iss", Subject: strings.Repeat("u", 188)}.Key()
				over = account.Principal{Issuer: "iss", Subject: strings.Repeat("u", 189)}.Key()
				if len(boundary) != 256 || len(over) != 257 {
					t.Fatal("invalid account key fixture")
				}
			}
			input := iq.BatchQuery{Kind: kind, Values: []string{boundary}, Scope: q.Scope, Domains: q.Domains, Purpose: "preview fixture"}
			ctx := context.Background()
			delivery := iq.Delivery{Channel: "admin"}

			t.Run("reject over limit", func(t *testing.T) {
				tooLong := input
				tooLong.Values = []string{over}
				out, err := s.Preview(ctx, actor, "preview-over", delivery, tooLong)
				if !errors.Is(err, iq.ErrInvalid) || len(out.Entries) != 0 {
					t.Fatalf("expected no preview and invalid request, got %d entries and %v", len(out.Entries), err)
				}
			})

			t.Run("echo in response only", func(t *testing.T) {
				out, err := s.Preview(ctx, actor, "preview-boundary", delivery, input)
				if err != nil {
					t.Fatal(err)
				}
				responseJSON, err := json.Marshal(out)
				if err != nil {
					t.Fatal(err)
				}
				var response struct {
					Entries []struct {
						Value string `json:"value"`
					} `json:"entries"`
				}
				if err = json.Unmarshal(responseJSON, &response); err != nil {
					t.Fatal(err)
				}
				if len(response.Entries) != 1 || response.Entries[0].Value != boundary {
					t.Error("preview row did not echo the submitted value")
				}
				last := audits.records[len(audits.records)-1]
				if len(last.Targets) != 0 || len(last.TargetScopes) != 0 {
					t.Error("preview audit retained target identifiers")
				}
			})
		})
	}
}
