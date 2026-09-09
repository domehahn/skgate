package api

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"strconv"
	"sync/atomic"
	"time"

	"github.com/domehahn/skgate/internal/admission"
	"github.com/domehahn/skgate/internal/auth"
	"github.com/domehahn/skgate/internal/store"
)

type Server struct {
	evaluator     admission.Evaluator
	store         store.Store
	authenticator *auth.Authenticator
	production    bool
	logger        *slog.Logger
	total         atomic.Uint64
	denied        atomic.Uint64
}

func New(e admission.Evaluator, st store.Store, token string, production bool, logger *slog.Logger) *Server {
	if logger == nil {
		logger = slog.Default()
	}
	authenticator := auth.NewAuthenticator(token, nil)
	return &Server{
		evaluator:     e.WithRevocations(st),
		store:         st,
		authenticator: authenticator,
		production:    production,
		logger:        logger,
	}
}

func (s *Server) WithAuthenticator(a *auth.Authenticator) *Server {
	s.authenticator = a
	return s
}

func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok\n"))
	})
	mux.HandleFunc("GET /readyz", func(w http.ResponseWriter, r *http.Request) {
		if s.store != nil {
			if err := s.store.Ping(); err != nil {
				w.WriteHeader(http.StatusServiceUnavailable)
				_, _ = w.Write([]byte(fmt.Sprintf("not ready: store error: %v\n", err)))
				return
			}
		}
		if err := s.evaluator.Policy.Validate(); err != nil {
			w.WriteHeader(http.StatusServiceUnavailable)
			_, _ = w.Write([]byte(fmt.Sprintf("not ready: policy invalid: %v\n", err)))
			return
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ready\n"))
	})
	mux.HandleFunc("GET /metrics", s.metrics)

	mux.Handle("POST /api/v1/evaluate", s.requireRole(auth.RoleEvaluator, http.HandlerFunc(s.evaluate)))

	mux.Handle("POST /api/v1/promotions", s.requireRole(auth.RolePromoter, http.HandlerFunc(s.promote)))
	mux.Handle("GET /api/v1/promotions", s.requireRole(auth.RoleViewer, http.HandlerFunc(s.getPromotions)))

	mux.Handle("POST /api/v1/revocations", s.requireRole(auth.RoleAdmin, http.HandlerFunc(s.revoke)))
	mux.Handle("GET /api/v1/revocations", s.requireRole(auth.RoleViewer, http.HandlerFunc(s.getRevocations)))

	mux.Handle("GET /api/v1/decisions", s.requireRole(auth.RoleAuditor, http.HandlerFunc(s.getDecisions)))

	return securityHeaders(mux)
}

func (s *Server) requireRole(requiredRole auth.Role, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		authHeader := r.Header.Get("Authorization")

		if authHeader == "" {
			if s.production {
				writeErr(w, 503, "SKGATE-AUTH-NOT-CONFIGURED", "production mode requires authorization header")
				return
			}
			// In dev non-production mode, default to admin
			next.ServeHTTP(w, r)
			return
		}

		userRole, err := s.authenticator.Authenticate(authHeader)
		if err != nil {
			writeErr(w, 401, "SKGATE-UNAUTHORIZED", err.Error())
			return
		}

		if !auth.HasPermission(userRole, requiredRole) {
			writeErr(w, 403, "SKGATE-FORBIDDEN", fmt.Sprintf("role %s insufficient for required role %s", userRole, requiredRole))
			return
		}

		next.ServeHTTP(w, r)
	})
}

func (s *Server) evaluate(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, 1<<20)
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()

	var req admission.EvaluationRequest
	if err := dec.Decode(&req); err != nil {
		writeErr(w, 400, "SKGATE-REQUEST-INVALID", err.Error())
		return
	}

	decision := s.evaluator.Evaluate(req)
	s.total.Add(1)
	if decision.Decision != admission.Allow {
		s.denied.Add(1)
	}

	if s.store != nil {
		if err := s.store.SaveDecision(decision); err != nil {
			writeErr(w, 500, "SKGATE-AUDIT-WRITE-FAILED", err.Error())
			return
		}
	}

	s.logger.Info("admission decision", "decision_id", decision.DecisionID, "decision", decision.Decision, "digest", decision.Subject.Digest, "environment", decision.Environment)
	writeJSON(w, 200, decision)
}

func (s *Server) promote(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, 1<<20)
	var p store.Promotion
	if err := json.NewDecoder(r.Body).Decode(&p); err != nil {
		writeErr(w, 400, "SKGATE-PROMOTION-INVALID", err.Error())
		return
	}
	if p.DecisionID == "" || p.Digest == "" || p.Environment == "" {
		writeErr(w, 400, "SKGATE-PROMOTION-INVALID", "decision_id, digest, and environment are required")
		return
	}
	if err := s.store.Promote(p); err != nil {
		writeErr(w, 500, "SKGATE-PROMOTION-FAILED", err.Error())
		return
	}
	writeJSON(w, 201, p)
}

func (s *Server) getPromotions(w http.ResponseWriter, r *http.Request) {
	env := r.URL.Query().Get("environment")
	list, err := s.store.GetPromotions(env)
	if err != nil {
		writeErr(w, 500, "SKGATE-PROMOTIONS-FAILED", err.Error())
		return
	}
	writeJSON(w, 200, list)
}

func (s *Server) revoke(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, 1<<20)
	var rev store.Revocation
	if err := json.NewDecoder(r.Body).Decode(&rev); err != nil {
		writeErr(w, 400, "SKGATE-REVOCATION-INVALID", err.Error())
		return
	}
	if rev.Digest == "" {
		writeErr(w, 400, "SKGATE-REVOCATION-INVALID", "digest is required")
		return
	}
	if err := s.store.Revoke(rev); err != nil {
		writeErr(w, 500, "SKGATE-REVOCATION-FAILED", err.Error())
		return
	}
	writeJSON(w, 201, rev)
}

func (s *Server) getRevocations(w http.ResponseWriter, r *http.Request) {
	env := r.URL.Query().Get("environment")
	list, err := s.store.GetRevocations(env)
	if err != nil {
		writeErr(w, 500, "SKGATE-REVOCATIONS-FAILED", err.Error())
		return
	}
	writeJSON(w, 200, list)
}

func (s *Server) getDecisions(w http.ResponseWriter, r *http.Request) {
	list, err := s.store.GetDecisions()
	if err != nil {
		writeErr(w, 500, "SKGATE-DECISIONS-FAILED", err.Error())
		return
	}
	writeJSON(w, 200, list)
}

func (s *Server) metrics(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/plain; version=0.0.4")
	_, _ = fmt.Fprintf(w, "skgate_evaluations_total %d\nskgate_non_allow_total %d\n", s.total.Load(), s.denied.Load())
}

func securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("Referrer-Policy", "no-referrer")
		next.ServeHTTP(w, r)
	})
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func writeErr(w http.ResponseWriter, status int, code, msg string) {
	writeJSON(w, status, map[string]any{
		"error":     map[string]string{"code": code, "message": msg},
		"status":    strconv.Itoa(status),
		"timestamp": time.Now().UTC().Format(time.RFC3339),
	})
}
