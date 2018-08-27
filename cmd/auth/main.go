package main

import (
	"context"
	"flag"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"text/tabwriter"
	"time"

	"github.com/go-kit/kit/log"
	"github.com/gorilla/mux"
	"github.com/oklog/run"
	"github.com/pkg/errors"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"github.com/prometheus/client_golang/prometheus/promhttp"

	"github.com/peterbourgon/sympatico/internal/auth"
)

func main() {
	fs := flag.NewFlagSet("auth", flag.ExitOnError)
	var (
		apiAddr = fs.String("api", "127.0.0.1:8080", "HTTP API listen address")
		authURN = fs.String("auth-urn", "file:auth.db", "URN for auth DB")
	)
	fs.Usage = usageFor(fs, "auth [flags]")
	fs.Parse(os.Args[1:])

	var logger log.Logger
	{
		logger = log.NewLogfmtLogger(os.Stdout)
		logger = log.With(logger, "ts", log.DefaultTimestampUTC)
	}

	var authEventsTotal *prometheus.CounterVec
	{
		authEventsTotal = promauto.NewCounterVec(prometheus.CounterOpts{
			Subsystem: "auth",
			Name:      "events_total",
			Help:      "Total number of auth events.",
		}, []string{"method", "success"})
	}

	var authsvc *auth.Service
	{
		authrepo, err := auth.NewSQLiteRepository(*authURN)
		if err != nil {
			logger.Log("during", "auth.NewSQLiteRepository", "err", err)
			os.Exit(1)
		}
		authsvc = auth.NewService(authrepo, authEventsTotal)
	}

	var api http.Handler
	{
		// The HTTP API mounts endpoints to be consumed by clients.
		r := mux.NewRouter()

		// One way to make a service accessible over HTTP is to write individual
		// handle functions that translate to and from HTTP semantics. Note that
		// we don't bind the auth validate method, because that's only used by
		// other components, never by clients directly.
		r.Methods("POST").Path("/auth/signup").HandlerFunc(handleSignup(authsvc))
		r.Methods("POST").Path("/auth/login").HandlerFunc(handleLogin(authsvc))
		r.Methods("POST").Path("/auth/logout").HandlerFunc(handleLogout(authsvc))
		r.Methods("GET").Path("/auth/validate").HandlerFunc(handleValidate(authsvc))

		// Wrap the router with a common logging middleware.
		api = newLoggingMiddleware(r, logger)
	}

	var g run.Group
	{
		mux := http.NewServeMux()
		mux.Handle("/metrics", promhttp.Handler())
		mux.Handle("/", api)
		server := &http.Server{
			Addr:    *apiAddr,
			Handler: mux,
		}
		g.Add(func() error {
			logger.Log("component", "auth-API", "addr", *apiAddr)
			return server.ListenAndServe()
		}, func(error) {
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			server.Shutdown(ctx)
		})
	}
	{
		ctx, cancel := context.WithCancel(context.Background())
		g.Add(func() error {
			c := make(chan os.Signal, 1)
			signal.Notify(c, syscall.SIGINT, syscall.SIGTERM)
			select {
			case <-ctx.Done():
				return ctx.Err()
			case sig := <-c:
				return errors.Errorf("received signal %s", sig)
			}
		}, func(error) {
			cancel()
		})
	}
	logger.Log("exit", g.Run())
}

func handleSignup(s *auth.Service) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var (
			user = r.URL.Query().Get("user")
			pass = r.URL.Query().Get("pass")
		)
		err := s.Signup(r.Context(), user, pass)
		if err == auth.ErrBadAuth {
			http.Error(w, err.Error(), http.StatusUnauthorized)
			return
		}
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		fmt.Fprintln(w, "signup OK")
	}
}

func handleLogin(s *auth.Service) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var (
			user = r.URL.Query().Get("user")
			pass = r.URL.Query().Get("pass")
		)
		token, err := s.Login(r.Context(), user, pass)
		if err == auth.ErrBadAuth {
			http.Error(w, err.Error(), http.StatusUnauthorized)
			return
		}
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		fmt.Fprintln(w, token)
	}
}

func handleLogout(s *auth.Service) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var (
			user  = r.URL.Query().Get("user")
			token = r.URL.Query().Get("token")
		)
		err := s.Logout(r.Context(), user, token)
		if err == auth.ErrBadAuth {
			http.Error(w, err.Error(), http.StatusUnauthorized)
			return
		}
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		fmt.Fprintln(w, "logout OK")
	}
}

func handleValidate(s *auth.Service) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var (
			user  = r.URL.Query().Get("user")
			token = r.URL.Query().Get("token")
		)
		err := s.Validate(r.Context(), user, token)
		if err == auth.ErrBadAuth {
			http.Error(w, err.Error(), http.StatusUnauthorized)
			return
		}
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		fmt.Fprintln(w, "validate OK")
	}
}
func usageFor(fs *flag.FlagSet, short string) func() {
	return func() {
		fmt.Fprintf(os.Stdout, "USAGE\n")
		fmt.Fprintf(os.Stdout, "  %s\n", short)
		fmt.Fprintf(os.Stdout, "\n")
		fmt.Fprintf(os.Stdout, "FLAGS\n")
		tw := tabwriter.NewWriter(os.Stdout, 0, 2, 2, ' ', 0)
		fs.VisitAll(func(f *flag.Flag) {
			def := f.DefValue
			if def == "" {
				def = "..."
			}
			fmt.Fprintf(tw, "  -%s %s\t%s\n", f.Name, f.DefValue, f.Usage)
		})
		tw.Flush()
		fmt.Fprintf(os.Stderr, "\n")
	}
}
