package main

import (
	"context"
	"flag"
	"fmt"
	"net/http"
	"net/url"
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

	"github.com/peterbourgon/sympatico/internal/dna"
)

// validator is a client that will dispatch to an external service to
// validate a user+token cobmination.
type validator url.URL

func NewValidator(vURL string) (validator, error) {
	u, err := url.Parse(vURL)
	if err != nil {
		return validator{}, errors.Wrap(err, "invalid validator URL")
	}
	return validator(*u), nil
}

// Validate the user+token combination.
func (v validator) Validate(ctx context.Context, user, token string) error {
	vals := url.Values{
		"user":  []string{user},
		"token": []string{token},
	}
	u := url.URL{
		Scheme:   v.Scheme,
		Host:     v.Host,
		Path:     "/auth/validate",
		RawQuery: vals.Encode(),
	}

	req, err := http.NewRequest("GET", u.String(), nil)
	if err != nil {
		return errors.Wrap(err, "error creating validate request")
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return errors.Wrap(err, "error validating request")
	}
	if resp.StatusCode != http.StatusOK {
		return errors.New("invalid token")
	}
	return nil
}

func main() {
	fs := flag.NewFlagSet("monolith", flag.ExitOnError)
	var (
		apiAddr = fs.String("api", "127.0.0.1:8080", "HTTP API listen address")
		authURL = fs.String("auth-url", "127.0.0.1:8081", "URL for Auth Service")
		dnaURN  = fs.String("dna-urn", "file:dna.db", "URN for DNA DB")
	)
	fs.Usage = usageFor(fs, "monolith [flags]")
	fs.Parse(os.Args[1:])

	var logger log.Logger
	{
		logger = log.NewLogfmtLogger(os.Stdout)
		logger = log.With(logger, "ts", log.DefaultTimestampUTC)
	}

	var validSvc validator
	{
		svc, err := NewValidator(*authURL)
		if err != nil {
			logger.Log("during", "NewValidator", "err", err)
			os.Exit(1)
		}
		validSvc = svc
	}

	var dnaCheckDuration *prometheus.HistogramVec
	{
		dnaCheckDuration = promauto.NewHistogramVec(prometheus.HistogramOpts{
			Subsystem: "dna",
			Name:      "check_duration_seconds",
			Help:      "Time spent performing DNA subsequence checks.",
			Buckets:   prometheus.DefBuckets,
		}, []string{"success"})
	}

	var dnasvc *dna.Service
	{
		dnarepo, err := dna.NewSQLiteRepository(*dnaURN)
		if err != nil {
			logger.Log("during", "dna.NewSQLiteRepository", "err", err)
			os.Exit(1)
		}
		dnasvc = dna.NewService(dnarepo, validSvc, dnaCheckDuration)
	}

	var api http.Handler
	{
		// The HTTP API mounts endpoints to be consumed by clients.
		r := mux.NewRouter()

		// Another way to make a service accessible over HTTP is to have the
		// service implement http.Handler directly, via a ServeHTTP method.
		r.PathPrefix("/dna/").Handler(http.StripPrefix("/dna", dnasvc))

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
			logger.Log("component", "API", "addr", *apiAddr)
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
