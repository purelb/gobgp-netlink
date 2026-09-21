//
// Copyright (C) 2014-2017 Nippon Telegraph and Telephone Corporation.
// Copyright (C) 2025 Acnodal Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//    http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
// implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/pprof"
	"net/netip"
	"os"
	"os/signal"
	"runtime"
	"strings"
	"syscall"
	"time"

	"github.com/coreos/go-systemd/v22/daemon"
	"github.com/getsentry/sentry-go"
	grpc_prometheus "github.com/grpc-ecosystem/go-grpc-prometheus"
	"github.com/jessevdk/go-flags"
	"github.com/kr/pretty"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"golang.org/x/time/rate"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"

	"github.com/osrg/gobgp/v4/internal/pkg/version"
	"github.com/osrg/gobgp/v4/pkg/config"
	"github.com/osrg/gobgp/v4/pkg/metrics"
	"github.com/osrg/gobgp/v4/pkg/server"
)

var logger = slog.Default()

// metricsHandler serves prometheus.DefaultGatherer with bounds on it.
//
// The bare promhttp.Handler() this replaces has MaxRequestsInFlight 0
// (unlimited) and Timeout 0 (none), and a scrape reaches ListPeer, which runs
// under the BGP write lock. Unbounded, concurrent scrapes queue without limit
// and compound, because Go's RWMutex parks new readers behind a waiting writer.
//
// MaxRequestsInFlight 1 rejects the surplus outright with 503 rather than
// letting it pile up. It bounds concurrency only - what bounds the share of
// time the lock is held is the caching collector in pkg/metrics, and the two
// are meant to be read together.
//
// ContinueOnError matters on its own. bgpCollector emits a
// prometheus.NewInvalidMetric when GetBgp or ListPeer fails, and the default
// HTTPErrorOnError turns that into a 500 with no body - so one transient error
// on one peer blanks the netlink and BFD metrics too, which are collected from
// lock-free counters and were perfectly fine.
func metricsHandler() http.Handler {
	return metricsHandlerFor(prometheus.DefaultGatherer, prometheus.DefaultRegisterer)
}

func metricsHandlerFor(g prometheus.Gatherer, r prometheus.Registerer) http.Handler {
	return promhttp.HandlerFor(g, promhttp.HandlerOpts{
		MaxRequestsInFlight: 1,
		Timeout:             10 * time.Second,
		ErrorHandling:       promhttp.ContinueOnError,
		// Without this promhttp_metric_handler_errors_total is never exported
		// and gathering failures are invisible.
		Registry: r,
	})
}

// isLoopbackHostPort reports whether a "host:port" binds only to loopback.
//
// An empty host means the wildcard, which is the case worth catching: ":6060"
// and "0.0.0.0:6060" reach every interface. A name is resolved, and is treated
// as loopback only if every address it resolves to is - "localhost" normally
// gives 127.0.0.1 and ::1, and both are. Anything that cannot be parsed or
// resolved is reported as not loopback, so the warning errs towards being
// shown.
func isLoopbackHostPort(hostPort string) bool {
	host, _, err := net.SplitHostPort(hostPort)
	if err != nil || host == "" {
		return false
	}
	if ip, err := netip.ParseAddr(host); err == nil {
		return ip.IsLoopback()
	}
	addrs, err := net.LookupHost(host)
	if err != nil || len(addrs) == 0 {
		return false
	}
	for _, a := range addrs {
		ip, err := netip.ParseAddr(a)
		if err != nil || !ip.IsLoopback() {
			return false
		}
	}
	return true
}

func main() {
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGTERM, syscall.SIGINT)

	var opts struct {
		ConfigFile       string `short:"f" long:"config-file" description:"specifying a config file"`
		ConfigType       string `short:"t" long:"config-type" description:"specifying config type (toml, yaml, json)" default:"toml"`
		ConfigAutoReload bool   `short:"a" long:"config-auto-reload" description:"activate config auto reload on changes"`
		LogLevel         string `short:"l" long:"log-level" description:"specifying log level"`
		LogPlain         bool   `short:"p" long:"log-plain" description:"use plain format for logging (json by default)"`
		DisableStdlog    bool   `long:"disable-stdlog" description:"disable standard logging"`
		CPUs             int    `long:"cpus" description:"specify the number of CPUs to be used"`
		// Loopback by default, not the wildcard this used to be. The gRPC API
		// has no authentication of its own - TLS is opt-in and client-certificate
		// auth needs --tls-client-ca-file on top - and it is a write API: AddPeer,
		// DeletePeer, AddPath, StopBgp, SetPolicies. Under hostNetwork a wildcard
		// bind hands all of that to anything that can route to the node,
		// including the BGP fabric. Both loopbacks are listed explicitly rather
		// than as "localhost" so the bind does not depend on how that name
		// resolves. Set the flag to expose it deliberately.
		GrpcHosts       string `long:"api-hosts" description:"specify the hosts that gobgpd listens on; loopback by default, set explicitly to expose the API off-host" default:"127.0.0.1:50051,[::1]:50051"`
		GrpcAllowRemote bool   `long:"api-insecure-allow-remote" description:"permit --api-hosts off-loopback without client-certificate authentication; the API is a write interface, so this exposes route injection"`
		GracefulRestart bool   `short:"r" long:"graceful-restart" description:"flag restart-state in graceful-restart capability"`
		Dry             bool   `short:"d" long:"dry-run" description:"check configuration"`
		PProfHost       string `long:"pprof-host" description:"specify the host that gobgpd listens on for pprof and metrics" default:"localhost:6060"`
		PProfDisable    bool   `long:"pprof-disable" description:"disable pprof profiling"`
		MetricsPath     string `long:"metrics-path" description:"specify path for prometheus metrics, empty value disables them" default:"/metrics"`
		MetricsHost     string `long:"metrics-host" description:"specify a separate host:port for prometheus metrics; defaults to --pprof-host, which also serves pprof"`
		// Collecting the BGP metrics takes the BGP write lock, so this bounds
		// the share of time that lock is held rather than how often the
		// endpoint may be scraped. Keep it at or below the scrape interval and
		// no sample is ever stale. 0 disables caching.
		MetricsMinInterval time.Duration `long:"metrics-min-interval" description:"minimum interval between BGP metric collections; scrapes in between replay the last result (0 disables)" default:"15s"`
		// Collected by default so the metric surface is unchanged, hence a
		// disable switch rather than an enable one - the same shape as
		// --pprof-disable, and the only shape go-flags offers, since a bool
		// option there is a switch and cannot be given =false.
		//
		// Computing the advertised count walks the RIB per peer per family with
		// the export policy applied. --metrics-min-interval is what bounds that
		// cost; this drops the series outright, which is what a very large RIB
		// may actually want.
		MetricsAdvertisedRoutesDisable bool    `long:"metrics-advertised-routes-disable" description:"stop collecting bgp_routes_advertised, which walks the RIB per peer per family"`
		UseSdNotify                    bool    `long:"sdnotify" description:"use sd_notify protocol"`
		TLS                            bool    `long:"tls" description:"enable TLS authentication for gRPC API"`
		TLSCertFile                    string  `long:"tls-cert-file" description:"The TLS cert file"`
		TLSKeyFile                     string  `long:"tls-key-file" description:"The TLS key file"`
		TLSClientCAFile                string  `long:"tls-client-ca-file" description:"Optional TLS client CA file to authenticate clients against"`
		Version                        bool    `long:"version" description:"show version number"`
		SentryDSN                      string  `long:"sentry-dsn" description:"Sentry DSN" default:""`
		SentryEnvironment              string  `long:"sentry-environment" description:"Sentry environment" default:"development"`
		SentrySampleRate               float64 `long:"sentry-sample-rate" description:"Sentry traces sample rate" default:"1.0"`
		SentryDebug                    bool    `long:"sentry-debug" description:"Sentry debug mode"`
	}
	_, err := flags.Parse(&opts)
	if err != nil {
		var flagsErr *flags.Error
		if errors.As(err, &flagsErr) {
			if flagsErr.Type == flags.ErrHelp {
				os.Exit(0)
			}
		}

		logger.Error("Error parsing flags", slog.String("Error", err.Error()))
		os.Exit(1)
	}

	if opts.Version {
		fmt.Println("gobgpd version", version.Version())
		os.Exit(0)
	}

	// if Sentry DSN is provided, initialize Sentry
	// We would like to capture errors and exceptions, but not traces
	if opts.SentryDSN != "" {
		logger.Debug("Initializing Sentry", slog.String("Env", opts.SentryEnvironment), slog.String("Release", version.Version()), slog.Float64("SampleRate", opts.SentrySampleRate), slog.Bool("Debug", opts.SentryDebug))
		err := sentry.Init(sentry.ClientOptions{
			Dsn:         opts.SentryDSN,
			SampleRate:  opts.SentrySampleRate,
			Debug:       opts.SentryDebug,
			Release:     version.Version(),
			Environment: opts.SentryEnvironment,
			// Disable tracing as it's not relevant for now
			EnableTracing:    false,
			TracesSampleRate: 0.0,
		})
		if err != nil {
			logger.Error("sentry.Init", slog.String("Error", err.Error()))
			os.Exit(1)
		}
		// Flush buffered events before the program terminates.
		defer sentry.Flush(2 * time.Second)

		if opts.SentryDebug {
			sentry.CaptureMessage("Sentry debug mode enabled on gobgpd")
		}
	}

	// Only override GOMAXPROCS when the operator asked for a specific value.
	// Setting it to NumCPU() defeated the cgroup CPU limit: in a container
	// limited to 500m on a 64-core node the runtime started 64 Ps, burned the
	// quota in well under a millisecond and then throttled for the rest of the
	// period. Since the go directive moved to 1.25 the runtime derives the
	// default from the cgroup limit itself, so leaving it alone is correct.
	if opts.CPUs != 0 {
		if runtime.NumCPU() < opts.CPUs {
			logger.Error("invalid number of CPUs", slog.Int("Available", runtime.NumCPU()), slog.Int("Specified", opts.CPUs))
			os.Exit(1)
		}
		runtime.GOMAXPROCS(opts.CPUs)
	}

	// Metrics and pprof were served from one mux on one address, and that
	// address's flag is --pprof-host. Exposing metrics therefore meant choosing
	// between exposing pprof alongside them or disabling pprof entirely.
	// --metrics-host lets them bind separately; unset, everything behaves as
	// before.
	pprofEnabled := !opts.PProfDisable
	metricsEnabled := opts.MetricsPath != ""
	serve := func(addr string, mux *http.ServeMux, what string) {
		// A bare http.ListenAndServe has no timeouts at all, so a client that
		// opens a connection and dribbles a request holds a goroutine and a
		// file descriptor indefinitely. Harmless on loopback, not once this is
		// bound to a node address.
		//
		// WriteTimeout has to exceed the metrics handler's own Timeout below,
		// or the connection is torn down before that handler can write its 503
		// and the client sees a reset instead of an error. pprof is unaffected
		// despite being slower than this: net/http/pprof extends the write
		// deadline by WriteTimeout plus the requested duration, so
		// /debug/pprof/profile?seconds=30 still completes.
		srv := &http.Server{
			Addr:              addr,
			Handler:           mux,
			ReadHeaderTimeout: 5 * time.Second,
			ReadTimeout:       10 * time.Second,
			WriteTimeout:      30 * time.Second,
		}
		go func() {
			// Error, not Warn. Metrics are a dependency for whatever is
			// scraping this, and a listener that never came up is otherwise
			// indistinguishable from a node that simply has nothing to report.
			if err := srv.ListenAndServe(); err != nil {
				logger.Error("HTTP listener failed",
					slog.String("Listener", what),
					slog.String("Address", addr),
					slog.String("Error", err.Error()))
			}
		}()
	}

	if metricsEnabled && opts.MetricsHost != "" {
		if opts.MetricsHost == opts.PProfHost {
			// One address can only carry one listener, so the muxes have to
			// merge here. Say so: it used to happen silently, and it means
			// pprof follows metrics to wherever this is bound. /debug/pprof/
			// cmdline returns os.Args, which carries --sentry-dsn and any TLS
			// key paths, and /debug/pprof/profile?seconds= is an
			// attacker-controlled CPU burn.
			logger.Warn("--metrics-host equals --pprof-host, so pprof is served on the metrics address too; pass --pprof-disable to keep it off",
				slog.String("Address", opts.MetricsHost))
		} else {
			metricsMux := http.NewServeMux()
			metricsMux.Handle(opts.MetricsPath, metricsHandler())
			serve(opts.MetricsHost, metricsMux, "metrics")
			metricsEnabled = false // already served on its own address
		}
	}

	httpMux := http.NewServeMux()
	if pprofEnabled {
		httpMux.HandleFunc("/debug/pprof/", pprof.Index)
		httpMux.HandleFunc("/debug/pprof/cmdline", pprof.Cmdline)
		httpMux.HandleFunc("/debug/pprof/profile", pprof.Profile)
		httpMux.HandleFunc("/debug/pprof/symbol", pprof.Symbol)
		httpMux.HandleFunc("/debug/pprof/trace", pprof.Trace)
	}
	if metricsEnabled {
		httpMux.Handle(opts.MetricsPath, metricsHandler())
	}
	if pprofEnabled || metricsEnabled {
		serve(opts.PProfHost, httpMux, "pprof")
	}

	lvl := new(slog.LevelVar)
	switch opts.LogLevel {
	case "debug":
		lvl.Set(slog.LevelDebug)
	default:
		lvl.Set(slog.LevelInfo)
	}

	var output io.Writer
	if opts.DisableStdlog {
		output = io.Discard
	} else {
		output = os.Stdout
	}

	lopts := &slog.HandlerOptions{Level: lvl}
	if opts.LogPlain {
		logger = slog.New(slog.NewTextHandler(output, lopts))
	} else {
		logger = slog.New(slog.NewJSONHandler(output, lopts))
	}

	// These three run here, after the handler above is installed, rather than
	// where the flags are read. Before it, logger is still slog.Default() -
	// plain text on stderr - so they bypassed --log-plain and --disable-stdlog
	// and did not appear in the JSON stream anything is actually parsing.
	// The metrics endpoint is unauthenticated and the default is loopback.
	// Binding it anywhere else publishes the node's full peer table, its BGP
	// authentication posture and its build identity to anything that can route
	// to that address - which under hostNetwork includes the BGP fabric itself.
	// Kubernetes NetworkPolicy does not cover host-namespace ports, so it is
	// not a mitigation. Exposing it can be the right call; doing it by accident
	// is not, so this is loud rather than fatal.
	if metricsAddr := opts.MetricsHost; metricsAddr != "" && opts.MetricsPath != "" && !isLoopbackHostPort(metricsAddr) {
		logger.Error("metrics are bound off-loopback and the endpoint is unauthenticated; it exposes the peer table and BGP auth posture to anything that can reach this address",
			slog.String("Address", metricsAddr))
	}
	// The gRPC API is the one that matters most and had no check at all. Unlike
	// metrics and pprof, which are read interfaces that leak, this one writes:
	// AddPeer, AddPath, and in this fork routes into the host FIB. So it is
	// fatal rather than loud.
	//
	// Client authentication means --tls *and* --tls-client-ca-file. --tls alone
	// is the dangerous middle state: it encrypts, it looks authenticated, and it
	// authenticates nobody, so it has to fail here too.
	clientAuth := opts.TLS && len(opts.TLSClientCAFile) != 0
	for _, host := range strings.Split(opts.GrpcHosts, ",") {
		host = strings.TrimSpace(host)
		if host == "" || strings.HasPrefix(host, "unix://") {
			continue
		}
		if isLoopbackHostPort(host) || clientAuth || opts.GrpcAllowRemote {
			continue
		}
		logger.Error("refusing to start: --api-hosts is bound off-loopback with no client-certificate authentication. "+
			"The API is a write interface - it adds peers and paths and installs routes into the host routing table - "+
			"and it is unauthenticated unless --tls-client-ca-file is set. "+
			"Pass --tls with --tls-client-ca-file, or --api-insecure-allow-remote to accept the exposure deliberately.",
			slog.String("Address", host),
			slog.Bool("TLS", opts.TLS),
			slog.Bool("ClientCA", len(opts.TLSClientCAFile) != 0))
		os.Exit(1)
	}

	if pprofEnabled && !isLoopbackHostPort(opts.PProfHost) {
		logger.Error("pprof is bound off-loopback; /debug/pprof/cmdline exposes the command line, including --sentry-dsn and TLS key paths",
			slog.String("Address", opts.PProfHost))
	}

	if opts.Dry {
		c, err := config.ReadConfigFile(opts.ConfigFile, opts.ConfigType)
		if err != nil {
			logger.Error("Can't read config file", slog.String("File", opts.ConfigFile), slog.String("Error", err.Error()))
			os.Exit(1)
		}
		logger.Info("Finished reading the config file", slog.String("File", opts.ConfigFile))
		if opts.LogLevel == "debug" {
			pretty.Println(c)
		}
		os.Exit(0)
	}

	maxSize := 256 << 20
	grpcOpts := []grpc.ServerOption{grpc.MaxRecvMsgSize(maxSize), grpc.MaxSendMsgSize(maxSize)}
	if opts.TLS {
		// server cert/key
		cert, err := tls.LoadX509KeyPair(opts.TLSCertFile, opts.TLSKeyFile)
		if err != nil {
			logger.Error("Failed to load server certificate/key pair", slog.String("File", opts.TLSCertFile), slog.String("Error", err.Error()))
			os.Exit(1)
		}
		tlsConfig := &tls.Config{Certificates: []tls.Certificate{cert}}

		// client CA
		if len(opts.TLSClientCAFile) != 0 {
			tlsConfig.ClientCAs = x509.NewCertPool()
			pemCerts, err := os.ReadFile(opts.TLSClientCAFile)
			if err != nil {
				logger.Error("Failed to load client CA certificates", slog.String("File", opts.TLSClientCAFile), slog.String("Error", err.Error()))
				os.Exit(1)
			}
			if ok := tlsConfig.ClientCAs.AppendCertsFromPEM(pemCerts); !ok {
				logger.Error("No valid client CA certificates", slog.String("File", opts.TLSClientCAFile))
				os.Exit(1)
			}
			tlsConfig.ClientAuth = tls.RequireAndVerifyClientCert
		}

		creds := credentials.NewTLS(tlsConfig)
		grpcOpts = append(grpcOpts, grpc.Creds(creds))
	}

	if opts.MetricsPath != "" {
		grpcOpts = append(
			grpcOpts,
			grpc.StreamInterceptor(grpc_prometheus.StreamServerInterceptor),
			grpc.UnaryInterceptor(grpc_prometheus.UnaryServerInterceptor),
		)
	}

	logger.Info("gobgpd started", slog.String("version", version.Version()))
	fsmTimingCollector := metrics.NewFSMTimingsCollector()
	bgpServer := server.NewBgpServer(
		server.GrpcListenAddress(opts.GrpcHosts),
		server.GrpcOption(grpcOpts),
		server.LoggerOption(logger, lvl),
		server.TimingHookOption(fsmTimingCollector),
		// Only the real daemon reconciles routes left behind by a previous run.
		server.StaleRouteCleanupOption(true))
	// Only the BGP collector is cached. It is the one that reaches ListPeer and
	// so takes the BGP write lock; the netlink and BFD collectors read
	// lock-free counters and cost nothing worth bounding.
	prometheus.MustRegister(metrics.NewCachingCollector(
		metrics.NewBgpCollector(bgpServer,
			metrics.WithAdvertisedRoutes(!opts.MetricsAdvertisedRoutesDisable)),
		opts.MetricsMinInterval))
	prometheus.MustRegister(metrics.NewNetlinkCollector(bgpServer))
	prometheus.MustRegister(metrics.NewBfdCollector(bgpServer))
	prometheus.MustRegister(fsmTimingCollector)
	prometheus.MustRegister(metrics.NewBuildInfoCollector())
	go bgpServer.Serve()

	if opts.ConfigFile == "" {
		notifyReady(opts.UseSdNotify)
		<-sigCh
		stopServer(bgpServer, opts.UseSdNotify)
		return
	}

	signal.Notify(sigCh, syscall.SIGHUP)

	initialConfig, err := config.ReadConfigFile(opts.ConfigFile, opts.ConfigType)
	if err != nil {
		logger.Error("Can't read config file", slog.String("File", opts.ConfigFile), slog.String("Error", err.Error()))
		os.Exit(1)
	}
	logger.Info("Finished reading the config file", slog.String("File", opts.ConfigFile))

	currentConfig, err := config.InitialConfig(context.Background(), bgpServer, initialConfig, opts.GracefulRestart)
	if err != nil {
		logger.Error("Failed to apply initial configuration", slog.String("File", opts.ConfigFile), slog.String("Error", err.Error()))
		os.Exit(1)
	}

	if opts.ConfigAutoReload {
		logger.Info("Watching for config changes to trigger auto-reload", slog.String("File", opts.ConfigFile))

		// Writing to the config may trigger many events in quick successions
		// To prevent abusive reloads, we ignore any event in a 100ms window
		rateLimiter := rate.Sometimes{Interval: 100 * time.Millisecond}

		config.WatchConfigFile(opts.ConfigFile, opts.ConfigType, func() {
			rateLimiter.Do(func() {
				logger.Info("Config changes detected, reloading configuration")
				sigCh <- syscall.SIGHUP
			})
		})
	}

	notifyReady(opts.UseSdNotify)

	for sig := range sigCh {
		if sig != syscall.SIGHUP {
			stopServer(bgpServer, opts.UseSdNotify)
			return
		}

		logger.Info("Reload the config file")
		// Avoid crashing gobgpd on reload - it shouldn't flush policy entirely, so it's safe to continue to run
		newConfig, err := config.ReadConfigFile(opts.ConfigFile, opts.ConfigType)
		if err != nil {
			logger.Warn("Can't read config file", slog.String("File", opts.ConfigFile), slog.String("Error", err.Error()))
			continue
		}

		currentConfig, err = config.UpdateConfig(context.Background(), bgpServer, currentConfig, newConfig)
		if err != nil {
			logger.Warn("Failed to update config", slog.String("File", opts.ConfigFile), slog.String("Error", err.Error()))
			continue
		}
	}
}

func notifyReady(useSdNotify bool) {
	if !useSdNotify {
		return
	}

	if status, err := daemon.SdNotify(false, daemon.SdNotifyReady); !status {
		if err != nil {
			logger.Warn("Failed to send notification via sd_notify()", slog.String("Error", err.Error()))
		} else {
			logger.Warn("The socket sd_notify() isn't available")
		}
	}
}

func stopServer(bgpServer *server.BgpServer, useSdNotify bool) {
	logger.Info("stopping gobgpd server")

	bgpServer.Stop()
	if useSdNotify {
		daemon.SdNotify(false, daemon.SdNotifyStopping)
	}
}
