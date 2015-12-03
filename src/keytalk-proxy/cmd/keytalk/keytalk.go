package main

import (
	"io"
	"keytalk-proxy/backends"
	_ "keytalk-proxy/backends/forfarmers"
	_ "keytalk-proxy/backends/headfirst"

	"keytalk-proxy/proxy"

	"flag"
	"os"
	"runtime"

	"github.com/BurntSushi/toml"
	logging "github.com/op/go-logging"
)

var version = "0.1"

var format = logging.MustStringFormatter(
	"%{color}%{time:15:04:05.000} %{shortfunc} ▶ %{level:.4s} %{id:03x}%{color:reset} %{message}",
)

var log = logging.MustGetLogger("proxy")

var server proxy.Server
var configFile string

func init() {
	runtime.GOMAXPROCS(runtime.NumCPU())
	flag.StringVar(&configFile, "config", "config.toml", "specifies the location of the config file")
}

func main() {
	flag.Parse()

	var md toml.MetaData
	var err error

	if md, err = toml.DecodeFile(configFile, &server); err != nil {
		panic(err)
	}
	logBackends := []logging.Backend{}
	for _, log := range server.Logging {

		var output io.Writer = os.Stdout
		switch log.Output {
		case "stdout":
		case "stderr":
			output = os.Stderr
		default:
			output, err = os.OpenFile(log.Output, os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0666)
		}

		if err != nil {
			panic(err)
		}

		backend1 := logging.NewLogBackend(output, "", 0)
		backend1Leveled := logging.AddModuleLevel(backend1)

		level, err := logging.LogLevel(log.Level)
		if err != nil {
			panic(err)
		}

		backend1Leveled.SetLevel(level, "")
		backend1Formatter := logging.NewBackendFormatter(backend1Leveled, format)

		logBackends = append(logBackends, backend1Formatter)
	}

	logging.SetBackend(logBackends...)

	for _, service := range server.Services {
		s := proxy.Service{}
		if err := md.PrimitiveDecode(service, &s); err != nil {
			panic(err)
		}

		var (
			creator backends.Creator
			ok      bool
		)

		if creator, ok = backends.Backends[s.Type]; !ok {
			log.Info("Backend %s not found.\n", s.Type)
			continue
		}

		backend := creator()
		if err := md.PrimitiveDecode(service, backend); err != nil {
			panic(err)
		}

		for _, host := range s.Hosts {
			log.Info("Registered backend for host %s and backend %s.\n", host, s.Type)
			backends.Hosts[host] = backend
		}
	}

	server.Start(backends.Backends)
}
