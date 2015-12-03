package main

import (
	"fmt"
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

	for _, service := range server.Services {
		fmt.Printf("%#v", service)
		s := proxy.Service{}
		if err := md.PrimitiveDecode(service, &s); err != nil {
			panic(err)
		}

		var (
			creator backends.Creator
			ok      bool
		)

		if creator, ok = backends.Backends[s.Type]; !ok {
			fmt.Printf("Backend %s not found.\n", s.Type)
			continue
		}

		backend := creator()
		if err := md.PrimitiveDecode(service, backend); err != nil {
			panic(err)
		}

		for _, host := range s.Hosts {
			fmt.Printf("Registered backend for host %s.\n", host)
			backends.Hosts[host] = backend
		}
	}

	backend1 := logging.NewLogBackend(os.Stdout, "", 0)
	backend1Leveled := logging.AddModuleLevel(backend1)

	// TODO: from config
	backend1Leveled.SetLevel(logging.INFO, "")
	backend1Formatter := logging.NewBackendFormatter(backend1Leveled, format)

	w, err := os.OpenFile("logs/log.txt", os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0666)
	if err != nil {
		panic(err)
	}

	backend2 := logging.NewLogBackend(w, "", 0)
	backend2Leveled := logging.AddModuleLevel(backend2)
	backend2Leveled.SetLevel(logging.INFO, "")

	backend2Formatter := logging.NewBackendFormatter(backend2Leveled, format)

	logging.SetBackend(backend1Formatter, backend2Formatter)

	server.Start(backends.Backends)
}
