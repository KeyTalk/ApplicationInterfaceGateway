package main

import (
	"backends"
	_ "backends/headfirst"
	"flag"
	"log"
	"os"
	"proxy"
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

	if _, err := toml.DecodeFile(configFile, &server); err != nil {
		log.Fatal(err)
	}

	backend1 := logging.NewLogBackend(os.Stdout, "", 0)
	backend1Leveled := logging.AddModuleLevel(backend1)
	backend1Leveled.SetLevel(logging.DEBUG, "")

	backend1Formatter := logging.NewBackendFormatter(backend1, format)

	logging.SetBackend(backend1Formatter)

	server.Start(backends.Backends)
}
