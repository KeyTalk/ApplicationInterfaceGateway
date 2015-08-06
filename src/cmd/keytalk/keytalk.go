package main

import (
	"backends"
	_ "backends/headfirst"
	// _ "backends/sugarcrm"
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

	w, err := os.OpenFile("logs/log.txt", os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0666)
	if err != nil {
		panic(err)
	}

	backend2 := logging.NewLogBackend(w, "", 0)
	backend2Leveled := logging.AddModuleLevel(backend2)
	backend2Leveled.SetLevel(logging.DEBUG, "")

	backend2Formatter := logging.NewBackendFormatter(backend2, format)

	logging.SetBackend(backend1Formatter, backend2Formatter)

	server.Start(backends.Backends)
}
