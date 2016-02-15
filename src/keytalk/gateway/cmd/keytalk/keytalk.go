package main

import (
	_ "keytalk/gateway/backends/forfarmers"
	_ "keytalk/gateway/backends/headfirst"
	_ "keytalk/gateway/backends/ldap"

	"keytalk/gateway/proxy"

	"flag"
	"runtime"

	logging "github.com/op/go-logging"
)

var version = "0.1"

var format = logging.MustStringFormatter(
	"%{color}%{time:15:04:05.000} %{shortfunc} ▶ %{level:.4s} %{id:03x}%{color:reset} %{message}",
)

var log = logging.MustGetLogger("main")

func init() {
	runtime.GOMAXPROCS(runtime.NumCPU())
}

func main() {
	var configFile string
	flag.StringVar(&configFile, "config", "config.toml", "specifies the location of the config file")
	flag.Parse()

	server := proxy.New(configFile)
	server.Serve()
}
