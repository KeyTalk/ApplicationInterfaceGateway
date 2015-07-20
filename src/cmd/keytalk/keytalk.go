package main

import (
	"flag"
	"log"
	"proxy"

	"github.com/BurntSushi/toml"
)

var server proxy.Server
var configFile string

func init() {
	flag.StringVar(&configFile, "config", "config.toml", "specifies the location of the config file")
}

func main() {
	flag.Parse()

	if _, err := toml.DecodeFile(configFile, &server); err != nil {
		log.Fatal(err)
	}

	server.Start()
}
