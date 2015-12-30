package proxy

import (
	"io"
	"os"

	logging "github.com/op/go-logging"
)

type Logging struct {
}

func (d *Logging) UnmarshalTOML(data interface{}) (err error) {
	backends := []logging.Backend{}

	for _, data2 := range data.([]map[string]interface{}) {
		var output io.Writer = os.Stdout
		switch data2["output"].(string) {
		case "stdout":
		case "stderr":
			output = os.Stderr
		default:
			output, err = os.OpenFile(data2["output"].(string), os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0666)
		}

		if err != nil {
			panic(err)
		}

		backend1 := logging.NewLogBackend(output, "", 0)
		backend1Leveled := logging.AddModuleLevel(backend1)

		level, err := logging.LogLevel(data2["level"].(string))
		if err != nil {
			panic(err)
		}

		backend1Leveled.SetLevel(level, "")

		var format = logging.MustStringFormatter(
			"%{color}%{time:15:04:05.000} %{shortfunc} ▶ %{level:.4s} %{id:03x}%{color:reset} %{message}",
		)

		if val, ok := data2["format"].(string); ok {
			format = logging.MustStringFormatter(val)
		}

		backend1Formatter := logging.NewBackendFormatter(backend1Leveled, format)

		backends = append(backends, backend1Formatter)
	}

	logging.SetBackend(backends...)
	return nil
}
