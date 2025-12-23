package messages

import (
	"fmt"
	"io"
	"os"

	"github.com/logrusorgru/aurora"
	"github.com/mattn/go-colorable"
	"github.com/mattn/go-isatty"
)

const showErrorEnvKey = "CFSECURITY_DEBUG"

func init() {
	if os.Getenv(showErrorEnvKey) != "" {
		showError = true
	}
}

var showError = false
var stdout = colorable.NewColorableStdout()
var C = aurora.NewAurora(isatty.IsTerminal(os.Stdout.Fd()))

func Output() io.Writer {
	return stdout
}

func Println(a ...interface{}) (n int, err error) {
	return fmt.Fprintln(stdout, a...)
}

func Print(a ...interface{}) (n int, err error) {
	return fmt.Fprint(stdout, a...)
}

func Printf(format string, a ...interface{}) (n int, err error) {
	return fmt.Fprintf(stdout, format, a...)
}

func Printfln(format string, a ...interface{}) (n int, err error) {
	return fmt.Fprintf(stdout, format+"\n", a...)
}

func Error(str string) {
	if !showError {
		return
	}
	// Fix errcheck: ignore write errors on stdout (non-recoverable)
	_, _ = Printfln("%s: %s", C.Red("Error"), str)
}

func Errorf(format string, a ...interface{}) {
	if !showError {
		return
	}
	// Fix errcheck: ignore write errors on stdout (non-recoverable)
	_, _ = Printf("%s: ", C.Red("Error"))
	_, _ = Printfln(format, a...)
}

func Fatal(str string) {
	// Fix errcheck: ignore write errors on stdout (non-recoverable)
	_, _ = Printfln("%s: %s", C.Red("Error"), str)
	os.Exit(1)
}

func Fatalf(format string, a ...interface{}) {
	// Fix errcheck: ignore write errors on stdout (non-recoverable)
	_, _ = Printf("%s: ", C.Red("Error"))
	_, _ = Printfln(format, a...)
	os.Exit(1)
}

func Warning(str string) {
	if !showError {
		return
	}
	// Fix errcheck: ignore write errors on stdout (non-recoverable)
	_, _ = Printfln("%s: %s", C.Magenta("Warning"), str)
}

func Warningf(format string, a ...interface{}) {
	if !showError {
		return
	}
	// Fix errcheck: ignore write errors on stdout (non-recoverable)
	_, _ = Printf("%s: ", C.Yellow("Warning"))
	_, _ = Printfln(format, a...)
}
