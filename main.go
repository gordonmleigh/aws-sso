package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"

	"github.com/charmbracelet/lipgloss"
	"github.com/gordonmleigh/aws-sso/cmd"
	"github.com/hashicorp/logutils"
)

// errors go to stderr, so the style is for whatever stderr is
var errorStyle = lipgloss.NewRenderer(os.Stderr).NewStyle().Foreground(lipgloss.Color("9"))

func main() {
	log.SetFlags(0)

	c, err := cmd.Parse(os.Args[0], os.Args[1:])
	if errors.Is(err, flag.ErrHelp) {
		// the usage has been printed
		os.Exit(0)
	}
	if err != nil {
		// the error and usage have been printed
		os.Exit(2)
	}

	var level logutils.LogLevel
	if c.Debug() {
		level = logutils.LogLevel("DEBUG")
	} else {
		level = logutils.LogLevel("WARN")
	}

	log.SetOutput(&logutils.LevelFilter{
		Levels:   []logutils.LogLevel{"DEBUG", "WARN", "ERROR"},
		MinLevel: level,
		Writer:   os.Stderr,
	})

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	err = c.Run(ctx)
	if err != nil {
		fmt.Fprintf(os.Stderr, "%v %v\n", errorStyle.Render("ERROR:"), err)
		os.Exit(1)
	}
}
