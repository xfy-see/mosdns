//go:build mosdns_minimal

package coremain

import (
	"errors"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/IrineSistiana/mosdns/v5/pkg/utils"
	"go.uber.org/zap"
)

var minimalVersion = "dev/unknown"

func SetMinimalVersion(v string) { minimalVersion = v }

// Run keeps the foreground lifecycle used by OpenWrt procd. Management and
// conversion commands belong to the full build.
func Run() error {
	args := os.Args[1:]
	if len(args) == 0 || args[0] == "help" || args[0] == "--help" || args[0] == "-h" {
		fmt.Println("mosdns minimal: version | start [-c config] [-d directory] [--cpu n] | check [-c config] [-d directory]")
		return nil
	}
	if args[0] == "version" {
		if len(args) != 1 {
			return errors.New("version takes no arguments")
		}
		fmt.Println(minimalVersion)
		return nil
	}
	if args[0] != "start" && args[0] != "check" {
		return fmt.Errorf("command %q is not available in the mosdns_minimal build", args[0])
	}
	sf := new(serverFlags)
	fs := flag.NewFlagSet(args[0], flag.ContinueOnError)
	fs.StringVar(&sf.c, "c", "", "configuration file")
	fs.StringVar(&sf.c, "config", "", "configuration file")
	fs.StringVar(&sf.dir, "d", "", "working directory")
	fs.StringVar(&sf.dir, "dir", "", "working directory")
	fs.IntVar(&sf.cpu, "cpu", 0, "runtime.GOMAXPROCS")
	if err := fs.Parse(args[1:]); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return nil
		}
		return err
	}
	if fs.NArg() != 0 {
		return errors.New("unexpected positional arguments")
	}
	if args[0] == "check" {
		if sf.dir != "" {
			if err := os.Chdir(sf.dir); err != nil {
				return err
			}
		}
		if err := checkMinimalConfig(sf.c, 0); err != nil {
			return err
		}
		fmt.Println("configuration decoding and plugin availability checks passed; startup validates plugin options and sockets")
		return nil
	}
	m, err := NewServer(sf)
	if err != nil {
		return err
	}
	signals := make(chan os.Signal, 1)
	signal.Notify(signals, syscall.SIGINT, syscall.SIGTERM)
	defer signal.Stop(signals)
	go func() {
		select {
		case sig := <-signals:
			m.logger.Warn("signal received", zap.Stringer("signal", sig))
			m.sc.SendCloseSignal(nil)
		case <-m.sc.ReceiveCloseSignal():
		}
	}()
	return m.GetSafeClose().WaitClosed()
}

// This command deliberately does not initialize plugins: checking a file must
// never open a listener or alter nftables.
func checkMinimalConfig(path string, depth int) error {
	if depth > 8 {
		return errors.New("maximum include depth reached")
	}
	cfg, _, err := loadConfig(path)
	if err != nil {
		return err
	}
	if err := validateProfileConfig(cfg); err != nil {
		return err
	}
	for _, include := range cfg.Include {
		if err := checkMinimalConfig(include, depth+1); err != nil {
			return err
		}
	}
	for _, p := range cfg.Plugins {
		info, ok := GetPluginType(p.Type)
		if !ok {
			return fmt.Errorf("plugin type %s is not available in the mosdns_minimal build", p.Type)
		}
		if err := utils.WeakDecode(p.Args, info.NewArgs()); err != nil {
			return fmt.Errorf("plugin %s: %w", p.Type, err)
		}
	}
	return nil
}
