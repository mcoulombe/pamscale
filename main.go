package main

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"os/exec"
	"reflect"
	"time"

	"github.com/alecthomas/kong"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"golang.org/x/term"
	"tailscale.com/client/local"
	"tailscale.com/ipn/ipnstate"
)

type CLI struct {
	Verbose bool `kong:"help='Enable verbose logging',short='v',name='verbose'"`
	Debug   bool `kong:"help='Enable debug logging',short='d',name='debug'"`
}

var logger *zap.Logger

type Proxy struct {
	cli              *CLI
	tsClient         *local.Client
	httpClient       *http.Client
	userLogin        string
	sessionID        string
	lastTags         []string
	lastReadonlyRole bool
}

func initLogger(debug bool, verbose bool) {
	var config zap.Config

	isTTY := term.IsTerminal(int(os.Stdout.Fd()))

	if isTTY {
		config = zap.NewDevelopmentConfig()
		config.EncoderConfig.EncodeLevel = zapcore.CapitalColorLevelEncoder
		config.EncoderConfig.EncodeTime = zapcore.TimeEncoderOfLayout("15:04:05")
	} else {
		config = zap.NewProductionConfig()
		config.EncoderConfig.TimeKey = "timestamp"
		config.EncoderConfig.EncodeTime = zapcore.ISO8601TimeEncoder
	}

	if debug {
		config.Level = zap.NewAtomicLevelAt(zap.DebugLevel)
	} else if verbose {
		config.Level = zap.NewAtomicLevelAt(zap.InfoLevel)
	} else {
		config.Level = zap.NewAtomicLevelAt(zap.WarnLevel)
	}

	var err error
	logger, err = config.Build()
	if err != nil {
		log.Fatal("Failed to initialize logger:", err)
	}

	zap.ReplaceGlobals(logger)
}

func NewProxy(cli *CLI) (*Proxy, error) {
	return &Proxy{
		cli:      cli,
		tsClient: &local.Client{},
		httpClient: &http.Client{
			Timeout: 30 * time.Second,
		},
	}, nil
}

func (p *Proxy) Initialize(ctx context.Context) error {
	status, err := p.tsClient.Status(ctx)
	if err != nil {
		return fmt.Errorf("failed to get Tailscale status: %w", err)
	}

	if status.BackendState != "Running" {
		return fmt.Errorf("tailscale is not running (state: %s)", status.BackendState)
	}

	whoIs, err := p.tsClient.WhoIs(ctx, "100.64.172.23")
	if err != nil {
		return fmt.Errorf("failed to get WhoIs info: %w", err)
	}

	user := status.User[status.Self.UserID]
	p.userLogin = user.LoginName

	// Store initial tags and readonly tag state for comparison
	p.lastTags = p.getTagsFromNode(whoIs.Node)
	p.lastReadonlyRole = p.checkReadonlyUserTag(ctx)

	return nil
}

func (p *Proxy) Run(ctx context.Context) error {
	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
			if err := p.checkTagChanges(ctx); err != nil {
				logger.Error("Failed to check tag changes", zap.Error(err))
			}
		}
	}
}

// getTagsAsSlice converts Tailscale tags to a string slice for comparison
func (p *Proxy) getTagsAsSlice(status *ipnstate.Status) []string {
	var tags []string
	if status.Self.Tags != nil {
		for i := 0; i < status.Self.Tags.Len(); i++ {
			tags = append(tags, status.Self.Tags.At(i))
		}
	}
	return tags
}

// getTagsFromNode converts node tags to a string slice for comparison
func (p *Proxy) getTagsFromNode(node interface{}) []string {
	// Use reflection to access the Tags field
	nodeValue := reflect.ValueOf(node)
	if nodeValue.Kind() == reflect.Ptr {
		nodeValue = nodeValue.Elem()
	}

	tagsField := nodeValue.FieldByName("Tags")
	if !tagsField.IsValid() {
		return []string{}
	}

	var tags []string
	if tagsField.Kind() == reflect.Slice {
		for i := 0; i < tagsField.Len(); i++ {
			tag := tagsField.Index(i)
			if tag.Kind() == reflect.String {
				tags = append(tags, tag.String())
			}
		}
	}

	return tags
}

func (p *Proxy) checkTagChanges(ctx context.Context) error {
	whoIs, err := p.tsClient.WhoIs(ctx, "100.64.172.23")
	if err != nil {
		return fmt.Errorf("failed to get WhoIs info: %w", err)
	}

	currentTags := p.getTagsFromNode(whoIs.Node)

	// Compare with previous tags using deep equality
	if !reflect.DeepEqual(p.lastTags, currentTags) {
		// Tags have changed, display the new tags
		tagsJSON, err := json.MarshalIndent(currentTags, "", "  ")
		if err != nil {
			logger.Error("Failed to marshal tags", zap.Error(err))
		} else {
			fmt.Printf("Node tags changed:\n%s\n", string(tagsJSON))
		}

		// Check if readonly_user tag state has changed
		currentReadonlyRole := p.checkReadonlyUserTag(ctx)
		if currentReadonlyRole != p.lastReadonlyRole {
			p.onReadonlyUserRoleChanged(currentReadonlyRole)
			p.lastReadonlyRole = currentReadonlyRole
		}

		// Update our stored tags
		p.lastTags = currentTags
	}

	return nil
}

// checkReadonlyUserTag checks if the "tag:db-readonly-user" tag is present in the node tags
func (p *Proxy) checkReadonlyUserTag(ctx context.Context) bool {
	whoIs, err := p.tsClient.WhoIs(ctx, "100.64.172.23")
	if err != nil {
		logger.Error("Failed to get WhoIs info", zap.Error(err))
		return false
	}

	// Get tags from the node and check if tag:db-readonly-user is present
	tags := p.getTagsFromNode(whoIs.Node)
	for _, tag := range tags {
		if tag == "tag:db-readonly-user" {
			return true
		}
	}

	return false
}

// restartPgbouncer stops and starts pgbouncer using systemctl
func (p *Proxy) restartPgbouncer() error {
	// Stop pgbouncer
	stopCmd := exec.Command("sudo", "systemctl", "stop", "pgbouncer")
	if err := stopCmd.Run(); err != nil {
		return fmt.Errorf("failed to stop pgbouncer: %w", err)
	}

	// Start pgbouncer
	startCmd := exec.Command("sudo", "systemctl", "start", "pgbouncer")
	if err := startCmd.Run(); err != nil {
		return fmt.Errorf("failed to start pgbouncer: %w", err)
	}

	return nil
}

// updateUserList manages the readonly_user entry in the userlist
func (p *Proxy) updateUserList(addUser bool) error {
	const targetEntry = `"readonly_user" "foobar"`

	var content string
	if addUser {
		// File should contain exactly the target entry
		content = targetEntry + "\n"
		logger.Info("target '100.64.172.23' can now use the 'readonly_user' role")
	} else {
		// File should be empty (truncated)
		content = ""
		logger.Info("target '100.64.172.23' can no longer use the 'readonly_user' role")
	}

	// Write the exact content to the file
	err := ioutil.WriteFile("/etc/pgbouncer/userlist.txt", []byte(content), 0644)
	if err != nil {
		return fmt.Errorf("failed to write userlist.txt: %w", err)
	}

	// Restart pgbouncer using systemctl
	return p.restartPgbouncer()
}

// onReadonlyUserRoleChanged is the callback triggered when readonly_user role changes
func (p *Proxy) onReadonlyUserRoleChanged(hasRole bool) {
	if hasRole {
		if err := p.updateUserList(true); err != nil {
			logger.Error("Failed to add readonly_user to userlist", zap.Error(err))
		}
	} else {
		if err := p.updateUserList(false); err != nil {
			logger.Error("Failed to remove readonly_user from userlist", zap.Error(err))
		}
	}
}

// proxyLoop handles the main proxy loop between stdio and HTTP
func (p *Proxy) proxyLoop(ctx context.Context) error {
	scanner := bufio.NewScanner(os.Stdin)

	logger.Debug("Starting proxy loop")

	for scanner.Scan() {
		line := scanner.Text()
		if line == "" {
			continue
		}
	}

	logger.Debug("Proxy loop ended")
	return nil
}

func main() {
	var cli CLI
	kong.Parse(&cli)

	initLogger(cli.Debug, cli.Verbose)
	defer logger.Sync()
	logger.Info("PAMscale online",
		zap.Bool("verbose", cli.Verbose),
		zap.Bool("debug", cli.Debug),
	)

	proxy, err := NewProxy(&cli)
	if err != nil {
		logger.Fatal("Failed to create proxy", zap.Error(err))
	}

	if err := proxy.Initialize(context.Background()); err != nil {
		logger.Fatal("Failed to initialize proxy", zap.Error(err))
	}

	if err := proxy.Run(context.Background()); err != nil {
		logger.Fatal("Proxy failed", zap.Error(err))
	}
}
