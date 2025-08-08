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
	"strings"
	"time"

	"github.com/alecthomas/kong"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"golang.org/x/term"
	"tailscale.com/client/local"
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
	lastCapMap       interface{}
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

	// Store initial CapMap and readonly role state for comparison
	p.lastCapMap = whoIs.Node.CapMap
	p.lastReadonlyRole = p.checkReadonlyUserRole(whoIs.Node.CapMap)

	logger.Info("Proxy initialized",
		zap.String("user", p.userLogin),
		zap.String("node", status.Self.DNSName),
		zap.String("backend_state", status.BackendState),
		zap.Any("cap", whoIs.Node.CapMap),
		zap.Any("tags", whoIs.Node.Tags),
	)

	return nil
}

func (p *Proxy) Run(ctx context.Context) error {
	logger.Info("Starting PAMscale - monitoring CapMap changes every 2 seconds")

	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
			if err := p.checkCapMapChanges(ctx); err != nil {
				logger.Error("Failed to check CapMap changes", zap.Error(err))
			}
		}
	}
}

func (p *Proxy) checkCapMapChanges(ctx context.Context) error {
	whoIs, err := p.tsClient.WhoIs(ctx, "100.64.172.23")
	if err != nil {
		return fmt.Errorf("failed to get WhoIs info: %w", err)
	}

	currentCapMap := whoIs.Node.CapMap

	// Compare with previous CapMap using deep equality
	if !reflect.DeepEqual(p.lastCapMap, currentCapMap) {
		// CapMap has changed, marshal to JSON and extract PAMscale capability
		capMapJSON, err := json.Marshal(currentCapMap)
		if err != nil {
			logger.Error("Failed to marshal CapMap", zap.Error(err))
		} else {
			var capMapData map[string]interface{}
			if err := json.Unmarshal(capMapJSON, &capMapData); err != nil {
				logger.Error("Failed to unmarshal CapMap", zap.Error(err))
			} else {
				if pamscaleCap, exists := capMapData["hackweek.com/cap/PAMscale"]; exists {
					pamscaleJSON, err := json.MarshalIndent(pamscaleCap, "", "  ")
					if err != nil {
						logger.Error("Failed to marshal PAMscale capability", zap.Error(err))
					} else {
						fmt.Printf("PAMscale capability changed:\n%s\n", string(pamscaleJSON))
					}
				}
			}
		}

		// Check if readonly_user role state has changed
		currentReadonlyRole := p.checkReadonlyUserRole(currentCapMap)
		if currentReadonlyRole != p.lastReadonlyRole {
			p.onReadonlyUserRoleChanged(currentReadonlyRole)
			p.lastReadonlyRole = currentReadonlyRole
		}

		// Update our stored CapMap
		p.lastCapMap = currentCapMap
	}

	return nil
}

// checkReadonlyUserRole checks if the readonly_user role is present in the PAMscale capability
func (p *Proxy) checkReadonlyUserRole(capMap interface{}) bool {
	// Marshal and unmarshal to convert NodeCapMap to map[string]interface{}
	capMapJSON, err := json.Marshal(capMap)
	if err != nil {
		return false
	}

	var capMapData map[string]interface{}
	if err := json.Unmarshal(capMapJSON, &capMapData); err != nil {
		return false
	}

	// Look for the PAMscale capability
	pamscaleCap, exists := capMapData["hackweek.com/cap/PAMscale"]
	if !exists {
		return false
	}

	// Parse the capability as an array
	pamscaleArray, ok := pamscaleCap.([]interface{})
	if !ok {
		return false
	}

	// Check each target in the capability
	for _, item := range pamscaleArray {
		target, ok := item.(map[string]interface{})
		if !ok {
			continue
		}

		targets, exists := target["targets"]
		if !exists {
			continue
		}

		targetsMap, ok := targets.(map[string]interface{})
		if !ok {
			continue
		}

		roles, exists := targetsMap["roles"]
		if !exists {
			continue
		}

		rolesArray, ok := roles.([]interface{})
		if !ok {
			continue
		}

		// Check if "readonly_user" is in the roles array
		for _, role := range rolesArray {
			if roleStr, ok := role.(string); ok && roleStr == "readonly_user" {
				return true
			}
		}
	}

	return false
}

// readUserList reads the pgbouncer userlist file and returns its lines
func (p *Proxy) readUserList() ([]string, error) {
	content, err := ioutil.ReadFile("/etc/pgbouncer/userlist.txt")
	if err != nil {
		if os.IsNotExist(err) {
			return []string{}, nil // Return empty list if file doesn't exist
		}
		return nil, fmt.Errorf("failed to read userlist.txt: %w", err)
	}
	
	lines := strings.Split(string(content), "\n")
	// Filter out empty lines
	var result []string
	for _, line := range lines {
		if strings.TrimSpace(line) != "" {
			result = append(result, line)
		}
	}
	
	return result, nil
}

// writeUserList writes the updated userlist back to the file
func (p *Proxy) writeUserList(lines []string) error {
	content := strings.Join(lines, "\n")
	if len(lines) > 0 {
		content += "\n" // Add trailing newline if there are lines
	}
	
	err := ioutil.WriteFile("/etc/pgbouncer/userlist.txt", []byte(content), 0644)
	if err != nil {
		return fmt.Errorf("failed to write userlist.txt: %w", err)
	}
	
	return nil
}

// reloadPgbouncer sends a SIGHUP to pgbouncer to reload configuration
func (p *Proxy) reloadPgbouncer() error {
	cmd := exec.Command("pkill", "-HUP", "pgbouncer")
	err := cmd.Run()
	if err != nil {
		return fmt.Errorf("failed to reload pgbouncer: %w", err)
	}
	
	logger.Info("Pgbouncer configuration reloaded")
	return nil
}

// updateUserList manages the readonly_user entry in the userlist
func (p *Proxy) updateUserList(addUser bool) error {
	lines, err := p.readUserList()
	if err != nil {
		return err
	}
	
	const targetEntry = `"readonly_user" "foobar"`
	
	// Remove any existing readonly_user entry
	var filteredLines []string
	for _, line := range lines {
		if !strings.Contains(line, "readonly_user") {
			filteredLines = append(filteredLines, line)
		}
	}
	
	// Add the entry if requested
	if addUser {
		filteredLines = append(filteredLines, targetEntry)
		logger.Info("Added readonly_user to pgbouncer userlist")
	} else {
		logger.Info("Removed readonly_user from pgbouncer userlist")
	}
	
	// Write the updated userlist
	if err := p.writeUserList(filteredLines); err != nil {
		return err
	}
	
	// Reload pgbouncer configuration
	return p.reloadPgbouncer()
}

// onReadonlyUserRoleChanged is the callback triggered when readonly_user role changes
func (p *Proxy) onReadonlyUserRoleChanged(hasRole bool) {
	if hasRole {
		fmt.Println("readonly_user role added - updating pgbouncer userlist")
		if err := p.updateUserList(true); err != nil {
			logger.Error("Failed to add readonly_user to userlist", zap.Error(err))
		}
	} else {
		fmt.Println("readonly_user role removed - updating pgbouncer userlist") 
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
	logger.Info("Starting PAMscale",
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
