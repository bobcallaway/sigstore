package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"
)

type PluginRequest struct {
	ProtocolVersion string `json:"protocol_version"`
	Method          string `json:"method"`
	Args            string `json:"args"`
	Stdin           string `json:"stdin"`
}

type PluginResponse struct {
	Success      bool   `json:"success"`
	Result       string `json:"result"`
	ErrorMessage string `json:"error_message,omitempty"`
}

type MockHSMDaemon struct {
	socket   net.Listener
	shutdown chan bool
	keys     map[string]string // Simple key storage
}

func NewMockHSMDaemon(socketPath string) (*MockHSMDaemon, error) {
	// Remove existing socket
	os.Remove(socketPath)
	
	socket, err := net.Listen("unix", socketPath)
	if err != nil {
		return nil, err
	}
	
	daemon := &MockHSMDaemon{
		socket:   socket,
		shutdown: make(chan bool),
		keys:     make(map[string]string),
	}
	
	// Pre-populate with a test key
	daemon.keys["test-key-1"] = "-----BEGIN PUBLIC KEY-----\nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA...\n-----END PUBLIC KEY-----"
	
	return daemon, nil
}

func (d *MockHSMDaemon) Start() {
	log.Printf("Daemon starting on socket: %s", d.socket.Addr().String())
	
	// Handle shutdown signals
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sigChan
		log.Println("Shutdown signal received")
		d.shutdown <- true
	}()
	
	for {
		select {
		case <-d.shutdown:
			log.Println("Daemon shutting down")
			d.socket.Close()
			return
		default:
			conn, err := d.socket.Accept()
			if err != nil {
				log.Printf("Accept error: %v", err)
				continue
			}
			go d.handleConnection(conn)
		}
	}
}

func (d *MockHSMDaemon) handleConnection(conn net.Conn) {
	defer conn.Close()
	
	scanner := bufio.NewScanner(conn)
	for scanner.Scan() {
		line := scanner.Text()
		if line == "" {
			continue
		}
		
		response := d.processRequest(line)
		responseBytes, _ := json.Marshal(response)
		
		conn.Write(responseBytes)
		conn.Write([]byte("\n"))
		break // One request per connection for simplicity
	}
}

func (d *MockHSMDaemon) processRequest(requestLine string) *PluginResponse {
	parts := strings.SplitN(requestLine, " ", 3)
	if len(parts) < 2 {
		return &PluginResponse{
			Success:      false,
			ErrorMessage: "Invalid request format",
		}
	}
	
	protocolVersion := parts[0]
	argsJSON := parts[1]
	
	log.Printf("Processing request - Protocol: %s, Args: %s", protocolVersion, argsJSON)
	
	// Simulate some async work (HSM operations are slow)
	time.Sleep(100 * time.Millisecond)
	
	// Parse the cliplugin args format
	var args map[string]interface{}
	if err := json.Unmarshal([]byte(argsJSON), &args); err != nil {
		return &PluginResponse{
			Success:      false,
			ErrorMessage: fmt.Sprintf("Failed to parse args: %v", err),
		}
	}
	
	// Extract method from nested structure
	methodArgs, ok := args["MethodArgs"].(map[string]interface{})
	if !ok {
		return &PluginResponse{
			Success:      false,
			ErrorMessage: "Missing MethodArgs",
		}
	}
	
	methodName, ok := methodArgs["MethodName"].(string)
	if !ok {
		return &PluginResponse{
			Success:      false,
			ErrorMessage: "Missing MethodName",
		}
	}
	
	// Handle different methods
	switch methodName {
	case "PublicKey":
		return &PluginResponse{
			Success: true,
			Result: `{"PublicKey": {"PublicKeyPEM": "-----BEGIN PUBLIC KEY-----\nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA7+5+2Z8k...\n-----END PUBLIC KEY-----"}}`,
		}
	case "SignMessage":
		return &PluginResponse{
			Success: true,
			Result:  `{"SignMessage": {"Signature": "MEUCIQDMockSignature123..."}}`,
		}
	case "DefaultAlgorithm":
		return &PluginResponse{
			Success: true,
			Result:  `{"DefaultAlgorithm": {"DefaultAlgorithm": "RSA_PKCS1V15_SHA256"}}`,
		}
	case "SupportedAlgorithms":
		return &PluginResponse{
			Success: true,
			Result:  `{"SupportedAlgorithms": {"SupportedAlgorithms": ["RSA_PKCS1V15_SHA256", "ECDSA_P256_SHA256"]}}`,
		}
	default:
		return &PluginResponse{
			Success:      false,
			ErrorMessage: fmt.Sprintf("Unsupported method: %s", methodName),
		}
	}
}

func (d *MockHSMDaemon) Stop() {
	d.shutdown <- true
}

func main() {
	if len(os.Args) != 2 {
		log.Fatal("Usage: demo-plugin-daemon <socket-path>")
	}
	
	socketPath := os.Args[1]
	daemon, err := NewMockHSMDaemon(socketPath)
	if err != nil {
		log.Fatalf("Failed to create daemon: %v", err)
	}
	
	daemon.Start()
}