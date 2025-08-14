# Async Sigstore Plugin Demo

This demonstrates how to create a sigstore cliplugin that performs asynchronous operations while maintaining compatibility with sigstore's synchronous process model.

## Problem Solved

Sigstore cliplugins normally spawn a new process for each operation and wait for it to complete. This is inefficient for:
- HSM operations with network latency
- Cryptographic operations requiring authentication/setup
- Any operation that benefits from persistent connections

## Solution

This implementation uses a **daemon + wrapper** pattern:
- **Daemon**: Persistent Go process handling slow operations
- **Wrapper**: Shell script that sigstore sees as a normal plugin
- **Communication**: Unix domain socket between wrapper and daemon

## Files

- `demo-plugin-daemon.go` - The persistent daemon that handles actual operations
- `sigstore-kms-demo` - Wrapper script that sigstore invokes (rename for your plugin)
- `test-plugin.sh` - Test suite demonstrating functionality

## How It Works

1. **First call**: Wrapper starts daemon if not running
2. **Communication**: Wrapper forwards sigstore's request via Unix socket
3. **Processing**: Daemon performs operation (simulated 100ms delay)
4. **Response**: Daemon returns JSON, wrapper forwards to sigstore
5. **Persistence**: Daemon stays running for subsequent calls

## Benefits

- ✅ **Performance**: Daemon reuse eliminates process startup overhead
- ✅ **Compatibility**: Sigstore sees normal synchronous behavior  
- ✅ **Async operations**: Daemon can handle slow/network operations
- ✅ **State preservation**: Maintain connections, caches, auth tokens
- ✅ **Language agnostic**: Daemon can be written in any language

## Usage

### Testing

```bash
# Run the test suite
./test-plugin.sh

# Manual test
./sigstore-kms-demo "1" '{"InitOptions":{"ProtocolVersion":"1","KeyResourceID":"demo://test-key","HashFunc":4},"MethodArgs":{"MethodName":"PublicKey","PublicKey":{"PublicKeyOptions":{}}}}'
```

### Integration with Cosign

1. **Rename the plugin**:
   ```bash
   cp sigstore-kms-demo sigstore-kms-myhsm
   chmod +x sigstore-kms-myhsm
   ```

2. **Place in PATH**:
   ```bash
   cp sigstore-kms-myhsm /usr/local/bin/
   ```

3. **Use with cosign**:
   ```bash
   cosign sign --key "myhsm://my-key-id" container-image
   ```

## Customization

### Modify the Daemon

Edit `demo-plugin-daemon.go` to:
- Connect to your actual HSM/KMS
- Implement real cryptographic operations
- Add authentication, caching, etc.
- Handle additional methods

### Protocol Support

The daemon implements these sigstore cliplugin methods:
- `PublicKey` - Returns public key in PEM format
- `SignMessage` - Signs data and returns signature
- `DefaultAlgorithm` - Returns preferred algorithm
- `SupportedAlgorithms` - Lists supported algorithms

Add more methods by:
1. Adding cases to `processRequest()` in the daemon
2. Ensuring JSON response format matches sigstore expectations

### Configuration

Environment variables you can add:
- `DAEMON_SOCKET_PATH` - Custom socket location
- `DAEMON_TIMEOUT` - Operation timeout
- `DAEMON_LOG_LEVEL` - Logging verbosity
- `HSM_ENDPOINT` - Your HSM connection details

## Architecture

```
┌─────────────┐    ┌────────────────┐    ┌─────────────┐
│   sigstore  │───▶│ sigstore-kms-* │───▶│   daemon    │
│  (cosign)   │    │  (wrapper)     │    │ (persistent)│
└─────────────┘    └────────────────┘    └─────────────┘
                           │                      │
                           └──── Unix Socket ─────┘
```

1. **Sigstore** calls wrapper with protocol args
2. **Wrapper** forwards request via Unix socket
3. **Daemon** processes request asynchronously
4. **Daemon** returns JSON response
5. **Wrapper** forwards response to sigstore

## Debugging

Enable debug output:
```bash
DEBUG=1 ./sigstore-kms-demo "1" '...'
```

Check daemon logs:
```bash
# Daemon logs to stderr, visible when started manually
./demo-plugin-daemon /tmp/debug.sock
```

Manual socket testing:
```bash
# Start daemon
./demo-plugin-daemon /tmp/test.sock &

# Send test request
echo '1 {"test":"data"}' | nc -U /tmp/test.sock
```

## Cleanup

The daemon persists until manually killed:
```bash
killall demo-plugin-daemon
rm -f /tmp/demo-plugin-daemon.*
```

## Performance

This demo simulates 100ms delays to show async behavior. Real benefits depend on your operations:
- **HSM network calls**: 50-500ms saved per operation
- **Authentication**: One-time setup vs per-call overhead  
- **Connection pooling**: Reuse expensive resources
- **Caching**: Store public keys, certificates, etc.

## Security Notes

- Unix sockets provide process-local communication
- Daemon runs with same privileges as wrapper
- No network exposure by default
- Consider adding authentication between wrapper and daemon for production use

## Community

This pattern can be adopted by any sigstore plugin needing async operations. The core insight is that sigstore's process-per-call model can be transparently bridged to persistent daemon architectures.

Feel free to use this as a starting point for your own HSM/KMS integrations!