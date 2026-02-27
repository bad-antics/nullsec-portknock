# NullSec PortKnock

Tcl port knocking detector demonstrating event-driven programming and dynamic typing.

## Features

- **Event-Driven** - Callback-based detection
- **Dynamic Typing** - Runtime introspection
- **Namespaces** - Clean code organization
- **Coroutines** - Async support (Tcl 8.6+)
- **Pattern Matching** - Sequence detection

## Detection Patterns

| Pattern | Description | Severity |
|---------|-------------|----------|
| basic_3port | 3+ ports in sequence | Medium |
| complex_5port | 5+ port sequence | High |
| ssh_unlock | 7000 → 8000 → 9000 | High |
| fwknop_spa | Single packet on 62201 | Medium |

## Run

```bash
# With tclsh
tclsh portknock.tcl

# Make executable
chmod +x portknock.tcl
./portknock.tcl

# Custom options
tclsh portknock.tcl -i eth0 -w 10000
```

## Usage

```bash
# Basic monitoring
./portknock.tcl

# Specific interface
./portknock.tcl -i eth0

# Custom detection window (ms)
./portknock.tcl -w 10000

# JSON output
./portknock.tcl -j > detections.json

# Verbose mode
./portknock.tcl -v
```

## Output Example

```
Monitoring traffic...

[HIGH]     SSH unlock sequence
    Source: 192.168.1.100
    Ports:  7000 -> 8000 -> 9000

[MEDIUM]   Unknown port sequence (4 ports)
    Source: 10.0.0.50
    Ports:  1234 -> 5678 -> 9012 -> 3456

Summary:
  Total Detections: 2
  Critical:     0
  High:         1
  Medium:       1
```

## Algorithm

1. Track connection events per source IP
2. Maintain sliding time window
3. Match against known patterns
4. Alert on sequence detection
5. Correlate timing characteristics

## Limitations

- Requires root/admin for raw sockets
- High traffic may need optimization
- UDP knocking requires protocol detection

## Author

bad-antics | [Twitter](https://x.com/AnonAntics)

## License

MIT
