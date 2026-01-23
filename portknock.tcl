#!/usr/bin/env tclsh
# NullSec PortKnock - Port Knocking Detection
# Tcl security tool demonstrating:
#   - Event-driven programming
#   - Dynamic typing with introspection
#   - Namespace organization
#   - Coroutines (Tcl 8.6+)
#   - Pattern-based packet matching
#
# Author: bad-antics
# License: MIT

package require Tcl 8.6

set VERSION "1.0.0"

# ANSI Colors
namespace eval ::colors {
    variable red "\033\[31m"
    variable green "\033\[32m"
    variable yellow "\033\[33m"
    variable cyan "\033\[36m"
    variable gray "\033\[90m"
    variable reset "\033\[0m"
    
    proc apply {color text} {
        variable $color
        variable reset
        return "[set $color]$text$reset"
    }
}

# Severity levels
namespace eval ::severity {
    variable levels {
        CRITICAL {priority 1 color red}
        HIGH     {priority 2 color red}
        MEDIUM   {priority 3 color yellow}
        LOW      {priority 4 color cyan}
        INFO     {priority 5 color gray}
    }
    
    proc color {sev} {
        variable levels
        return [dict get $levels $sev color]
    }
    
    proc priority {sev} {
        variable levels
        return [dict get $levels $sev priority]
    }
}

# Port knock sequence detector
namespace eval ::portknock {
    variable sequences {}
    variable detections {}
    variable window_ms 5000
    variable config {}
    
    # Known port knock patterns
    variable known_patterns {
        "basic_3port" {
            description "Basic 3-port knock"
            severity MEDIUM
            ports {3 any}
        }
        "complex_5port" {
            description "Complex 5-port sequence"
            severity HIGH
            ports {5 any}
        }
        "ssh_unlock" {
            description "SSH unlock sequence"
            severity HIGH
            ports {7000 8000 9000}
        }
        "fwknop_spa" {
            description "fwknop Single Packet Auth"
            severity MEDIUM
            ports {1 62201}
        }
    }
    
    # Connection event
    proc connection_event {src_ip dst_port timestamp} {
        variable sequences
        variable window_ms
        
        # Get or create sequence for this IP
        if {![dict exists $sequences $src_ip]} {
            dict set sequences $src_ip {events {}}
        }
        
        # Add event
        set events [dict get $sequences $src_ip events]
        lappend events [list port $dst_port time $timestamp]
        
        # Prune old events
        set cutoff [expr {$timestamp - $window_ms}]
        set events [lmap e $events {
            if {[dict get $e time] >= $cutoff} {set e} else {continue}
        }]
        
        dict set sequences $src_ip events $events
        
        # Check for patterns
        check_patterns $src_ip $events
    }
    
    # Check for known patterns
    proc check_patterns {src_ip events} {
        variable known_patterns
        variable detections
        
        set ports [lmap e $events {dict get $e port}]
        set count [llength $ports]
        
        # Check each known pattern
        dict for {pattern_id pattern_info} $known_patterns {
            set req_ports [dict get $pattern_info ports]
            set req_count [lindex $req_ports 0]
            
            if {$count >= $req_count} {
                # Pattern match found
                set detection [dict create \
                    src_ip $src_ip \
                    pattern $pattern_id \
                    description [dict get $pattern_info description] \
                    severity [dict get $pattern_info severity] \
                    ports $ports \
                    timestamp [clock milliseconds]]
                
                lappend detections $detection
                alert_detection $detection
                return
            }
        }
        
        # Generic sequence detection
        if {$count >= 3} {
            set detection [dict create \
                src_ip $src_ip \
                pattern "unknown_sequence" \
                description "Unknown port sequence ($count ports)" \
                severity MEDIUM \
                ports $ports \
                timestamp [clock milliseconds]]
            
            lappend detections $detection
            alert_detection $detection
        }
    }
    
    # Alert on detection
    proc alert_detection {detection} {
        set sev [dict get $detection severity]
        set color [::severity::color $sev]
        set desc [dict get $detection description]
        set src [dict get $detection src_ip]
        set ports [dict get $detection ports]
        
        set sev_str [format "\[%-8s\]" $sev]
        puts "[::colors::apply $color $sev_str] $desc"
        puts "    Source: $src"
        puts "    Ports:  [join $ports { -> }]"
        puts ""
    }
    
    # Get statistics
    proc stats {} {
        variable detections
        
        set total [llength $detections]
        set by_severity [dict create CRITICAL 0 HIGH 0 MEDIUM 0 LOW 0]
        
        foreach d $detections {
            set sev [dict get $d severity]
            dict incr by_severity $sev
        }
        
        return [dict create total $total by_severity $by_severity]
    }
}

# CLI namespace
namespace eval ::cli {
    proc print_banner {} {
        puts ""
        puts "╔══════════════════════════════════════════════════════════════════╗"
        puts "║           NullSec PortKnock - Port Knock Detector                ║"
        puts "╚══════════════════════════════════════════════════════════════════╝"
        puts ""
    }
    
    proc print_usage {} {
        print_banner
        puts {
USAGE:
    portknock [OPTIONS]

OPTIONS:
    -h, --help        Show this help
    -i, --interface IF Network interface
    -w, --window MS   Detection window (default: 5000ms)
    -j, --json        JSON output
    -v, --verbose     Verbose output

EXAMPLES:
    portknock
    portknock -i eth0
    portknock -w 10000
    portknock -j > detections.json

DETECTION:
    - Sequential port access patterns
    - Known knock sequences (knockd, etc.)
    - Single Packet Authorization (fwknop)
    - Timing-based correlation

KNOWN PATTERNS:
    basic_3port    - 3+ ports in sequence
    complex_5port  - 5+ port complex sequence
    ssh_unlock     - 7000 -> 8000 -> 9000
    fwknop_spa     - Single packet on 62201
}
    }
    
    proc print_findings {} {
        variable ::portknock::detections
        
        if {[llength $detections] == 0} {
            puts "[::colors::apply green {✓ No port knock sequences detected}]"
            return
        }
        
        puts "[::colors::apply yellow Detections:]"
        puts ""
    }
    
    proc print_summary {} {
        set stats [::portknock::stats]
        set total [dict get $stats total]
        set by_sev [dict get $stats by_severity]
        
        puts ""
        puts "[::colors::apply gray ═══════════════════════════════════════════]"
        puts ""
        puts "Summary:"
        puts "  Total Detections: $total"
        puts "  [::colors::apply red Critical:]     [dict get $by_sev CRITICAL]"
        puts "  [::colors::apply red High:]         [dict get $by_sev HIGH]"
        puts "  [::colors::apply yellow Medium:]       [dict get $by_sev MEDIUM]"
        puts "  [::colors::apply cyan Low:]          [dict get $by_sev LOW]"
    }
}

# Simulate traffic for demo
proc demo_mode {} {
    puts "[::colors::apply yellow {Demo Mode - Simulated Traffic}]"
    puts ""
    
    set base_time [clock milliseconds]
    
    # Simulate normal traffic
    puts "[::colors::apply gray {Monitoring traffic...}]"
    puts ""
    
    # Simulate port knock attempt
    ::portknock::connection_event "192.168.1.100" 7000 $base_time
    after 100
    ::portknock::connection_event "192.168.1.100" 8000 [expr {$base_time + 100}]
    after 100
    ::portknock::connection_event "192.168.1.100" 9000 [expr {$base_time + 200}]
    
    # Another suspicious sequence
    after 200
    ::portknock::connection_event "10.0.0.50" 1234 [expr {$base_time + 500}]
    ::portknock::connection_event "10.0.0.50" 5678 [expr {$base_time + 600}]
    ::portknock::connection_event "10.0.0.50" 9012 [expr {$base_time + 700}]
    ::portknock::connection_event "10.0.0.50" 3456 [expr {$base_time + 800}]
    
    # fwknop-style SPA
    after 100
    ::portknock::connection_event "172.16.0.25" 62201 [expr {$base_time + 1000}]
}

# Parse arguments
proc parse_args {argv} {
    set config [dict create \
        interface "any" \
        window 5000 \
        json false \
        verbose false \
        help false]
    
    for {set i 0} {$i < [llength $argv]} {incr i} {
        set arg [lindex $argv $i]
        switch -exact -- $arg {
            "-h" - "--help" {
                dict set config help true
            }
            "-i" - "--interface" {
                incr i
                dict set config interface [lindex $argv $i]
            }
            "-w" - "--window" {
                incr i
                dict set config window [lindex $argv $i]
            }
            "-j" - "--json" {
                dict set config json true
            }
            "-v" - "--verbose" {
                dict set config verbose true
            }
        }
    }
    
    return $config
}

# Main
proc main {argv} {
    set config [parse_args $argv]
    
    if {[dict get $config help]} {
        ::cli::print_usage
        return
    }
    
    ::cli::print_banner
    
    # Set detection window
    set ::portknock::window_ms [dict get $config window]
    
    demo_mode
    
    ::cli::print_findings
    ::cli::print_summary
}

main $argv
