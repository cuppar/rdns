# Rust DNS

A toy DNS by Rust from scratch.

rdns default use port 22222 to open underlying UDP connection.

Usage:
```
rdns <domain> <query-type>

    <query-type> is one of:
        - a
        - ns
        - cname
        - mx
        - aaaa
```