<?php

return [

    /*
    |--------------------------------------------------------------------------
    | HTTP Client
    |--------------------------------------------------------------------------
    |
    | Configuration for Laravel's HTTP client. The "ssrf_guard" block protects
    | your application against Server-Side Request Forgery (SSRF) by blocking
    | outbound requests to private IP ranges, internal hostnames, sensitive
    | ports, and non-allow-listed URL schemes.
    |
    */

    'ssrf_guard' => [

        // Master switch.
        //
        // When unset, the guard is auto-enabled for new Laravel applications
        // (those installed on or after 2026-08-01, detected via the
        // LARAVEL_START timestamp in public/index.php) and disabled for
        // existing applications that are upgrading. This means existing
        // apps see no behaviour change, while new apps are secure by
        // default.
        //
        // Set to true / false to lock in an explicit choice. The
        // HTTP_SSRF_GUARD env var takes precedence over everything.
        'enabled' => env('HTTP_SSRF_GUARD', defined('LARAVEL_START')
            ? LARAVEL_START >= strtotime('2026-08-01')
            : false),

        // Block RFC1918 / link-local / loopback / reserved IP ranges.
        'block_private_ranges' => true,

        // URL schemes that are permitted by default. The SSRF guard will
        // block any request whose scheme is not in this list. Restricted to
        // HTTPS by default to keep credentials / payloads off the wire in
        // cleartext. Use `['http', 'https']` to allow plaintext for local
        // development, or any other list of schemes you trust.
        'allowed_schemes' => ['https'],

        // Extra hostnames considered "internal" and blocked in addition to
        // the IP-based check.
        'blocked_hostnames' => [
            'localhost',
            'broadcasthost',
            'ip6-localhost',
            'ip6-loopback',
        ],

        // Wildcard patterns matched against the host (Str::is-style).
        'blocked_hostname_patterns' => [
            '*.local',
            '*.localdomain',
            '*.internal',
            '*.intranet',
            '*.lan',
            '*.home',
        ],

        // Ports that are always blocked when paired with an HTTP/HTTPS scheme.
        'blocked_ports' => [
            22,    // SSH
            23,    // Telnet
            25,    // SMTP
            465,   // SMTP
            587,   // SMTP
            3306,  // MySQL
            5432,  // PostgreSQL
            6379,  // Redis
            9200,  // Elasticsearch
            11211, // memcached
            27017, // MongoDB
        ],

        // Hostnames / IPs that are explicitly allowed (bypass all other
        // checks). Use this for explicitly-trusted internal services.
        'allowed_hosts' => [],

        // Allowed ports (overrides any block above). Defaults to 443 — the
        // default port for HTTPS, which is the only scheme allowed by
        // default. Add 80 if you also allow the `http` scheme.
        'allowed_ports' => [443],
    ],

];
