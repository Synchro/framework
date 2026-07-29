<?php

namespace Illuminate\Http\Client;

use Illuminate\Support\Str;
use Illuminate\Support\Uri;
use Symfony\Component\HttpFoundation\IpUtils;

class SsrfGuard
{
    /**
     * Whether to block private/reserved IP ranges.
     */
    protected bool $blockPrivateRanges = true;

    /**
     * URL schemes that are permitted.
     *
     * @var array<int, string>
     */
    protected array $allowedSchemes = ['https'];

    /**
     * Extra hostnames that should always be considered unsafe (in addition
     * to IP-based checks).
     *
     * @var array<int, string>
     */
    protected array $blockedHostnames = [
        'localhost',
        'broadcasthost',
        'ip6-localhost',
        'ip6-loopback',
    ];

    /**
     * Wildcard patterns (Str::is-style) matched against the host.
     *
     * @var array<int, string>
     */
    protected array $blockedHostnamePatterns = [
        '*.local',
        '*.localdomain',
        '*.internal',
        '*.intranet',
        '*.lan',
        '*.home',
    ];

    /**
     * Ports that are always considered unsafe.
     *
     * @var array<int, int>
     */
    protected array $blockedPorts = [
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
    ];

    /**
     * Hosts that are explicitly allowed (bypass all other checks).
     *
     * @var array<int, string>
     */
    protected array $allowedHosts = [];

    /**
     * Ports that are explicitly allowed (overrides any block).
     *
     * @var array<int, int>
     */
    protected array $allowedPorts = [443];

    /**
     * Additional schemes allowed for this guard instance (merged with
     * {@see $allowedSchemes}). Used by PendingRequest::allowScheme().
     *
     * @var array<int, string>
     */
    protected array $extraSchemes = [];

    /**
     * Per-host resolution cache. Matches the strategy used by
     * Symfony\Component\HttpClient\NoPrivateNetworkHttpClient to avoid
     * re-resolving the same hostname for every request.
     *
     * @var array<string, string|null>
     */
    protected array $dnsCache = [];

    /**
     * Create a new SSRF guard.
     *
     * @param  array{
     *     block_private_ranges?: bool,
     *     allowed_schemes?: array<int, string>,
     *     blocked_hostnames?: array<int, string>,
     *     blocked_hostname_patterns?: array<int, string>,
     *     blocked_ports?: array<int, int>,
     *     allowed_hosts?: array<int, string>,
     *     allowed_ports?: array<int, int>,
     * }  $config
     */
    public function __construct(array $config = [])
    {
        foreach ($config as $key => $value) {
            $this->{$key} = $value;
        }
    }

    /**
     * Determine whether the given URL is safe to send a request to.
     */
    public function isSafe(string $url): bool
    {
        try {
            $this->checkUrl($url);

            return true;
        } catch (SsrfBlockedException $e) {
            return false;
        }
    }

    /**
     * Assert that the given URL is safe, throwing SsrfBlockedException if not.
     *
     * Expects a plain string URL — the HTTP client types all of its URL
     * parameters as `string`, so this is the only input shape the guard
     * receives in practice. If a future API change relaxes that to
     * `Stringable|string`, this method should be widened to accept a
     * `Stringable` and cast to string before calling checkUrl().
     *
     * @throws \Illuminate\Http\Client\SsrfBlockedException
     */
    public function assertSafe(string $url): void
    {
        $this->checkUrl($url);
    }

    /**
     * Determine whether the given URL scheme is permitted.
     *
     * @param  string  $scheme
     * @return bool
     */
    public function isSchemeSafe($scheme)
    {
        $scheme = strtolower($scheme);

        $allowed = array_map('strtolower', array_merge($this->allowedSchemes, $this->extraSchemes));

        return in_array($scheme, $allowed, true);
    }

    /**
     * Determine whether the given host is safe to send requests to.
     */
    public function isHostSafe(string $host): bool
    {
        $host = strtolower(trim($host));

        if ($host === '') {
            return false;
        }

        // Explicit allow list short-circuits everything.
        foreach ($this->allowedHosts as $allowed) {
            if (strtolower($allowed) === $host) {
                return true;
            }
        }

        // Blocked hostnames.
        if (in_array($host, array_map('strtolower', $this->blockedHostnames), true)) {
            return false;
        }

        // Wildcard patterns.
        foreach ($this->blockedHostnamePatterns as $pattern) {
            if (Str::is($pattern, $host)) {
                return false;
            }
        }

        // If the host is a literal IP, run the IP check directly.
        if (filter_var($host, FILTER_VALIDATE_IP) !== false) {
            return $this->isIpSafe($host);
        }

        // Otherwise resolve to an IP and check it.
        $address = $this->resolveHost($host);

        if ($address === null) {
            // We could not resolve — treat as unsafe to be conservative.
            return false;
        }

        return $this->isIpSafe($address);
    }

    /**
     * Determine whether the given port is safe.
     */
    public function isPortSafe(?int $port): bool
    {
        if ($port === null) {
            return true;
        }

        if (in_array($port, $this->allowedPorts, true)) {
            return true;
        }

        return ! in_array($port, $this->blockedPorts, true);
    }

    /**
     * Add extra schemes that this guard should permit. Merged with the
     * instance's allowed schemes (additive; does not replace them).
     *
     * @param  array<int, string>  $schemes
     * @return $this
     */
    public function allowSchemes(array $schemes): static
    {
        $this->extraSchemes = array_values(array_unique(array_merge($this->extraSchemes, $schemes)));

        return $this;
    }

    /**
     * Run all SSRF checks against the given URL. Throws on failure.
     *
     * Uses {@see \Illuminate\Support\Uri} (Laravel's wrapper around
     * league/uri) for parsing — it is RFC 3986-compliant, lowercases the
     * scheme and host automatically, validates ports, and is already a
     * hard dependency of the framework.
     *
     * @throws \Illuminate\Http\Client\SsrfBlockedException
     */
    protected function checkUrl(string $url): void
    {
        try {
            $uri = Uri::of($url);
        } catch (\Throwable $e) {
            throw new SsrfBlockedException($url, 'unparseable URL');
        }

        $scheme = $uri->scheme();
        $host = $uri->host();

        // Reject anything that didn't parse into a usable URL.
        if ($scheme === null || $host === null) {
            throw new SsrfBlockedException($url, 'unparseable URL');
        }

        // port() returns null when the URL uses the scheme's default port
        // (e.g. 443 for https) — fall back to the default so we always
        // have an integer for the port check.
        $port = $uri->port() ?? $this->defaultPortForScheme($scheme);

        if (! $this->isSchemeSafe($scheme)) {
            throw new SsrfBlockedException($url, "scheme [{$scheme}] is not in allowed_schemes");
        }

        if (! $this->isHostSafe($host)) {
            throw new SsrfBlockedException($url, "host [{$host}] resolves to a private or internal address");
        }

        if (! $this->isPortSafe($port)) {
            throw new SsrfBlockedException($url, "port [{$port}] is on the blocked_ports list");
        }
    }

    /**
     * Determine whether a literal IP is safe (not private/reserved).
     *
     * Delegates to {@see IpUtils::isPrivateIp()} from symfony/http-foundation
     * — a curated CIDR list (PRIVATE_SUBNETS) more thorough than
     * FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE: it additionally
     * covers 0.0.0.0/8, 240.0.0.0/4, IPv6 link-local (fe80::/10), IPv4
     * mapped IPv6 (::ffff:0:0/96), and the unspecified address (::/128).
     *
     * @param  string  $ip
     */
    protected function isIpSafe($ip): bool
    {
        if (! $this->blockPrivateRanges) {
            return true;
        }

        // Strip IPv6 brackets if present.
        return ! IpUtils::isPrivateIp(trim($ip, '[]'));
    }

    /**
     * Resolve a hostname to a single IP address. Returns null on failure.
     *
     * Matches the resolution strategy used by
     * Symfony\Component\HttpClient\NoPrivateNetworkHttpClient::dnsResolve():
     * try A records first via gethostbynamel(), then AAAA via
     * dns_get_record(). The result is cached per-host for the lifetime of
     * this guard instance.
     */
    protected function resolveHost(string $host): ?string
    {
        if (array_key_exists($host, $this->dnsCache)) {
            return $this->dnsCache[$host];
        }

        $ip = null;

        if ($records = @gethostbynamel($host)) {
            $ip = $records[0];
        } elseif ($records = @dns_get_record($host, DNS_AAAA)) {
            $ip = $records[0]['ipv6'] ?? null;
        } elseif (in_array($host, ['localhost', 'localhost.'], true)) {
            $ip = '::1';
        }

        return $this->dnsCache[$host] = $ip;
    }

    /**
     * Return the default port for a given URL scheme.
     */
    protected function defaultPortForScheme(string $scheme): ?int
    {
        return match ($scheme) {
            'http' => 80,
            'https' => 443,
            default => null,
        };
    }
}
