<?php

namespace Illuminate\Http\Client;

use RuntimeException;

class SsrfBlockedException extends RuntimeException
{
    public function __construct(string $url, string $reason)
    {
        parent::__construct(
            "Request to [{$url}] was blocked by Laravel's SSRF guard ({$reason}). "
            .'To allow this request, add the URL to the `allowed_hosts` or `allowed_schemes` '
            .'list in `config/http.php`, or use `Http::unsafeRequest()` for an explicit opt-out.'
        );
    }
}
