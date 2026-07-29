<?php

namespace Illuminate\Tests\Http;

use Illuminate\Http\Client\Factory;
use Illuminate\Http\Client\SsrfBlockedException;
use Illuminate\Http\Client\SsrfGuard;
use PHPUnit\Framework\TestCase;

class HttpClientSsrfGuardTest extends TestCase
{
    /**
     * @var \Illuminate\Http\Client\Factory
     */
    protected $factory;

    protected function setUp(): void
    {
        parent::setUp();

        $this->factory = new Factory;

        // A reasonable "real config" that mirrors config/http.php defaults:
        // HTTPS only, block private ranges and sensitive ports.
        $this->factory->ssrfGuard(new SsrfGuard([
            'enabled' => true,
            'allowed_schemes' => ['https'],
            'allowed_ports' => [443],
            'blocked_ports' => [
                3306, 5432, 6379, 9200, 11211, 27017,
            ],
            'blocked_hostnames' => [
                'localhost',
                'broadcasthost',
                'ip6-localhost',
                'ip6-loopback',
            ],
            'blocked_hostname_patterns' => [
                '*.local',
                '*.localdomain',
                '*.internal',
                '*.intranet',
                '*.lan',
                '*.home',
            ],
            'allowed_hosts' => [],
            'block_private_ranges' => true,
        ]));
    }

    protected function tearDown(): void
    {
        \Illuminate\Http\Client\Response::flushState();
    }

    public function testIsSafeUrlAcceptsPublicHttps()
    {
        $this->assertTrue($this->factory->isSafeUrl('https://laravel.com'));
        $this->assertTrue($this->factory->isSafeUrl('https://example.com/foo?bar=1'));
        $this->assertTrue($this->factory->isSafeUrl('https://1.1.1.1'));
    }

    public function testIsSafeUrlRejectsPlaintextHttpByDefault()
    {
        $this->assertFalse($this->factory->isSafeUrl('http://laravel.com'));
        $this->assertFalse($this->factory->isSafeUrl('http://example.com'));
    }

    public function testIsSafeUrlRejectsPrivateIpv4Addresses()
    {
        $this->assertFalse($this->factory->isSafeUrl('https://127.0.0.1'));
        $this->assertFalse($this->factory->isSafeUrl('https://10.0.0.1'));
        $this->assertFalse($this->factory->isSafeUrl('https://192.168.1.1'));
        $this->assertFalse($this->factory->isSafeUrl('https://169.254.169.254'));
    }

    public function testIsSafeUrlRejectsLoopbackAndLocalhost()
    {
        $this->assertFalse($this->factory->isSafeUrl('https://localhost'));
        $this->assertFalse($this->factory->isSafeUrl('https://LocalHost'));
        $this->assertFalse($this->factory->isSafeUrl('https://broadcasthost'));
        $this->assertFalse($this->factory->isSafeUrl('https://service.local'));
        $this->assertFalse($this->factory->isSafeUrl('https://api.internal'));
        $this->assertFalse($this->factory->isSafeUrl('https://intra.lan'));
        $this->assertFalse($this->factory->isSafeUrl('https://router.home'));
        $this->assertFalse($this->factory->isSafeUrl('https://node.lan'));
    }

    public function testIsSafeUrlRejectsBlockedPorts()
    {
        $this->assertFalse($this->factory->isSafeUrl('https://laravel.com:6379'));
        $this->assertFalse($this->factory->isSafeUrl('https://laravel.com:3306'));
        $this->assertFalse($this->factory->isSafeUrl('https://example.com:9200'));
        $this->assertTrue($this->factory->isSafeUrl('https://laravel.com:443'));
    }

    public function testRealRequestToLoopbackIsBlocked()
    {
        $this->expectException(SsrfBlockedException::class);

        $this->factory->get('https://127.0.0.1');
    }

    public function testRealRequestToPlaintextHttpIsBlocked()
    {
        $this->expectException(SsrfBlockedException::class);
        $this->expectExceptionMessageMatches('/scheme \[http\]/');

        $this->factory->get('http://example.com');
    }

    public function testUnsafeRequestBypassesGuard()
    {
        // UnsafeRequest() should disable the guard for this call only and
        // not throw SsrfBlockedException. We use a wildcard fake so the
        // request is short-circuited before cURL is touched.
        $this->factory->fake([
            '*' => Factory::response('ok', 200),
        ]);

        $response = $this->factory->unsafeRequest()->get('https://127.0.0.1');

        $this->assertTrue($response->ok());
    }

    public function testAllowSchemeAddsExtraSchemeForOneRequest()
    {
        // The factory's global config restricts to https, but the per-call
        // allowScheme() should permit http just for this call.
        $this->factory->fake([
            'http://example.com/*' => Factory::response('ok', 200),
        ]);

        $response = $this->factory->allowScheme('http')->get('http://example.com');

        $this->assertTrue($response->ok());
    }

    public function testAllowSchemeDoesNotWeakenTheFactoryGuard()
    {
        // The factory's ssrfGuard is shared between requests. Per-request
        // calls to allowScheme() should clone the guard, so the factory's
        // shared instance is never mutated.
        $factoryGuard = new SsrfGuard([
            'enabled' => true,
            'allowed_schemes' => ['https'],
        ]);

        $this->factory->ssrfGuard($factoryGuard);

        // Before any request: factory's guard does not allow http.
        $this->assertFalse($this->factory->isSafeUrl('http://example.com'));

        // After a request that opts in to http: factory's guard is unchanged.
        $this->factory->allowScheme('http');
        $this->assertFalse($this->factory->isSafeUrl('http://example.com'));

        // The per-request guard does allow http, but the factory-level
        // isSafeUrl() reflects the (unchanged) factory guard.
        $request = $this->factory->allowScheme('http');
        $this->assertTrue($request->isSafeUrl('http://example.com'));
        $this->assertFalse($this->factory->isSafeUrl('http://example.com'));
    }

    public function testFakedRequestsBypassGuard()
    {
        // Developers routinely stub internal addresses with Http::fake().
        // Fakes must not be blocked by the SSRF guard.
        $this->factory->fake([
            'https://internal.example/*' => Factory::response('stubbed', 200),
        ]);

        $response = $this->factory->get('https://internal.example/anything');

        $this->assertTrue($response->ok());
        $this->assertSame('stubbed', $response->body());
    }

    public function testFakesToInternalAddressesAreNotBlocked()
    {
        // A fake on a private IP / localhost should still be returned
        // without hitting the guard.
        $this->factory->fake([
            'https://localhost/*' => Factory::response('hello', 200),
        ]);

        $response = $this->factory->get('https://localhost/health');

        $this->assertTrue($response->ok());
        $this->assertSame('hello', $response->body());
    }

    public function testFactoryIsSafeUrlReturnsTrueWhenNoGuardConfigured()
    {
        $factory = new Factory;

        $this->assertTrue($factory->isSafeUrl('http://127.0.0.1'));
        $this->assertTrue($factory->isSafeUrl('https://localhost'));
    }

    public function testGuardHonoursAllowedHostsList()
    {
        $this->factory->ssrfGuard(new SsrfGuard([
            'enabled' => true,
            'allowed_schemes' => ['https'],
            'allowed_hosts' => ['1.1.1.1', '8.8.8.8'],
            'allowed_ports' => [443, 8080],
            'blocked_ports' => [],
            'blocked_hostnames' => [],
            'blocked_hostname_patterns' => [],
        ]));

        // Public IPs on the allowed list pass even though we don't resolve
        // DNS for them (they're literals).
        $this->assertTrue($this->factory->isSafeUrl('https://1.1.1.1'));
        $this->assertTrue($this->factory->isSafeUrl('https://1.1.1.1:8080/api'));

        // A literal RFC1918 IP that's not on the allowed list is blocked.
        $this->assertFalse($this->factory->isSafeUrl('https://192.168.1.1'));
    }

    public function testAssertSafeThrowsDescriptiveMessage()
    {
        try {
            (new SsrfGuard(['enabled' => true, 'allowed_schemes' => ['https']]))
                ->assertSafe('http://example.com');
            $this->fail('Expected SsrfBlockedException was not thrown.');
        } catch (SsrfBlockedException $e) {
            $this->assertStringContainsString('http://example.com', $e->getMessage());
            $this->assertStringContainsString('unsafeRequest', $e->getMessage());
        }
    }
}
