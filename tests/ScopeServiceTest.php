<?php

declare(strict_types=1);

namespace Unquam\NetteApiAuth\Tests;

use Tester\Assert;
use Tester\TestCase;
use Unquam\NetteApiAuth\ScopeService;

require __DIR__ . '/../vendor/autoload.php';

\Tester\Environment::setup();

class ScopeServiceTest extends TestCase
{
    private ScopeService $service;

    protected function setUp(): void
    {
        $this->service = new ScopeService(['read', 'write', 'admin']);
    }

    // test that empty scopes means all scopes allowed
    public function testEmptyScopesAllowsAll(): void
    {
        Assert::true($this->service->has([], 'read'));
        Assert::true($this->service->has([], 'write'));
        Assert::true($this->service->has([], 'admin'));
    }

    // test that has() returns true for existing scope
    public function testHasScope(): void
    {
        Assert::true($this->service->has(['read', 'write'], 'read'));
        Assert::false($this->service->has(['read', 'write'], 'admin'));
    }

    // test that hasAll() returns true only if all scopes present
    public function testHasAllScopes(): void
    {
        Assert::true($this->service->hasAll(['read', 'write'], ['read', 'write']));
        Assert::false($this->service->hasAll(['read'], ['read', 'write']));
    }

    // test that hasAny() returns true if at least one scope present
    public function testHasAnyScope(): void
    {
        Assert::true($this->service->hasAny(['read'], ['read', 'write']));
        Assert::false($this->service->hasAny(['admin'], ['read', 'write']));
    }

    // test that validate() returns false for invalid scopes
    public function testValidateInvalidScope(): void
    {
        Assert::false($this->service->validate(['invalid']));
    }

    // test that validate() returns true for valid scopes
    public function testValidateValidScopes(): void
    {
        Assert::true($this->service->validate(['read', 'write']));
    }

    // test parse scopes from comma separated string
    public function testParseScopes(): void
    {
        $scopes = $this->service->parse('read,write,admin');
        Assert::equal(['read', 'write', 'admin'], array_values($scopes));
    }

    // test parse null returns empty array
    public function testParseNullScopes(): void
    {
        $scopes = $this->service->parse(null);
        Assert::equal([], $scopes);
    }

    // test toString converts array to comma separated string
    public function testToString(): void
    {
        $string = $this->service->toString(['read', 'write']);
        Assert::equal('read,write', $string);
    }

    // test getInvalid returns invalid scopes
    public function testGetInvalidScopes(): void
    {
        $invalid = $this->service->getInvalid(['read', 'invalid', 'unknown']);
        Assert::equal(['invalid', 'unknown'], array_values($invalid));
    }

    // test getAvailable returns all available scopes
    public function testGetAvailableScopes(): void
    {
        Assert::equal(['read', 'write', 'admin'], $this->service->getAvailable());
    }

    // test that validate() returns true for any scope when availableScopes is empty
    public function testValidateWithEmptyAvailableScopesAllowsAll(): void
    {
        $anyScope = new ScopeService([]);

        Assert::true($anyScope->validate(['read']));
        Assert::true($anyScope->validate(['write', 'admin', 'completely-unknown-scope']));
        Assert::equal([], $anyScope->getInvalid(['whatever']));
    }

    // test parse with double commas produces no empty entries
    public function testParseIgnoresEmptySegments(): void
    {
        $scopes = $this->service->parse('read,,write');
        Assert::equal(['read', 'write'], $scopes);
    }
}

(new ScopeServiceTest)->run();