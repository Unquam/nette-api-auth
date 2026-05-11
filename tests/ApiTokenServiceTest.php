<?php

declare(strict_types=1);

namespace Unquam\NetteApiAuth\Tests;

use Tester\Assert;
use Tester\TestCase;
use Mockery;
use Nette\Database\Explorer;
use Nette\Database\Table\ActiveRow;
use Nette\Database\Table\Selection;
use Unquam\NetteApiAuth\ApiTokenService;
use Unquam\NetteApiAuth\ScopeService;

require __DIR__ . '/../vendor/autoload.php';

\Tester\Environment::setup();

class ApiTokenServiceTest extends TestCase
{
    private ApiTokenService $service;
    private ScopeService $scopeService;
    private Explorer $database;

    protected function setUp(): void
    {
        $this->scopeService = new ScopeService(['read', 'write', 'admin']);
        $this->database     = Mockery::mock(Explorer::class);

        $this->service = new ApiTokenService(
            $this->database,
            $this->scopeService,
            'api_tokens',
            'users',
            'sk_test_',
            'sk_live_',
            'test-secret-key'
        );
    }

    protected function tearDown(): void
    {
        Mockery::close();
    }

    // test that generated token has correct test prefix
    public function testGenerateTestToken(): void
    {
        $selection = Mockery::mock(Selection::class);
        $selection->shouldReceive('insert')->once()->andReturn(true);

        $this->database->shouldReceive('table')
            ->with('api_tokens')
            ->andReturn($selection);

        $token = $this->service->generate(1, 'test-app', false);

        Assert::true(strpos($token, 'sk_test_') === 0);
    }

    // test that generated token has correct live prefix
    public function testGenerateLiveToken(): void
    {
        $selection = Mockery::mock(Selection::class);
        $selection->shouldReceive('insert')->once()->andReturn(true);

        $this->database->shouldReceive('table')
            ->with('api_tokens')
            ->andReturn($selection);

        $token = $this->service->generate(1, 'live-app', true);

        Assert::true(strpos($token, 'sk_live_') === 0);
    }

    // test that generated token with invalid scope throws exception
    public function testGenerateTokenWithInvalidScope(): void
    {
        Assert::exception(function () {
            $this->service->generate(1, 'test-app', false, ['invalid-scope']);
        }, \InvalidArgumentException::class);
    }

    // test that generated token with valid scopes passes
    public function testGenerateTokenWithValidScopes(): void
    {
        $selection = Mockery::mock(Selection::class);
        $selection->shouldReceive('insert')->once()->andReturn(true);

        $this->database->shouldReceive('table')
            ->with('api_tokens')
            ->andReturn($selection);

        $token = $this->service->generate(1, 'test-app', false, ['read', 'write']);

        Assert::true(strpos($token, 'sk_test_') === 0);
    }

    // test that token is hashed with HMAC before storing
    public function testTokenIsHashedWithHmac(): void
    {
        $storedHash = null;

        $selection = Mockery::mock(Selection::class);
        $selection->shouldReceive('insert')
            ->once()
            ->andReturnUsing(function (array $data) use (&$storedHash) {
                $storedHash = $data['token'];
                return true;
            });

        $this->database->shouldReceive('table')
            ->with('api_tokens')
            ->andReturn($selection);

        $raw = $this->service->generate(1, 'test-app', false);

        // stored hash must be HMAC of raw token
        Assert::equal(hash_hmac('sha256', $raw, 'test-secret-key'), $storedHash);

        // raw token must not equal stored hash
        Assert::notEqual($raw, $storedHash);
    }

    // test that validate returns null for invalid token
    public function testValidateInvalidToken(): void
    {
        $selection = Mockery::mock(Selection::class);
        $selection->shouldReceive('where')->andReturnSelf();
        $selection->shouldReceive('fetch')->andReturn(null);

        $this->database->shouldReceive('table')
            ->with('api_tokens')
            ->andReturn($selection);

        $result = $this->service->validate('invalid-token');

        Assert::null($result);
    }

    // test that revoke deletes token from database
    public function testRevokeToken(): void
    {
        $selection = Mockery::mock(Selection::class);
        $selection->shouldReceive('where')->andReturnSelf();
        $selection->shouldReceive('delete')->once()->andReturn(1);

        $this->database->shouldReceive('table')
            ->with('api_tokens')
            ->andReturn($selection);

        $this->service->revoke('sk_test_sometoken');

        // if we get here without exception, revoke worked
        Assert::true(true);
    }

    // test that revokeAll deletes all tokens for user
    public function testRevokeAllTokens(): void
    {
        $selection = Mockery::mock(Selection::class);
        $selection->shouldReceive('where')->andReturnSelf();
        $selection->shouldReceive('delete')->once()->andReturn(3);

        $this->database->shouldReceive('table')
            ->with('api_tokens')
            ->andReturn($selection);

        $this->service->revokeAll(1);

        Assert::true(true);
    }

    // test that validate returns user data for a valid token
    public function testValidateValidToken(): void
    {
        $tokenRow = Mockery::mock(ActiveRow::class);
        $tokenRow->shouldReceive('update')->once()->andReturn(1);
        $tokenRow->id         = 42;
        $tokenRow->user_id    = 7;
        $tokenRow->is_live    = 0;
        $tokenRow->scopes     = 'read,write';
        $tokenRow->expires_at = null;

        $userRow = Mockery::mock(ActiveRow::class);
        $userRow->id    = 7;
        $userRow->email = 'user@example.com';
        $userRow->role  = 'user';

        $tokenSelection = Mockery::mock(Selection::class);
        $tokenSelection->shouldReceive('where')->andReturnSelf();
        $tokenSelection->shouldReceive('fetch')->andReturn($tokenRow);

        $userSelection = Mockery::mock(Selection::class);
        $userSelection->shouldReceive('where')->andReturnSelf();
        $userSelection->shouldReceive('fetch')->andReturn($userRow);

        $this->database->shouldReceive('table')
            ->with('api_tokens')->andReturn($tokenSelection);
        $this->database->shouldReceive('table')
            ->with('users')->andReturn($userSelection);

        $result = $this->service->validate('sk_test_somevalidtoken');

        Assert::notNull($result);
        Assert::equal(7, $result['user_id']);
        Assert::equal('user@example.com', $result['email']);
        Assert::equal('user', $result['role']);
        Assert::equal(42, $result['token_id']);
        Assert::false($result['is_live']);
        Assert::equal(['read', 'write'], $result['scopes']);
    }

    // test that validate returns null when user row is missing
    public function testValidateReturnsNullForMissingUser(): void
    {
        $tokenRow = Mockery::mock(ActiveRow::class);
        $tokenRow->shouldReceive('update')->once()->andReturn(1);
        $tokenRow->id         = 42;
        $tokenRow->user_id    = 99;
        $tokenRow->is_live    = 0;
        $tokenRow->scopes     = null;
        $tokenRow->expires_at = null;

        $tokenSelection = Mockery::mock(Selection::class);
        $tokenSelection->shouldReceive('where')->andReturnSelf();
        $tokenSelection->shouldReceive('fetch')->andReturn($tokenRow);

        $userSelection = Mockery::mock(Selection::class);
        $userSelection->shouldReceive('where')->andReturnSelf();
        $userSelection->shouldReceive('fetch')->andReturn(null);

        $this->database->shouldReceive('table')
            ->with('api_tokens')->andReturn($tokenSelection);
        $this->database->shouldReceive('table')
            ->with('users')->andReturn($userSelection);

        Assert::null($this->service->validate('sk_test_sometoken'));
    }

    // test that revokeById only deletes when userId matches
    public function testRevokeByIdChecksOwner(): void
    {
        $selection = Mockery::mock(Selection::class);
        $selection->shouldReceive('where')->twice()->andReturnSelf();
        $selection->shouldReceive('delete')->once()->andReturn(1);

        $this->database->shouldReceive('table')
            ->with('api_tokens')
            ->andReturn($selection);

        $this->service->revokeById(5, 1);

        Assert::true(true);
    }

    // test that listForUser returns mapped arrays without token hashes
    public function testListForUserDoesNotExposeTokenHash(): void
    {
        $row              = Mockery::mock(ActiveRow::class);
        $row->id          = 1;
        $row->name        = 'My Token';
        $row->is_live     = 0;
        $row->scopes      = 'read';
        $row->last_used   = null;
        $row->expires_at  = null;
        $row->created_at  = '2024-01-01 00:00:00';

        $selection = Mockery::mock(Selection::class);
        $selection->shouldReceive('where')->andReturnSelf();
        $selection->shouldReceive('order')->andReturnSelf();
        $selection->shouldReceive('fetchAll')->andReturn([$row]);

        $this->database->shouldReceive('table')
            ->with('api_tokens')
            ->andReturn($selection);

        $list = $this->service->listForUser(1);

        Assert::count(1, $list);
        Assert::false(isset($list[0]['token']));
        Assert::equal(1, $list[0]['id']);
        Assert::equal('My Token', $list[0]['name']);
    }

    // test that findByRaw returns token metadata without exposing hash
    public function testFindByRawReturnsMetadata(): void
    {
        $row             = Mockery::mock(ActiveRow::class);
        $row->id         = 3;
        $row->name       = 'Found Token';
        $row->is_live    = 1;
        $row->scopes     = null;
        $row->expires_at = null;
        $row->created_at = '2024-01-01 00:00:00';

        $selection = Mockery::mock(Selection::class);
        $selection->shouldReceive('where')->andReturnSelf();
        $selection->shouldReceive('fetch')->andReturn($row);

        $this->database->shouldReceive('table')
            ->with('api_tokens')
            ->andReturn($selection);

        $result = $this->service->findByRaw('sk_live_sometoken');

        Assert::notNull($result);
        Assert::equal(3, $result['id']);
        Assert::true($result['is_live']);
        Assert::false(isset($result['token']));
    }

    // test that findByRaw returns null for unknown token
    public function testFindByRawReturnsNullForUnknown(): void
    {
        $selection = Mockery::mock(Selection::class);
        $selection->shouldReceive('where')->andReturnSelf();
        $selection->shouldReceive('fetch')->andReturn(null);

        $this->database->shouldReceive('table')
            ->with('api_tokens')
            ->andReturn($selection);

        Assert::null($this->service->findByRaw('sk_test_unknown'));
    }
}

(new ApiTokenServiceTest)->run();