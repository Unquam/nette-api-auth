<?php

declare(strict_types=1);

namespace Unquam\NetteApiAuth\DI;

use Nette\DI\CompilerExtension;
use Nette\Schema\Expect;
use Nette\Schema\Schema;
use Unquam\NetteApiAuth\ApiTokenService;
use Unquam\NetteApiAuth\RefreshTokenService;
use Unquam\NetteApiAuth\RateLimiterService;
use Unquam\NetteApiAuth\ScopeService;

class ApiAuthExtension extends CompilerExtension
{
    public function getConfigSchema(): Schema
    {
        return Expect::structure([
            // table name for tokens
            'tokenTable'      => Expect::string('api_tokens'),

            // table name for users
            'userTable'       => Expect::string('api_users'),

            // table name for refresh tokens
            'refreshTable'    => Expect::string('refresh_tokens'),

            // table name for rate limits
            'rateLimitTable'  => Expect::string('rate_limits'),

            // prefix for test tokens
            'testPrefix'      => Expect::string('sk_test_'),

            // prefix for live tokens
            'livePrefix'      => Expect::string('sk_live_'),

            // prefix for refresh tokens
            'refreshPrefix'   => Expect::string('rt_'),

            // secret key for HMAC token hashing
            'secret'          => Expect::string()->required(),

            // NULL = unlimited, integer = token lifetime in minutes
            'ttl'             => Expect::anyOf(Expect::int(), Expect::null())->default(null),

            // NULL = unlimited, integer = refresh token lifetime in minutes
            'refreshTtl'      => Expect::anyOf(Expect::int(), Expect::null())->default(null),

            // max requests per window for test tokens
            'rateLimitTest'   => Expect::int(60),

            // max requests per window for live tokens
            'rateLimitLive'   => Expect::int(1000),

            // rate limit window size in seconds
            'rateLimitWindow' => Expect::int(60),

            // list of available scopes, empty = all scopes allowed
            'scopes'          => Expect::listOf(Expect::string())->default([]),

            // allowed CORS origins, empty = all origins allowed
            'corsOrigins'     => Expect::listOf(Expect::string())->default([]),

            // paths that do not require authentication (middleware only)
            'publicPaths'     => Expect::listOf(Expect::string())->default([]),

            // user table column names with defaults
            'userColumns'     => Expect::structure([
                'id'    => Expect::string('id'),
                'email' => Expect::string('email'),
                'role'  => Expect::string('role'),
            ])->castTo('array'),
        ]);
    }

    public function loadConfiguration(): void
    {
        $builder = $this->getContainerBuilder();
        $config  = $this->getConfig();

        // register scope service in DI container
        $builder->addDefinition($this->prefix('scopeService'))
            ->setFactory(ScopeService::class, [
                'availableScopes' => $config->scopes,
            ]);

        // register api token service in DI container
        $builder->addDefinition($this->prefix('tokenService'))
            ->setFactory(ApiTokenService::class, [
                'tokenTable'  => $config->tokenTable,
                'userTable'   => $config->userTable,
                'testPrefix'  => $config->testPrefix,
                'livePrefix'  => $config->livePrefix,
                'ttl'         => $config->ttl,
                'secret'      => $config->secret,
                'userColumns' => $config->userColumns,
            ]);

        // register refresh token service in DI container
        $builder->addDefinition($this->prefix('refreshTokenService'))
            ->setFactory(RefreshTokenService::class, [
                'refreshTable'  => $config->refreshTable,
                'refreshPrefix' => $config->refreshPrefix,
                'ttl'           => $config->refreshTtl,
                'secret'        => $config->secret,
            ]);

        // register rate limiter service in DI container
        $builder->addDefinition($this->prefix('rateLimiterService'))
            ->setFactory(RateLimiterService::class, [
                'table'   => $config->rateLimitTable,
                'maxTest' => $config->rateLimitTest,
                'maxLive' => $config->rateLimitLive,
                'window'  => $config->rateLimitWindow,
            ]);

        // register middleware only if contributte/middlewares is installed
        if (interface_exists('Contributte\Middlewares\IMiddleware')) {
            $middlewareClass = 'Unquam\NetteApiAuth\Middleware\ApiAuthMiddleware';
            $builder->addDefinition($this->prefix('middleware'))
                ->setFactory($middlewareClass, [
                    'publicPaths' => $config->publicPaths,
                    'corsOrigins' => $config->corsOrigins,
                ]);
        }
    }
}