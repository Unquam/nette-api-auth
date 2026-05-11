<?php

declare(strict_types=1);

namespace Unquam\NetteApiAuth;

use Nette\Application\UI\Presenter;

abstract class BaseApiPresenter extends Presenter
{
    // current authenticated user data
    protected ?array $currentUser = null;

    // current token scopes
    protected array $currentScopes = [];

    // whether the request is using a live token
    protected bool $isLive = false;

    // actions that do not require authentication
    protected array $publicActions = [];

    // allowed CORS origins, empty = all origins allowed
    private array $corsOrigins;

    // token service instance
    protected ApiTokenService $tokenService;

    // scope service instance
    protected ScopeService $scopeService;

    // rate limiter service instance
    protected RateLimiterService $rateLimiter;

    public function __construct(
        ApiTokenService $tokenService,
        ScopeService $scopeService,
        RateLimiterService $rateLimiter,
        array $corsOrigins = []
    ) {
        parent::__construct();
        $this->tokenService = $tokenService;
        $this->scopeService = $scopeService;
        $this->rateLimiter  = $rateLimiter;
        $this->corsOrigins  = $corsOrigins;
    }

    public function startup(): void
    {
        parent::startup();

        $this->setCorsHeaders();

        if ($this->getHttpRequest()->getMethod() === 'OPTIONS') {
            $this->getHttpResponse()->setCode(200);
            $this->sendJson([]);
        }

        if (!in_array($this->getAction(), $this->publicActions, true)) {
            try {
                $this->authenticate();
                $this->checkRateLimit();
            } catch (Exception\UnauthorizedException $e) {
                $this->sendError($e->getCode(), $e->getMessage());
            } catch (Exception\ForbiddenException $e) {
                $this->sendError($e->getCode(), $e->getMessage());
            }
        }
    }

    // authenticate request by token
    private function authenticate(): void
    {
        $header = $this->getHttpRequest()->getHeader('Authorization');

        if (!$header || strpos($header, 'Bearer ') !== 0) {
            throw new Exception\UnauthorizedException('Token not provided');
        }

        $raw    = substr($header, 7);
        $result = $this->tokenService->validate($raw);

        if (!$result) {
            throw new Exception\UnauthorizedException('Invalid or expired token');
        }

        $this->currentUser   = $result;
        $this->currentScopes = $result['scopes'];
        $this->isLive        = $result['is_live'];
    }

    // check rate limit for current token
    private function checkRateLimit(): void
    {
        if (!$this->currentUser) {
            return;
        }

        $key = 'token_' . $this->currentUser['token_id'];

        if ($this->rateLimiter->isExceeded($key, $this->isLive)) {
            $this->getHttpResponse()->setHeader('X-RateLimit-Remaining', '0');
            $this->sendError(429, 'Too Many Requests');
        }

        $this->getHttpResponse()->setHeader(
            'X-RateLimit-Remaining',
            (string) $this->rateLimiter->remaining($key, $this->isLive)
        );
    }

    // set CORS headers for cross-origin requests
    private function setCorsHeaders(): void
    {
        $originHeader = $this->getHttpRequest()->getHeader('Origin');

        if ($originHeader === null) {
            // no Origin header — not a browser CORS request, allow wildcard
            $origin = '*';
        } elseif (!empty($this->corsOrigins)) {
            $origin = in_array($originHeader, $this->corsOrigins, true) ? $originHeader : 'null';
        } else {
            $origin = $originHeader;
        }

        $this->getHttpResponse()->setHeader('Access-Control-Allow-Origin', $origin);
        $this->getHttpResponse()->setHeader('Vary', 'Origin');
        $this->getHttpResponse()->setHeader(
            'Access-Control-Allow-Methods', 'GET, POST, PUT, PATCH, DELETE, OPTIONS'
        );
        $this->getHttpResponse()->setHeader(
            'Access-Control-Allow-Headers', 'Authorization, Content-Type'
        );
    }

    // returns true if request is using a live token
    protected function isLiveMode(): bool
    {
        return $this->isLive;
    }

    // returns current authenticated user data
    protected function getCurrentUser(): array
    {
        return $this->currentUser ?? [];
    }

    // returns current token scopes
    protected function getCurrentScopes(): array
    {
        return $this->currentScopes;
    }

    // allow only specified HTTP methods
    protected function requireMethod(string ...$methods): void
    {
        if (!in_array($this->getHttpRequest()->getMethod(), $methods, true)) {
            $this->sendError(405, 'Method Not Allowed');
        }
    }

    // allow only specified role
    protected function requireRole(string $role): void
    {
        if (($this->currentUser['role'] ?? '') !== $role) {
            $this->sendError(403, 'Forbidden');
        }
    }

    // check if token has a specific scope
    protected function requireScope(string $scope): void
    {
        if (!$this->scopeService->has($this->currentScopes, $scope)) {
            $this->sendError(403, 'Insufficient scope: ' . $scope);
        }
    }

    // check if token has all specified scopes
    protected function requireAllScopes(string ...$scopes): void
    {
        if (!$this->scopeService->hasAll($this->currentScopes, $scopes)) {
            $this->sendError(403, 'Insufficient scopes: ' . implode(', ', $scopes));
        }
    }

    // check if token has at least one of specified scopes
    protected function requireAnyScope(string ...$scopes): void
    {
        if (!$this->scopeService->hasAny($this->currentScopes, $scopes)) {
            $this->sendError(403, 'Insufficient scopes: ' . implode(', ', $scopes));
        }
    }

    // returns decoded JSON request body
    protected function getJsonBody(): array
    {
        $raw  = $this->getHttpRequest()->getRawBody();
        $data = $raw !== null ? json_decode($raw, true) : null;

        if ($raw !== null && $raw !== '' && json_last_error() !== JSON_ERROR_NONE) {
            $this->sendError(400, 'Invalid JSON: ' . json_last_error_msg());
        }

        return $data ?? [];
    }

    /**
     * Send a JSON error response and terminate execution.
     * sendJson() always throws Nette\Application\AbortException — this method never returns.
     * @return never
     */
    protected function sendError(int $code, string $message): void
    {
        $this->getHttpResponse()->setCode($code);
        $this->sendJson(['error' => $message]);
    }
}