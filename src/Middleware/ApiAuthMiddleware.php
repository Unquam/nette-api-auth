<?php

declare(strict_types=1);

namespace Unquam\NetteApiAuth\Middleware;

use Contributte\Middlewares\IMiddleware;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Unquam\NetteApiAuth\ApiTokenService;
use Unquam\NetteApiAuth\RateLimiterService;

class ApiAuthMiddleware implements IMiddleware
{
    // token service instance
    private ApiTokenService $tokenService;

    // rate limiter service instance
    private RateLimiterService $rateLimiter;

    // paths that do not require authentication
    private array $publicPaths;

    // allowed CORS origins, empty = all origins allowed
    private array $corsOrigins;

    public function __construct(
        ApiTokenService $tokenService,
        RateLimiterService $rateLimiter,
        array $publicPaths = [],
        array $corsOrigins = []
    ) {
        $this->tokenService = $tokenService;
        $this->rateLimiter  = $rateLimiter;
        $this->publicPaths  = $publicPaths;
        $this->corsOrigins  = $corsOrigins;
    }

    /**
     * @param ServerRequestInterface $request
     * @param ResponseInterface $response
     * @param callable $next
     * @return ResponseInterface
     */
    public function __invoke(
        ServerRequestInterface $request,
        ResponseInterface $response,
        callable $next
    ): ResponseInterface {
        // handle preflight OPTIONS request
        if ($request->getMethod() === 'OPTIONS') {
            return $this->withCorsHeaders($request, $response)->withStatus(200);
        }

        $response = $this->withCorsHeaders($request, $response);

        // skip authentication for public paths
        if ($this->isPublicPath($request->getUri()->getPath())) {
            return $next($request, $response);
        }

        // get token from header
        $header = $request->getHeaderLine('Authorization');

        if (!$header || strpos($header, 'Bearer ') !== 0) {
            $response->getBody()->write(json_encode(['error' => 'Token not provided']));
            return $response
                ->withStatus(401)
                ->withHeader('Content-Type', 'application/json');
        }

        $raw    = substr($header, 7);
        $result = $this->tokenService->validate($raw);

        if (!$result) {
            $response->getBody()->write(json_encode(['error' => 'Invalid or expired token']));
            return $response
                ->withStatus(401)
                ->withHeader('Content-Type', 'application/json');
        }

        // check rate limit
        $key = 'token_' . $result['token_id'];

        if ($this->rateLimiter->isExceeded($key, $result['is_live'])) {
            $response->getBody()->write(json_encode(['error' => 'Too Many Requests']));
            return $response
                ->withStatus(429)
                ->withHeader('Content-Type', 'application/json')
                ->withHeader('X-RateLimit-Remaining', '0');
        }

        $remaining = $this->rateLimiter->remaining($key, $result['is_live']);

        // pass user data to next middleware via request attribute
        $request = $request->withAttribute('user', $result);

        return $next($request, $response)
            ->withHeader('X-RateLimit-Remaining', (string) $remaining);
    }

    /**
     * @param string $path
     * @return bool
     */
    private function isPublicPath(string $path): bool
    {
        foreach ($this->publicPaths as $publicPath) {
            $publicPath = rtrim($publicPath, '/');

            if ($path === $publicPath || strpos($path, $publicPath . '/') === 0) {
                return true;
            }
        }

        return false;
    }

    /**
     * @param ServerRequestInterface $request
     * @param ResponseInterface $response
     * @return ResponseInterface
     */
    private function withCorsHeaders(
        ServerRequestInterface $request,
        ResponseInterface $response
    ): ResponseInterface {
        $originHeader = $request->getHeaderLine('Origin');

        if ($originHeader === '') {
            // no Origin header — not a browser CORS request, allow wildcard
            $origin = '*';
        } elseif (!empty($this->corsOrigins)) {
            $origin = in_array($originHeader, $this->corsOrigins, true) ? $originHeader : 'null';
        } else {
            $origin = $originHeader;
        }

        return $response
            ->withHeader('Access-Control-Allow-Origin', $origin)
            ->withHeader('Vary', 'Origin')
            ->withHeader('Access-Control-Allow-Methods', 'GET, POST, PUT, PATCH, DELETE, OPTIONS')
            ->withHeader('Access-Control-Allow-Headers', 'Authorization, Content-Type');
    }
}