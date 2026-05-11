# Nette API Auth

Nette API Auth is a straightforward API token authentication package for the Nette Framework. It was built because the Nette ecosystem lacked a solid, ready-to-use solution for token-based API authentication. Forking and adapting it to your own needs is very much welcome.

## Requirements

PHP 7.4 or higher, Nette Framework 3.0, 3.1 or 3.2, and Nette Database 3.0, 3.1 or 3.2.

## Installation

```bash
composer require unquam/nette-api-auth
```

## Database Setup

The package uses a separate `api_users` table to keep API authentication completely independent from your web authentication. Run the migration files in order — `api_users` must be created first because the other tables reference it.

```bash
mysql -u root -p your_database < vendor/unquam/nette-api-auth/migrations/api_users.sql
mysql -u root -p your_database < vendor/unquam/nette-api-auth/migrations/api_tokens.sql
mysql -u root -p your_database < vendor/unquam/nette-api-auth/migrations/refresh_tokens.sql
mysql -u root -p your_database < vendor/unquam/nette-api-auth/migrations/rate_limits.sql
```

The `api_tokens` table stores hashed access tokens. The `refresh_tokens` table stores hashed refresh tokens. The `rate_limits` table tracks per-token request counts and is managed automatically — you never write to it yourself.

## Configuration

First generate a secure secret key and keep it somewhere safe. This key is used to hash all tokens and must never change — if you change it, all existing tokens will become invalid.

```bash
openssl rand -hex 32
```

Then register the extension in your `config/common.neon` and paste the generated key as the `secret` value.

```neon
extensions:
    apiAuth: Unquam\NetteApiAuth\DI\ApiAuthExtension

apiAuth:
    secret: 'paste-your-generated-secret-here'   # required, never change this after tokens are issued

    tokenTable:      api_tokens       # table that stores access tokens
    userTable:       api_users        # table that stores API users
    refreshTable:    refresh_tokens   # table that stores refresh tokens
    rateLimitTable:  rate_limits      # table that stores rate limit counters

    testPrefix:    sk_test_           # prefix for test-mode tokens
    livePrefix:    sk_live_           # prefix for live-mode tokens
    refreshPrefix: rt_                # prefix for refresh tokens

    ttl:        null                  # access token lifetime in minutes, null means unlimited
    refreshTtl: null                  # refresh token lifetime in minutes, null means unlimited

    rateLimitTest:   60               # max requests per window for test tokens
    rateLimitLive:   1000             # max requests per window for live tokens
    rateLimitWindow: 60               # window size in seconds

    scopes: []                        # allowed scopes, empty list means all scopes are accepted

    corsOrigins: []                   # allowed CORS origins, empty list means all origins are accepted
    publicPaths: []                   # paths that skip authentication (middleware only)

    userColumns:                      # column names in your api_users table
        id:    id
        email: email
        role:  role
```

The `secret` key is the only required field. Every other key has a sensible default and can be omitted if you are happy with the default value.

### Token Lifetime Examples

```neon
apiAuth:
    ttl: null    # unlimited
    ttl: 60      # 1 hour
    ttl: 1440    # 1 day
    ttl: 10080   # 1 week
    ttl: 43200   # 30 days
```

### Custom User Table Columns

If your `api_users` table uses different column names, map them with `userColumns`.

```neon
apiAuth:
    userColumns:
        id:    id
        email: email_address
        role:  user_role
```

## How Token Hashing Works

When a token is generated, the package creates a random raw value and stores only its HMAC-SHA256 hash in the database. The raw token is returned to you once and never stored again. On every subsequent request the incoming token is hashed with the same secret and compared against the stored hash, so even if someone reads your database they cannot recover usable tokens.

## Authentication Presenter

The first thing you need is an `AuthPresenter` that handles login and issues tokens. Extend it from `BaseApiPresenter`, mark the `login` action as public so it does not require a token, and inject the database to look up users.

```php
<?php

declare(strict_types=1);

namespace App\Presentation\Api;

use Nette\Database\Explorer;
use Unquam\NetteApiAuth\ApiTokenService;
use Unquam\NetteApiAuth\BaseApiPresenter;
use Unquam\NetteApiAuth\RateLimiterService;
use Unquam\NetteApiAuth\RefreshTokenService;
use Unquam\NetteApiAuth\ScopeService;

class AuthPresenter extends BaseApiPresenter
{
    private Explorer $database;
    private RefreshTokenService $refreshTokenService;

    protected array $publicActions = ['login', 'refresh'];

    public function __construct(
        ApiTokenService $tokenService,
        ScopeService $scopeService,
        RateLimiterService $rateLimiter,
        RefreshTokenService $refreshTokenService,
        Explorer $database
    ) {
        parent::__construct($tokenService, $scopeService, $rateLimiter);
        $this->refreshTokenService = $refreshTokenService;
        $this->database            = $database;
    }

    // POST /api/auth/login
    public function actionLogin(): void
    {
        $this->requireMethod('POST');

        $data = $this->getJsonBody();

        if (empty($data['email']) || empty($data['password'])) {
            $this->sendError(422, 'Email and password are required');
        }

        $user = $this->database->table('api_users')
            ->where('email', $data['email'])
            ->fetch();

        if (!$user || !password_verify($data['password'], $user->password)) {
            $this->sendError(401, 'Invalid credentials');
        }

        $tokenRaw = $this->tokenService->generate(
            $user->id,
            'web-app',
            false // false = test token (sk_test_), true = live token (sk_live_)
        );

        $tokenRow     = $this->tokenService->findByRaw($tokenRaw);
        $refreshToken = $this->refreshTokenService->generate($user->id, $tokenRow['id']);

        $this->sendJson([
            'access_token'  => $tokenRaw,
            'refresh_token' => $refreshToken,
            'token_type'    => 'Bearer',
        ]);
    }

    // POST /api/auth/refresh
    public function actionRefresh(): void
    {
        $this->requireMethod('POST');

        $data            = $this->getJsonBody();
        $newRefreshToken = $this->refreshTokenService->rotate($data['refresh_token']);

        if (!$newRefreshToken) {
            $this->sendError(401, 'Invalid or expired refresh token');
        }

        $this->sendJson([
            'refresh_token' => $newRefreshToken,
            'token_type'    => 'Bearer',
        ]);
    }
    
    // POST /api/auth/logout
    public function actionLogout(): void
    {
        $this->requireMethod('POST');
    
        $user = $this->getCurrentUser();
    
        $this->refreshTokenService->revokeByApiToken($user['token_id']);
        $this->tokenService->revokeById($user['token_id'], $user['user_id']);
    
        $this->sendJson(['success' => true]);
    }

    // GET /api/auth/me
    public function actionMe(): void
    {
        $this->requireMethod('GET');
        $this->sendJson($this->getCurrentUser());
    }
}
```

## Usage with BaseApiPresenter

Extend your API presenters from `BaseApiPresenter` and all authentication, rate limiting, and CORS handling is taken care of automatically on every request. Actions listed in the `$publicActions` property are skipped entirely, meaning no token is required to reach them.

```php
<?php

declare(strict_types=1);

namespace App\Presentation\Api;

use Nette\Database\Explorer;
use Unquam\NetteApiAuth\ApiTokenService;
use Unquam\NetteApiAuth\BaseApiPresenter;
use Unquam\NetteApiAuth\RateLimiterService;
use Unquam\NetteApiAuth\ScopeService;

class ArticlePresenter extends BaseApiPresenter
{
    private Explorer $database;

    protected array $publicActions = ['list', 'show'];

    public function __construct(
        ApiTokenService $tokenService,
        ScopeService $scopeService,
        RateLimiterService $rateLimiter,
        Explorer $database
    ) {
        parent::__construct($tokenService, $scopeService, $rateLimiter);
        $this->database = $database;
    }

    // GET /api/articles
    public function actionList(): void
    {
        $this->requireMethod('GET');
        $this->sendJson(
            $this->database->table('articles')->fetchAll()
        );
    }

    // POST /api/articles
    public function actionStore(): void
    {
        $this->requireMethod('POST');

        $user = $this->getCurrentUser();
        $data = $this->getJsonBody();

        $this->database->table('articles')->insert([
            'title'     => $data['title'],
            'body'      => $data['body'],
            'author_id' => $user['user_id'],
        ]);

        $this->sendJson(['success' => true]);
    }

    // DELETE /api/articles/:id
    public function actionDestroy(int $id): void
    {
        $this->requireMethod('DELETE');
        $this->requireRole('admin');

        $this->database->table('articles')->where('id', $id)->delete();
        $this->sendJson(['success' => true]);
    }
}
```

## Live and Test Mode

Every token is either a live token or a test token, determined by the third argument passed to `generate()`.

```php
// generate a test token — prefix sk_test_
$tokenRaw = $this->tokenService->generate($user->id, 'web-app', false);

// generate a live token — prefix sk_live_
$tokenRaw = $this->tokenService->generate($user->id, 'web-app', true);
```

Inside any action you can check which mode the current request is using and behave accordingly.

```php
if ($this->isLiveMode()) {
    // token starts with sk_live_ — production mode
    $this->sendJson(['status' => 'charged', 'amount' => $data['amount']]);
} else {
    // token starts with sk_test_ — sandbox mode
    $this->sendJson(['status' => 'sandbox', 'amount' => $data['amount']]);
}
```

## Scopes

Scopes let you attach fine-grained permissions to individual tokens. First declare the complete list of scopes your application supports in the configuration.

```neon
apiAuth:
    scopes:
        - read
        - write
        - admin
```

When generating a token, pass the scopes you want to assign as the fourth argument.

```php
$tokenRaw = $this->tokenService->generate($userId, 'mobile-app', false, ['read', 'write']);
```

Inside a protected action you can then enforce scope requirements.

```php
$this->requireScope('write');             // token must have this scope
$this->requireAllScopes('read', 'write'); // token must have all of these scopes
$this->requireAnyScope('write', 'admin'); // token must have at least one of these scopes
```

When a token was generated without any scopes, all scope checks pass automatically.

## Rate Limiting

Rate limiting is applied automatically on every authenticated request. The package tracks how many requests each token has made within the current time window and compares that count against the configured limit. Test tokens and live tokens have separate limits.

When a request succeeds, the number of remaining requests in the current window is returned in the response header.

```
X-RateLimit-Remaining: 42
```

When the limit is exceeded the response is a 429 with a JSON error body.

## Refresh Tokens

When an access token expires the client can use a refresh token to get a new one without asking the user to log in again. Calling `rotate()` atomically revokes the old refresh token and generates a replacement in a single database transaction, preventing reuse even under concurrent requests. See the `AuthPresenter` example above for the full implementation.

## Revoking Tokens

```php
// revoke a specific token using its raw value
$this->tokenService->revoke($raw);

// revoke a specific token by its database id, only the owner can revoke it
$this->tokenService->revokeById($id, $userId);

// revoke every access token belonging to a user
$this->tokenService->revokeAll($userId);

// revoke every refresh token belonging to a user
$this->refreshTokenService->revokeAll($userId);

// revoke all refresh tokens linked to a specific access token
$this->refreshTokenService->revokeByApiToken($apiTokenId);
```

## CORS

By default every origin is allowed. To restrict access to specific origins, set the `corsOrigins` list in the configuration.

```neon
apiAuth:
    corsOrigins:
        - https://app.example.com
        - https://admin.example.com
```

When a request arrives from an origin that is not on the list, the response sets `Access-Control-Allow-Origin: null`, which causes browsers to block the response. A `Vary: Origin` header is always included so that caches and proxies handle origin-dependent responses correctly. Preflight OPTIONS requests are handled automatically and return HTTP 200 with the appropriate CORS headers before any authentication takes place.

## Sending a Request

Pass the token in the `Authorization` header with every request that requires authentication.

```
Authorization: Bearer sk_live_xxxx
```

In Postman, open the Auth tab on your request, select Bearer Token from the type dropdown, and paste the raw token value into the Token field. In Insomnia the same option is available under the Auth tab as Bearer.

## Available Methods in BaseApiPresenter

```php
$this->getCurrentUser()                   // returns the authenticated user data as an array
$this->getCurrentScopes()                 // returns the scopes assigned to the current token
$this->isLiveMode()                       // returns true when the request uses a live token
$this->requireMethod('GET', 'POST')       // terminates with 405 if the HTTP method is not listed
$this->requireRole('admin')              // terminates with 403 if the user role does not match
$this->requireScope('write')             // terminates with 403 if the token lacks the scope
$this->requireAllScopes('read', 'write') // terminates with 403 unless all scopes are present
$this->requireAnyScope('write', 'admin') // terminates with 403 unless at least one scope is present
$this->getJsonBody()                     // decodes the request body as JSON, returns 400 on invalid input
$this->sendError(401, 'Unauthorized')    // sends a JSON error response and terminates
```

`getCurrentUser()` returns an array with the keys `user_id`, `email`, `role`, `is_live`, `token_id`, `expires_at`, and `scopes`.

## Usage with ApiAuthMiddleware

If your project uses `contributte/middlewares` you can use `ApiAuthMiddleware` instead of extending `BaseApiPresenter`. Install the optional dependency first.

```bash
composer require contributte/middlewares
```

The middleware is registered automatically by the DI extension. Configure public paths in your `config/common.neon` — any request whose path exactly matches or begins with one of those entries will pass through without a token.

```neon
apiAuth:
    publicPaths:
        - /api/v1/auth
        - /api/v1/health
```

When authentication succeeds the middleware attaches the user data to the request as an attribute named `user`, which subsequent middleware or handlers can read via `$request->getAttribute('user')`. The `X-RateLimit-Remaining` header is added to every successful response, and rate-limited requests receive a 429 with a JSON error body.

## License

This package is open source. You are free to fork it, modify it and use it in your projects.