# Nette API Auth

Nette API Auth is a straightforward API token authentication package for the Nette Framework. It was built because the Nette ecosystem lacked a solid, ready-to-use solution for token-based API authentication. Forking and adapting it to your own needs is very much welcome.

## Requirements

PHP 7.4 or higher, Nette Framework 3.0, 3.1 or 3.2, and Nette Database 3.0, 3.1 or 3.2.

## Installation

```bash
composer require unquam/nette-api-auth
```

## Database Setup

Run all three migration files to create the required tables.

```bash
mysql -u root -p your_database < vendor/unquam/nette-api-auth/migrations/api_tokens.sql
mysql -u root -p your_database < vendor/unquam/nette-api-auth/migrations/refresh_tokens.sql
mysql -u root -p your_database < vendor/unquam/nette-api-auth/migrations/rate_limits.sql
```

The `api_tokens` table stores hashed access tokens. The `refresh_tokens` table stores hashed refresh tokens. The `rate_limits` table tracks per-token request counts and is managed automatically — you never write to it yourself.

## Configuration

First generate a secure secret key.

```bash
openssl rand -hex 32
```

Then register the extension in your `config/common.neon` and paste the generated key as the `secret` value.

```neon
extensions:
    apiAuth: Unquam\NetteApiAuth\DI\ApiAuthExtension

apiAuth:
    secret: 'paste-your-generated-secret-here'
```

```neon
extensions:
    apiAuth: Unquam\NetteApiAuth\DI\ApiAuthExtension

apiAuth:
    secret: your-random-secret-string   # required, used for HMAC token hashing

    tokenTable:      api_tokens         # table that stores access tokens
    userTable:       users              # table that stores your application users
    refreshTable:    refresh_tokens     # table that stores refresh tokens
    rateLimitTable:  rate_limits        # table that stores rate limit counters

    testPrefix:    sk_test_             # prefix for test-mode tokens
    livePrefix:    sk_live_             # prefix for live-mode tokens
    refreshPrefix: rt_                  # prefix for refresh tokens

    ttl:        null                    # access token lifetime in minutes, null means unlimited
    refreshTtl: null                    # refresh token lifetime in minutes, null means unlimited

    rateLimitTest:   60                 # max requests per window for test tokens
    rateLimitLive:   1000               # max requests per window for live tokens
    rateLimitWindow: 60                 # window size in seconds

    scopes: []                          # allowed scopes, empty list means all scopes are accepted

    corsOrigins: []                     # allowed CORS origins, empty list means all origins are accepted
    publicPaths: []                     # paths that skip authentication (middleware only)

    userColumns:                        # column names in your users table
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

### User Table Columns

If your users table uses different column names, map them with `userColumns`. For example, if your role column is called `user_role` and your email column is `email_address`:

```neon
apiAuth:
    userColumns:
        id:    id
        email: email_address
        role:  user_role
```

## How Token Hashing Works

When a token is generated, the package creates a random raw value and stores only its HMAC-SHA256 hash in the database. The raw token is returned to you once and never stored again. On every subsequent request the incoming token is hashed with the same secret and compared against the stored hash, so even if someone reads your database they cannot recover usable tokens.

## Generating Tokens

Inject `ApiTokenService` into your presenter or service and call `generate()` at login time. The third argument controls whether the token operates in live mode (`true`) or test mode (`false`). The optional fourth argument is an array of scopes to assign to the token.

```php
public function actionLogin(): void
{
    $this->requireMethod('POST');

    $data = $this->getJsonBody();
    $user = $this->userService->findByEmail($data['email']);

    if (!$user || !password_verify($data['password'], $user->password)) {
        $this->sendError(401, 'Invalid credentials');
    }

    // generate access token
    $tokenRaw = $this->tokenService->generate(
        $user->id,
        'web-app',
        false,
        ['read', 'write']
    );

    // find token row to get its database id for refresh token
    $tokenRow = $this->tokenService->findByRaw($tokenRaw);

    // generate refresh token linked to access token
    $refreshToken = $this->refreshTokenService->generate(
        $user->id,
        $tokenRow['id']
    );

    $this->sendJson([
        'access_token'  => $tokenRaw,
        'refresh_token' => $refreshToken,
        'token_type'    => 'Bearer',
    ]);
}
```

Save the raw token immediately after receiving it. It is shown exactly once and cannot be recovered from the database.

## Token Format

Tokens are prefixed so you can instantly tell which mode they belong to.
You can customise all three prefixes in the configuration.

## Usage with BaseApiPresenter

Extend your presenters from `BaseApiPresenter` and all authentication, rate limiting, and CORS handling is taken care of automatically on every request. Actions listed in the `$publicActions` property are skipped entirely, meaning no token is required to reach them.

```php
<?php

namespace App\Api\Presenters;

use Unquam\NetteApiAuth\BaseApiPresenter;

class ArticlePresenter extends BaseApiPresenter
{
    protected array $publicActions = ['list', 'show'];

    public function actionList(): void
    {
        $this->requireMethod('GET');
        $this->sendJson($this->articleService->findAll());
    }

    public function actionStore(): void
    {
        $this->requireMethod('POST');

        $user = $this->getCurrentUser();
        $data = $this->getJsonBody();
        $data['author_id'] = $user['user_id'];

        $this->sendJson($this->articleService->create($data));
    }

    public function actionDestroy(int $id): void
    {
        $this->requireMethod('DELETE');
        $this->requireRole('admin');

        $this->articleService->delete($id);
        $this->sendJson(['success' => true]);
    }
}
```

## Live and Test Mode

Every token is either a live token or a test token, determined by the third argument passed to `generate()`. Inside any action you can check which mode the current request is using and behave accordingly.

```php
if ($this->isLiveMode()) {
    $result = $this->paymentGateway->chargeReal($data);
} else {
    $result = $this->paymentGateway->chargeSandbox($data);
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
$token = $this->tokenService->generate($userId, 'mobile-app', false, ['read', 'write']);
```

Inside a protected action you can then enforce scope requirements. `requireScope` demands that the token carries a specific scope. `requireAllScopes` demands that all listed scopes are present. `requireAnyScope` passes if the token carries at least one of the listed scopes.

```php
$this->requireScope('write');
$this->requireAllScopes('read', 'write');
$this->requireAnyScope('write', 'admin');
```

When a token was generated without any scopes, all scope checks pass automatically.

## Rate Limiting

Rate limiting is applied automatically on every authenticated request. The package tracks how many requests each token has made within the current time window and compares that count against the configured limit. Test tokens and live tokens have separate limits.

When a request succeeds, the number of remaining requests in the current window is returned in the response header.

```
X-RateLimit-Remaining: 42
```

When the limit is exceeded the response is a 429 with a JSON error body.

The window is aligned to fixed time boundaries calculated from the Unix timestamp. A 60-second window always starts at the top of each UTC minute, so resets are predictable regardless of when the first request arrived.

## Refresh Tokens

When an access token expires the client can use a refresh token to get a new one without asking the user to log in again. Calling `rotate()` atomically revokes the old refresh token and generates a replacement in a single database transaction, preventing reuse even under concurrent requests.

```php
public function actionRefresh(): void
{
    $this->requireMethod('POST');

    $data = $this->getJsonBody();
    $newRefreshToken = $this->refreshTokenService->rotate($data['refresh_token']);

    if (!$newRefreshToken) {
        $this->sendError(401, 'Invalid or expired refresh token');
    }

    $this->sendJson([
        'refresh_token' => $newRefreshToken,
        'token_type'    => 'Bearer',
    ]);
}
```

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
$this->getCurrentUser()                   // returns the authenticated user's data as an array
$this->getCurrentScopes()                 // returns the scopes assigned to the current token
$this->isLiveMode()                       // returns true when the request uses a live token
$this->requireMethod('GET', 'POST')       // terminates with 405 if the HTTP method is not listed
$this->requireRole('admin')               // terminates with 403 if the user's role does not match
$this->requireScope('write')              // terminates with 403 if the token lacks the scope
$this->requireAllScopes('read', 'write')  // terminates with 403 unless all scopes are present
$this->requireAnyScope('write', 'admin')  // terminates with 403 unless at least one scope is present
$this->getJsonBody()                      // decodes the request body as JSON, returns 400 on invalid input
$this->sendError(401, 'Unauthorized')     // sends a JSON error response and terminates
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
