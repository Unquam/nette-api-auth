<?php

declare(strict_types=1);

namespace Unquam\NetteApiAuth;

use Nette\Database\Explorer;

class ApiTokenService
{
    // database explorer instance
    private Explorer $database;

    // scope service instance
    private ScopeService $scopeService;

    // table names
    private string $tokenTable;
    private string $userTable;

    // token prefixes
    private string $testPrefix;
    private string $livePrefix;

    // secret key for HMAC token hashing
    private string $secret;

    // user table column names
    private array $userColumns;

    // NULL = unlimited, integer = lifetime in minutes
    private ?int $ttl;

    public function __construct(
        Explorer $database,
        ScopeService $scopeService,
        string $tokenTable  = 'api_tokens',
        string $userTable   = 'api_users',
        string $testPrefix  = 'sk_test_',
        string $livePrefix  = 'sk_live_',
        string $secret      = '',
        ?int   $ttl         = null,
        array  $userColumns = ['id' => 'id', 'email' => 'email', 'role' => 'role']
    ) {
        $this->database     = $database;
        $this->scopeService = $scopeService;
        $this->tokenTable   = $tokenTable;
        $this->userTable    = $userTable;
        $this->testPrefix   = $testPrefix;
        $this->livePrefix   = $livePrefix;
        $this->secret       = $secret;
        $this->ttl          = $ttl;
        $this->userColumns  = $userColumns;

        // secret key must not be empty
        if (empty($this->secret)) {
            throw new \InvalidArgumentException('Secret key cannot be empty');
        }

        // validate that all required user column keys are present
        foreach (['id', 'email', 'role'] as $key) {
            if (!isset($this->userColumns[$key])) {
                throw new \InvalidArgumentException(
                    'userColumns must contain key: ' . $key
                );
            }
        }
    }

    // generate a new token for a user with optional scopes
    public function generate(int $userId, string $name, bool $isLive = false, array $scopes = []): string
    {
        // revoke all existing tokens for this user before generating new one
        $this->revokeAll($userId);

        // validate scopes before generating token
        if (!empty($scopes) && !$this->scopeService->validate($scopes)) {
            $invalid = $this->scopeService->getInvalid($scopes);
            throw new \InvalidArgumentException(
                'Invalid scopes: ' . implode(', ', $invalid)
            );
        }

        $prefix    = $isLive ? $this->livePrefix : $this->testPrefix;
        $raw       = $prefix . bin2hex(random_bytes(32));
        $expiresAt = $this->resolveExpiresAt();

        try {
            $this->database->table($this->tokenTable)->insert([
                'user_id'    => $userId,
                'token'      => $this->hash($raw),
                'name'       => $name,
                'is_live'    => $isLive,
                'scopes'     => empty($scopes) ? null : $this->scopeService->toString($scopes),
                'expires_at' => $expiresAt,
                'created_at' => new \DateTime,
            ]);
        } catch (\Nette\Database\UniqueConstraintViolationException $e) {
            // extremely rare hash collision, retry with new token
            return $this->generate($userId, $name, $isLive, $scopes);
        }

        // return raw token only once
        return $raw;
    }

    // validate token and return user data with scopes
    public function validate(string $raw): ?array
    {
        $row = $this->database->table($this->tokenTable)
            ->where('token', $this->hash($raw))
            ->where('expires_at IS NULL OR expires_at > ?', new \DateTime)
            ->fetch();

        if (!$row) {
            return null;
        }

        // update last used timestamp
        $row->update(['last_used' => new \DateTime]);

        $user = $this->database->table($this->userTable)
            ->where($this->userColumns['id'], $row->user_id)
            ->fetch();

        if (!$user) {
            return null;
        }

        return [
            'user_id'    => $user->{$this->userColumns['id']},
            'email'      => $user->{$this->userColumns['email']},
            'role'       => $user->{$this->userColumns['role']},
            'is_live'    => (bool) $row->is_live,
            'token_id'   => $row->id,
            'expires_at' => $row->expires_at,
            'scopes'     => $this->scopeService->parse($row->scopes),
        ];
    }

    // find token row by raw value
    public function findByRaw(string $raw): ?array
    {
        $row = $this->database->table($this->tokenTable)
            ->where('token', $this->hash($raw))
            ->fetch();

        if (!$row) {
            return null;
        }

        return [
            'id'         => $row->id,
            'name'       => $row->name,
            'is_live'    => (bool) $row->is_live,
            'scopes'     => $this->scopeService->parse($row->scopes),
            'expires_at' => $row->expires_at,
            'created_at' => $row->created_at,
        ];
    }

    // revoke token by raw value
    public function revoke(string $raw): void
    {
        $this->database->table($this->tokenTable)
            ->where('token', $this->hash($raw))
            ->delete();
    }

    // revoke token by id, only owner can revoke
    public function revokeById(int $id, int $userId): void
    {
        $this->database->table($this->tokenTable)
            ->where('id', $id)
            ->where('user_id', $userId)
            ->delete();
    }

    // revoke all tokens for a user
    public function revokeAll(int $userId): void
    {
        $this->database->table($this->tokenTable)
            ->where('user_id', $userId)
            ->delete();
    }

    // get all tokens for a user without exposing token hashes
    public function listForUser(int $userId): array
    {
        return array_map(function ($row) {
            return [
                'id'         => $row->id,
                'name'       => $row->name,
                'is_live'    => (bool) $row->is_live,
                'scopes'     => $this->scopeService->parse($row->scopes),
                'last_used'  => $row->last_used,
                'expires_at' => $row->expires_at,
                'created_at' => $row->created_at,
            ];
        }, $this->database->table($this->tokenTable)
            ->where('user_id', $userId)
            ->order('created_at DESC')
            ->fetchAll()
        );
    }

    // calculate expiration date based on ttl
    private function resolveExpiresAt(): ?\DateTime
    {
        if ($this->ttl === null) {
            return null;
        }

        return (new \DateTime)->modify('+' . $this->ttl . ' minutes');
    }

    // hash token for secure storage
    private function hash(string $raw): string
    {
        return hash_hmac('sha256', $raw, $this->secret);
    }
}