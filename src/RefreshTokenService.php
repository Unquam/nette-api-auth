<?php

declare(strict_types=1);

namespace Unquam\NetteApiAuth;

use Nette\Database\Explorer;

class RefreshTokenService
{
    // database explorer instance
    private Explorer $database;

    // table name for refresh tokens
    private string $refreshTable;

    // prefix for refresh tokens
    private string $refreshPrefix;

    // secret key for HMAC token hashing
    private string $secret;

    // NULL = unlimited, integer = lifetime in minutes
    private ?int $ttl;

    public function __construct(
        Explorer $database,
        string $refreshTable  = 'refresh_tokens',
        string $refreshPrefix = 'rt_',
        string $secret        = '',
        ?int   $ttl           = null
    ) {
        $this->database      = $database;
        $this->refreshTable  = $refreshTable;
        $this->refreshPrefix = $refreshPrefix;
        $this->secret        = $secret;
        $this->ttl           = $ttl;

        // secret key must not be empty
        if (empty($this->secret)) {
            throw new \InvalidArgumentException('Secret key cannot be empty');
        }
    }

    // generate a new refresh token linked to an api token
    public function generate(int $userId, int $apiTokenId, bool $revokeExisting = true): string
    {
        if ($revokeExisting) {
            // revoke all existing refresh tokens for this user before generating new one
            $this->revokeAll($userId);
        }

        $raw       = $this->refreshPrefix . bin2hex(random_bytes(32));
        $expiresAt = $this->resolveExpiresAt();

        $this->database->table($this->refreshTable)->insert([
            'user_id'      => $userId,
            'token'        => $this->hash($raw),
            'api_token_id' => $apiTokenId,
            'expires_at'   => $expiresAt,
            'created_at'   => new \DateTime,
        ]);

        // return raw token only once
        return $raw;
    }

    // validate refresh token and return data, uses FOR UPDATE inside transaction
    public function validate(string $raw): ?array
    {
        $row = $this->database->query(
            'SELECT * FROM ' . $this->refreshTable . ' WHERE token = ? AND (expires_at IS NULL OR expires_at > ?) FOR UPDATE',
            $this->hash($raw),
            new \DateTime
        )->fetch();

        if (!$row) {
            return null;
        }

        return [
            'user_id'      => $row->user_id,
            'api_token_id' => $row->api_token_id,
            'expires_at'   => $row->expires_at,
        ];
    }

    // rotate refresh token atomically inside a transaction
    public function rotate(string $raw): ?string
    {
        $result = null;

        $this->database->transaction(function () use ($raw, &$result): void {
            // validate inside transaction so FOR UPDATE row lock is effective
            $data = $this->validate($raw);

            if (!$data) {
                return;
            }

            $this->revoke($raw);
            $result = $this->generate($data['user_id'], $data['api_token_id'], false);
        });

        return $result;
    }

    // revoke refresh token by raw value
    public function revoke(string $raw): void
    {
        $this->database->table($this->refreshTable)
            ->where('token', $this->hash($raw))
            ->delete();
    }

    // revoke all refresh tokens for a user
    public function revokeAll(int $userId): void
    {
        $this->database->table($this->refreshTable)
            ->where('user_id', $userId)
            ->delete();
    }

    // revoke all refresh tokens linked to an api token
    public function revokeByApiToken(int $apiTokenId): void
    {
        $this->database->table($this->refreshTable)
            ->where('api_token_id', $apiTokenId)
            ->delete();
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