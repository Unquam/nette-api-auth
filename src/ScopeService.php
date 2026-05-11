<?php

declare(strict_types=1);

namespace Unquam\NetteApiAuth;

class ScopeService
{
    // all available scopes in the application
    private array $availableScopes;

    public function __construct(array $availableScopes = [])
    {
        $this->availableScopes = $availableScopes;
    }

    // parse scopes from comma separated string
    public function parse(?string $scopes): array
    {
        if ($scopes === null) {
            return [];
        }

        return array_values(array_filter(
            array_map('trim', explode(',', $scopes))
        ));
    }

    // convert scopes array to comma separated string
    public function toString(array $scopes): string
    {
        return implode(',', $scopes);
    }

    // check if token has a specific scope
    public function has(array $tokenScopes, string $scope): bool
    {
        // empty scopes means all scopes allowed
        if (empty($tokenScopes)) {
            return true;
        }

        return in_array($scope, $tokenScopes, true);
    }

    // check if token has all specified scopes
    public function hasAll(array $tokenScopes, array $scopes): bool
    {
        foreach ($scopes as $scope) {
            if (!$this->has($tokenScopes, $scope)) {
                return false;
            }
        }

        return true;
    }

    // check if token has at least one of specified scopes
    public function hasAny(array $tokenScopes, array $scopes): bool
    {
        foreach ($scopes as $scope) {
            if ($this->has($tokenScopes, $scope)) {
                return true;
            }
        }

        return false;
    }

    // validate scopes against available scopes
    public function validate(array $scopes): bool
    {
        if (empty($this->availableScopes)) {
            return true;
        }

        foreach ($scopes as $scope) {
            if (!in_array($scope, $this->availableScopes, true)) {
                return false;
            }
        }

        return true;
    }

    // get all invalid scopes
    public function getInvalid(array $scopes): array
    {
        if (empty($this->availableScopes)) {
            return [];
        }

        return array_values(
            array_diff($scopes, $this->availableScopes)
        );
    }

    // get all available scopes
    public function getAvailable(): array
    {
        return $this->availableScopes;
    }
}