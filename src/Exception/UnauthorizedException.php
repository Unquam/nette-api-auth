<?php

declare(strict_types=1);

namespace Unquam\NetteApiAuth\Exception;

class UnauthorizedException extends \RuntimeException
{
    // default message and code for unauthorized requests
    public function __construct(string $message = 'Unauthorized', int $code = 401)
    {
        parent::__construct($message, $code);
    }
}