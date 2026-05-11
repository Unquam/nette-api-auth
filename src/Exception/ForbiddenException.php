<?php

declare(strict_types=1);

namespace Unquam\NetteApiAuth\Exception;

class ForbiddenException extends \RuntimeException
{
    // default message and code for forbidden requests
    public function __construct(string $message = 'Forbidden', int $code = 403)
    {
        parent::__construct($message, $code);
    }
}