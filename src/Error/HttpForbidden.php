<?php

declare(strict_types=1);

namespace Conia\Chuck\Error;

use Throwable;

class HttpForbidden extends HttpError
{
    public function __construct(
        string $message = 'Forbidden',
        int $code = 403,
        ?Throwable $previous = null
    ) {
        parent::__construct($message, $code, $previous);
    }
}
