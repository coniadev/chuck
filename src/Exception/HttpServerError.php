<?php

declare(strict_types=1);

namespace Conia\Chuck\Exception;

use Throwable;

/** @psalm-api */
class HttpServerError extends HttpError
{
    public function __construct(
        string $message = 'Internal Server Error',
        int $code = 500,
        ?Throwable $previous = null
    ) {
        parent::__construct($message, $code, $previous);
    }
}
