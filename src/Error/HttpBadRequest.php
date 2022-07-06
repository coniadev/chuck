<?php

declare(strict_types=1);

namespace Conia\Chuck\Error;

use Throwable;


class HttpBadRequest extends HttpError
{
    public function __construct(
        string $message = 'Bad Request',
        int $code = 400,
        ?Throwable $previous = null
    ) {
        parent::__construct($message, $code, $previous);
    }
}
