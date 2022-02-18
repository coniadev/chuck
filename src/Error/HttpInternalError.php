<?php

declare(strict_types=1);

namespace Chuck\Error;

use Chuck\RequestInterface;


class HttpInternalError extends HttpError
{
    public function __construct(
        RequestInterface $request,
        string $message = 'Internal Server Error',
        int $code = 500,
        ?\Throwable $previous = null
    ) {
        parent::__construct($message, $code, $previous);
        $this->request = $request;
        $this->title = '500 Internal Server Error';
    }
}
