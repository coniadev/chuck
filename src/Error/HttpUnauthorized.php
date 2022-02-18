<?php

declare(strict_types=1);

namespace Chuck\Error;

use Chuck\RequestInterface;


class HttpUnauthorized extends HttpError
{
    public function __construct(
        RequestInterface $request,
        string $message = 'Unauthorized',
        int $code = 401,
        ?\Throwable $previous = null
    ) {
        parent::__construct($message, $code, $previous);
        $this->request = $request;
        $this->title = '401 Unauthorized';
    }
}
