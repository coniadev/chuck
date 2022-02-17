<?php

declare(strict_types=1);

namespace Chuck\Exception;

use Chuck\RequestInterface;


class HttpUnauthorized extends HttpException
{
    public function __construct(
        protected RequestInterface $request,
        string $message = 'Unauthorized',
        int $code = 401,
        ?\Throwable $previous = null
    ) {
        parent::__construct($message, $code, $previous);
        $this->title = '401 Unauthorized';
    }
}
