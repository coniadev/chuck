<?php

declare(strict_types=1);

namespace Chuck\Exception;

use Chuck\RequestInterface;


class HttpInternalError extends HttpException
{
    public function __construct(
        protected RequestInterface $request,
        string $message = 'Internal Server Error',
        int $code = 500,
        ?\Throwable $previous = null
    ) {
        parent::__construct($message, $code, $previous);
        $this->title = '500 Internal Server Error';
    }
}
