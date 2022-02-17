<?php

declare(strict_types=1);

namespace Chuck\Exception;

use Chuck\RequestInterface;


class HttpNotFound extends HttpException
{
    public function __construct(
        protected RequestInterface $request,
        string $message = 'Not Found',
        int $code = 404,
        ?\Throwable $previous = null
    ) {
        parent::__construct($message, $code, $previous);
        $this->title = '404 Not Found';
    }
}
