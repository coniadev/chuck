<?php

declare(strict_types=1);

namespace Chuck\Error;

use Chuck\RequestInterface;


class HttpNotFound extends HttpError
{
    public function __construct(
        RequestInterface $request,
        string $message = 'Not Found',
        int $code = 404,
        ?\Throwable $previous = null
    ) {
        parent::__construct($message, $code, $previous);
        $this->request = $request;
        $this->title = '404 Not Found';
    }
}
