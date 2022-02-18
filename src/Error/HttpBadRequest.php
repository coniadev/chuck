<?php

declare(strict_types=1);

namespace Chuck\Error;

use Chuck\RequestInterface;


class HttpBadRequest extends HttpError
{
    public function __construct(
        RequestInterface $request,
        string $message = 'HTTP Error',
        int $code = 400,
        ?\Throwable $previous = null
    ) {
        parent::__construct($message, $code, $previous);
        $this->request = $request;
        $this->title = '400 Bad Request';
    }
}
