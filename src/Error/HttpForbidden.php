<?php

declare(strict_types=1);

namespace Chuck\Error;

use Chuck\RequestInterface;


class HttpForbidden extends HttpError
{
    public function __construct(
        RequestInterface $request,
        string $message = 'Forbidden',
        int $code = 403,
        ?\Throwable $previous = null
    ) {
        parent::__construct($message, $code, $previous);
        $this->request = $request;
        $this->title = '403 Forbidden';
    }
}
