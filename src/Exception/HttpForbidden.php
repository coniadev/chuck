<?php

declare(strict_types=1);

namespace Chuck\Exception;

use Chuck\RequestInterface;


class HttpForbidden extends HttpException
{
    public function __construct(
        protected RequestInterface $request,
        string $message = 'Forbidden',
        int $code = 403,
        ?\Throwable $previous = null
    ) {
        parent::__construct($message, $code, $previous);
        $this->title = '403 Forbidden';
    }
}
