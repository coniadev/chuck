<?php

declare(strict_types=1);

namespace Chuck\Exception;

class HttpInternalError extends HttpException
{
    protected $code = 500;

    protected $message = 'Internal Server Error';

    protected $title = '500 Internal Server Error';
}
