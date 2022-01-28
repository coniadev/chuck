<?php

declare(strict_types=1);

namespace Chuck\Exception;

class HttpNotFound extends HttpException
{
    protected $code = 404;

    protected $message = 'Not Found';

    protected $title = '404 Not Found';
}
