<?php

declare(strict_types=1);

namespace Chuck\Exception;

class HttpUnauthorized extends HttpException
{
    protected $code = 401;

    protected $message = 'Unauthorized';

    protected $title = '401 Unauthorized';
}
