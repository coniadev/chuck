<?php

declare(strict_types=1);

namespace Chuck\Exception;

class HttpForbidden extends HttpException
{
    protected $code = 403;

    protected $message = 'Forbidden';

    protected $title = '403 Forbidden';
}
