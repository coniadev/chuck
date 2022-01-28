<?php

declare(strict_types=1);

namespace Chuck\Exception;

class HttpBadRequest extends HttpException
{
    protected $code = 400;

    protected $message = 'Bad Request';

    protected $title = '400 Bad Request';
}
