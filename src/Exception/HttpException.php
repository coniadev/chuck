<?php

declare(strict_types=1);

namespace Chuck\Exception;

use Chuck\RequestInterface;


abstract class HttpException extends \Exception
{
    protected readonly RequestInterface $request;
    protected readonly string $title;

    public function getRequest(): RequestInterface
    {
        return $this->request;
    }

    public function getTitle(): string
    {
        return $this->title;
    }

    public function __toString(): string
    {
        return $this->title;
    }
}
