<?php

declare(strict_types=1);

namespace Chuck\Error;

use Chuck\RequestInterface;


abstract class HttpError extends \Exception
{
    protected readonly string $title;
    protected readonly RequestInterface $request;

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
