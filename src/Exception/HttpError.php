<?php

declare(strict_types=1);

namespace Conia\Chuck\Exception;

use Exception;

/** @psalm-api */
abstract class HttpError extends Exception implements ChuckException
{
    protected mixed $payload = null;

    public function getTitle(): string
    {
        return (string)$this->getCode() . ' ' . $this->getMessage();
    }

    public function withPayload(mixed $payload): static
    {
        $exception = new static();
        $exception->setPayload($payload);

        return $exception;
    }

    public function setPayload(mixed $payload): mixed
    {
        $this->payload = $payload;
    }

    public function payload(): mixed
    {
        return $this->payload;
    }
}
