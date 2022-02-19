<?php

declare(strict_types=1);

namespace Chuck\Error;

use Chuck\RequestInterface;


class Handler
{
    protected RequestInterface $request;

    public function addRequest(RequestInterface $request): void
    {
        $this->request = $request;
    }

    public function handleError(
        int $level,
        string $message,
        string $file = null,
        int $line = null
    ): bool {
        if ($level & error_reporting()) {
            throw new \ErrorException($message, $level, $level, $file, $line);
        }

        return false;
    }

    public function handleException(\Throwable $exception): void
    {
        throw $exception;
    }

    public function setup(): void
    {
        $errorLevel = $this->request->getConfig()->get('errorLevel');

        set_error_handler($this->handleError(...), $errorLevel);
        set_exception_handler($this->handleException(...));
    }
}
