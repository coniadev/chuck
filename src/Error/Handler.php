<?php

declare(strict_types=1);

namespace Chuck\Error;

use Chuck\RequestInterface;
use Chuck\Error\HttpError;


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
        $debug = $this->request->getConfig()->debug();
        $response = $this->request->getResponse();

        if ($exception instanceof HttpError) {
            $response->setStatusCode($exception->getCode());
            $body = '<h1>' . htmlspecialchars($exception->getTitle()) . '</h1>';
            $subTitle = $exception->getSubtitle();

            if ($subTitle) {
                $body .= '<h2>' . htmlspecialchars($subTitle) . '</h2>';
            } else {
                $body .= '<h2>HTTP Error</h2>';
            }
        } else {
            $response->setStatusCode(500);
            $body = '<h1>500 Internal Server Error</h1>';
            $body .= '<h2>' . htmlspecialchars($exception->getMessage()) . '</h2>';
        }

        if ($debug) {
            $trace = htmlspecialchars($exception->getTraceAsString());
            $trace = implode('<br>#', explode('#', $trace));
            $body .= preg_replace('/^<br>/', '', $trace);
        }

        $response->setBody($body);
        $response->emit();
    }

    public function setup(): void
    {
        $errorLevel = $this->request->getConfig()->get('errorLevel');

        set_error_handler($this->handleError(...), $errorLevel);
        set_exception_handler($this->handleException(...));
    }
}
