<?php

declare(strict_types=1);

namespace Chuck\Error;

use Chuck\RequestInterface;
use Chuck\Error\HttpError;
use Chuck\Error\HttpBadRequest;
use Chuck\Error\HttpForbidden;
use Chuck\Error\HttpNotFound;
use Chuck\Error\HttpServerError;
use Chuck\Error\HttpUnauthorized;
use Chuck\Log;


class Handler
{
    public function __construct(protected RequestInterface $request)
    {
    }

    public function setup(): callable|null
    {
        $errorLevel = $this->request->getConfig()->get('errorlevel');

        set_error_handler($this->handleError(...), $errorLevel);
        return set_exception_handler($this->handleException(...));
    }

    public function handleError(
        int $level,
        string $message,
        string $file = '',
        int $line = 0,
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
            /** @var int $code */
            $code = $exception->getCode();
            $response->setStatusCode($code);
            $body = '<h1>' . htmlspecialchars($exception->getTitle()) . '</h1>';
            $subTitle = $exception->getSubtitle();

            if ($subTitle) {
                $body .= '<h2>' . htmlspecialchars($subTitle) . '</h2>';
            } else {
                $body .= '<h2>HTTP Error</h2>';
            }

            $level = match ($exception::class) {
                HttpNotFound::class => Log::INFO,
                HttpBadRequest::class => Log::WARNING,
                HttpForbidden::class => Log::WARNING,
                HttpUnauthorized::class => Log::WARNING,
                HttpServerError::class => Log::ERROR,
            };
        } else {
            $response->setStatusCode(500);
            $body = '<h1>500 Internal Server Error</h1>';
            $body .= '<h2>' . htmlspecialchars($exception->getMessage()) . '</h2>';
            $level = Log::ERROR;
        }

        $trace = $exception->getTraceAsString();
        $this->log(
            $level,
            "Uncaught Exception\n\t" .
                $exception->getMessage() . "\n\t" .
                implode("\n\t#", explode('#', $trace))
        );

        if ($debug) {
            $trace = htmlspecialchars($trace);
            $trace = implode('<br>#', explode('#', $trace));
            $body .= preg_replace('/^<br>/', '', $trace);
        }

        $response->setBody($body);
        $response->emit();
    }

    public function log(int $level, string $message): void
    {
        $logger = new Log($this->request);
        $logger->log($level, $message);
    }
}
