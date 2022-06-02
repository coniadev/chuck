<?php

declare(strict_types=1);

namespace Chuck\Error;

use \ErrorException;
use \Throwable;
use Chuck\RequestInterface;
use Chuck\Error\HttpError;
use Chuck\Error\HttpBadRequest;
use Chuck\Error\HttpForbidden;
use Chuck\Error\HttpNotFound;
use Chuck\Error\HttpServerError;
use Chuck\Error\HttpUnauthorized;
use Chuck\Logger;


class Handler
{
    public function __construct(protected RequestInterface $request)
    {
    }

    public function setup(): callable|null
    {
        set_error_handler($this->handleError(...), E_ALL);
        return set_exception_handler($this->handleException(...));
    }

    public function handleError(
        int $level,
        string $message,
        string $file = '',
        int $line = 0,
    ): bool {
        if ($level & error_reporting()) {
            throw new ErrorException($message, $level, $level, $file, $line);
        }

        return false;
    }

    public function handleException(Throwable $exception): void
    {
        $code = 0;
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
                HttpNotFound::class => Logger::INFO,
                HttpMethodNotAllowed::class => Logger::INFO,
                HttpForbidden::class => Logger::NOTICE,
                HttpUnauthorized::class => Logger::NOTICE,
                HttpBadRequest::class => Logger::WARNING,
                HttpServerError::class => Logger::ERROR,
            };
        } elseif ($exception instanceof ExitException) {
            exit();
        } else {
            $code = 500;
            $response->setStatusCode($code);
            $body = '<h1>500 Internal Server Error</h1>';
            $body .= '<h2>' . htmlspecialchars($exception->getMessage()) . '</h2>';
            $level = Logger::ERROR;
        }

        if ($debug && $code === 500) {
            $trace = str_replace(
                ['<', '>', '"'],
                ['&lt;', '&gt', '&quot;'],
                $exception->getTraceAsString()
            );
            $trace = implode('<br>#', explode('#', $trace));
            $body .= preg_replace('/^<br>/', '', $trace);
        }

        $response->body($body);
        $response->emit();
        $this->log($level, $exception);
    }

    public function log(int $level, \Throwable $exception): void
    {
        $registry = $this->request->getRegistry();

        if ($registry->has('logger')) {
            $logger = $registry->instance('logger');

            $logger->log(
                $level,
                "Uncaught Exception:",
                [
                    'exception' => $exception,
                ]
            );
        }
    }
}
