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
        $debug = $this->request->config()->debug();
        $response = $this->request->response();

        if ($exception instanceof HttpError) {
            $code = $exception->getCode();
            $response->setStatusCode($code);
            $body = '<h1>' . htmlspecialchars($exception->getTitle()) . '</h1>';
            $subTitle = $exception->getSubtitle();

            if ($subTitle) {
                $body .= '<h2>' . htmlspecialchars($subTitle) . '</h2>';
            } else {
                $body .= '<h2>HTTP Error</h2>';
            }
        } elseif ($exception instanceof ExitException) {
            // @codeCoverageIgnoreStart
            exit();
            // @codeCoverageIgnoreEnd
        } else {
            $code = 500;
            $response->setStatusCode($code);
            $body = '<h1>500 Internal Server Error</h1>';
            $body .= '<h2>' . htmlspecialchars($exception->getMessage()) . '</h2>';
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
        $this->log($exception);
    }

    protected function getLoggerMethod(Throwable $exception): string
    {
        return match ($exception::class) {
            HttpNotFound::class => 'info',
            HttpMethodNotAllowed::class => 'info',
            HttpForbidden::class => 'notice',
            HttpUnauthorized::class => 'notice',
            HttpBadRequest::class => 'warning',
            HttpServerError::class => 'error',
            default => 'error',
        };
    }

    public function log(Throwable $exception): void
    {
        $logger = $this->request->config()->logger();
        if ($logger) {
            $method = $this->getLoggerMethod($exception);
            ([$logger, $method])("Uncaught Exception:", ['exception' => $exception]);
        }
    }
}
