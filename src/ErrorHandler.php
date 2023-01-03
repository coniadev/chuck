<?php

declare(strict_types=1);

namespace Conia\Chuck;

use ErrorException;
use Throwable;
use Conia\Chuck\RequestInterface;
use Conia\Chuck\Response\ResponseInterface;
use Conia\Chuck\Exception\ExitException;
use Conia\Chuck\Exception\HttpError;
use Conia\Chuck\Exception\HttpBadRequest;
use Conia\Chuck\Exception\HttpForbidden;
use Conia\Chuck\Exception\HttpNotFound;
use Conia\Chuck\Exception\HttpMethodNotAllowed;
use Conia\Chuck\Exception\HttpServerError;
use Conia\Chuck\Exception\HttpUnauthorized;

class ErrorHandler
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
        $response = $this->request->response()->html(null);
        $debug = $this->request->config()->debug();

        if ($exception instanceof HttpError) {
            $code = $exception->getCode();
            $response->statusCode($code);
            $body = '<h1>' . htmlspecialchars($exception->getTitle()) . '</h1>';
            $subTitle = $exception->getSubtitle();

            if ($subTitle) {
                $body .= '<h2>' . htmlspecialchars($subTitle) . '</h2>';
            } else {
                $body .= '<h2>HTTP Error</h2>';
            }
        } elseif ($exception instanceof ExitException) {
            // Would stop the test suit
            // @codeCoverageIgnoreStart
            exit();
            // @codeCoverageIgnoreEnd
        } else {
            $code = 500;
            $response->statusCode($code);
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

        $this->log($exception);

        try {
            $response->body($body)->emit();
        } catch (Throwable) {
            // No server request, most likley a CLI call
            echo $exception->getMessage() . "\n";
        }
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
