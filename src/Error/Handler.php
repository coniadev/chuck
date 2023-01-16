<?php

declare(strict_types=1);

namespace Conia\Chuck\Error;

use Conia\Chuck\Config;
use Conia\Chuck\Exception\ExitException;
use Conia\Chuck\Exception\HttpBadRequest;
use Conia\Chuck\Exception\HttpError;
use Conia\Chuck\Exception\HttpForbidden;
use Conia\Chuck\Exception\HttpMethodNotAllowed;
use Conia\Chuck\Exception\HttpNotFound;
use Conia\Chuck\Exception\HttpServerError;
use Conia\Chuck\Exception\HttpUnauthorized;
use Conia\Chuck\Http\Emitter;
use Conia\Chuck\Middleware;
use Conia\Chuck\Registry;
use Conia\Chuck\Request;
use Conia\Chuck\Response;
use Conia\Chuck\ResponseFactory;
use ErrorException;
use Psr\Log\LoggerInterface as PsrLogger;
use Throwable;

class Handler implements Middleware
{
    public function __construct(protected Config $config, protected Registry $registry)
    {
        set_error_handler([$this, 'handleError'], E_ALL);
        set_exception_handler([$this, 'emitException']);
    }

    public function __destruct()
    {
        restore_error_handler();
        restore_exception_handler();
    }

    public function __invoke(Request $request, callable $next): Response
    {
        try {
            $response = $next($request);
            assert($response instanceof Response);

            return $response;
        } catch (Throwable $e) {
            return $this->handleException($e);
        }
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

    public function emitException(Throwable $exception): void
    {
        $response = $this->handleException($exception);
        (new Emitter())->emit($response->psr());
    }

    public function handleException(Throwable $exception): Response
    {
        $response = (new ResponseFactory($this->registry))->html(null);
        $debug = $this->config->debug();

        if ($exception instanceof HttpError) {
            $code = $exception->getCode();
            $response->status($code);
            $body = '<h1>' . htmlspecialchars($exception->getTitle()) . '</h1>';
            $subTitle = $exception->getSubtitle();

            if ($subTitle) {
                $body .= '<h2>' . htmlspecialchars($subTitle) . '</h2>';
            } else {
                $body .= '<h2>HTTP Error</h2>';
            }
        } else {
            $code = 500;
            $response->status($code);
            $body = '<h1>500 Internal Server Error</h1>';

            if ($debug) {
                $body .= '<h2>' . htmlspecialchars($exception->getMessage()) . '</h2>';
            }
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

        return $response->body($body);
    }

    public function log(Throwable $exception): void
    {
        if ($this->registry->has(PsrLogger::class)) {
            $logger = $this->registry->get(PsrLogger::class);
            assert($logger instanceof PsrLogger);
            $method = $this->getLoggerMethod($exception);
            ([$logger, $method])('Uncaught Exception:', ['exception' => $exception]);
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
}
