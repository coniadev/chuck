<?php

declare(strict_types=1);

namespace Conia\Chuck\Error;

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
use Conia\Chuck\Renderer\Render;
use Conia\Chuck\Request;
use Conia\Chuck\Response;
use Conia\Chuck\ResponseWrapper;
use ErrorException;
use Psr\Log\LoggerInterface as PsrLogger;
use Throwable;

/** @psalm-api */
class Handler implements Middleware
{
    public function __construct(protected Registry $registry)
    {
        set_error_handler([$this, 'handleError'], E_ALL);
        set_exception_handler([$this, 'emitException']);
    }

    public function __destruct()
    {
        restore_error_handler();
        restore_exception_handler();
    }

    public function __invoke(Request $request, callable $next): ResponseWrapper
    {
        try {
            $response = $next($request);
            assert($response instanceof ResponseWrapper);

            return $response;
        } catch (Throwable $e) {
            return $this->handleException($e, $request);
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
        $response = $this->handleException($exception, null);
        (new Emitter())->emit($response->psr());
    }

    public function handleException(Throwable $exception, ?Request $request): ResponseWrapper
    {
        if ($exception instanceof HttpError) {
            $code = $exception->getCode();
            $title = htmlspecialchars($exception->getTitle());
            $description = 'HTTP Error';
        } else {
            $code = 500;
            $title = '500 Internal Server Error';
            $description = $exception->getMessage();
        }

        $error = new Error(
            $title,
            $description,
            $exception->getTraceAsString(),
            $code,
        );

        $this->log($exception);

        $accepted = $request ? $this->getAcceptedContentType($request) : 'text/html';
        $rendererConfig = $this->registry->tag(self::class)->get($accepted);
        assert($rendererConfig instanceof ErrorRenderer);
        $render = new Render($rendererConfig->renderer, ...$rendererConfig->args);
        $response = new Response($render->response($this->registry, ['error' => $error])->psr());
        $response->status($code);

        return $response;
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

    protected function getAcceptedContentType(Request $request): string
    {
        $tag = $this->registry->tag(self::class);
        $accepted = $request->accept();
        $renderers = $tag->entries();
        $available = array_intersect($accepted, $renderers);

        return (string)(array_shift($available) ?? 'text/plain');
    }
}
