<?php

declare(strict_types=1);

namespace Chuck;

use Whoops\Handler\JsonResponseHandler;
use Whoops\Handler\PrettyPageHandler;
use Whoops\Handler\Handler;
use Whoops\Util\Misc;
use Whoops\Run;

use Chuck\Exception\HttpException;

class Error
{
    protected RequestInterface $request;

    public function __construct(RequestInterface $request)
    {
        $this->request = $request;
    }

    protected function getCritical(
        $exception,
        bool $colors = false
    ): string {
        if ($colors) {
            $msg = "\033[1;31mUncaught Exception\033[0m:";
        } else {
            $msg = "Uncaught Exception:";
        }

        $msg .= "\n  " . $exception;
        $msg .= "\n  with message: " . $exception->getMessage();
        $msg .= "\n  Thrown in " .
            $exception->getFile() .
            ' on line ' .
            $exception->getLine();
        $msg .= "\n  Stack Trace: " .
            $exception->getTraceAsString();

        return $msg;
    }

    protected function getNotice($exception, bool $colors = false): string
    {
        $code = $exception->getCode();
        $hostPort = "[" .
            $_SERVER["REMOTE_ADDR"] .
            "]:" .
            $_SERVER["REMOTE_PORT"];
        $title = $exception->getTitle();

        if ($colors) {
            $msg = "$hostPort [\033[1;31m$code\033[0m]: $title";
        } else {
            $msg = "$hostPort $code: $title";
        }

        return $msg;
    }

    protected function logMessage($exception, bool $debug): void
    {
        $code = $exception->getCode();
        $log = $this->request->getConfig()->registry(\Chuck\Middleware\Log::class);

        $isHttpError = is_subclass_of($exception::class, 'Chuck\Exception\HttpException');

        if ($code == 404) {
            return;
        }
        if (!$isHttpError || $code >= 500) {
            $log::critical($this->getCritical($exception));

            if ($debug) {
                // write to builtin server output
                error_log($this->getCritical($exception, true));
            }
        } else {
            $log::notice($this->getNotice($exception));

            if ($debug) {
                error_log($this->getNotice($exception, true));
            }
        }
    }

    protected function jsonResponse(HttpException $exception): void
    {
        header('Content-type: application/json');

        echo json_encode([
            'status_code' => $exception->getCode(),
            'error_message' => $exception->getMessage()
        ]);
    }

    protected function htmlResponse(
        RequestInterface $request,
        HttpException $exception
    ): void {
        $config = $request->getConfig();
        $code = $exception->getCode();
        $tmplDefault = 'errors/httperror';
        $tmplPath = "errors/http$code";

        $class = $config->registry(TemplateInterface::class);
        $tmpl = new $class($request);
        $context = [
            'request' => $request,
            'debug' => $config->get('debug'),
            'env' => $config->get('env'),
            'exception' => $exception,
        ];

        if ($tmpl->exists($tmplPath)) {
            echo $tmpl->render($tmplPath, $context);
        } elseif ($tmpl->exists($tmplDefault)) {
            echo $tmpl->render($tmplDefault, $context);
        } else {
            echo '<h1>' . $exception->getTitle() . '</h1>';
        }
    }

    protected function respondWithHttpError(
        RequestInterface $request,
        HttpException $exception
    ): void {
        http_response_code($exception->getCode());

        if (Misc::isAjaxRequest()) {
            $this->jsonResponse($exception);
            return;
        }

        $this->htmlResponse($request, $exception);
    }


    public function register(): void
    {
        $request = $this->request;
        $debug = $this->request->getConfig()->get('debug');
        $run = new Run();

        // Must be the first handler
        $handler = function (
            $exception,
            $inspector,
            $run
        ) use (
            $request,
            $debug
        ) {
            $this->logMessage($exception, $debug);

            if (is_subclass_of($exception::class, 'Chuck\Exception\HttpException')) {
                $run->sendHttpCode(false);

                $this->respondWithHttpError($request, $exception);

                return Handler::LAST_HANDLER;
            }

            return Handler::DONE;
        };
        $run->pushHandler($handler);

        if ($debug) {
            if (Misc::isAjaxRequest()) {
                $jsonHandler = new JsonResponseHandler();

                $jsonHandler->addTraceToOutput(true);
                $jsonHandler->setJsonApi(true);
                $run->appendHandler($jsonHandler);
            }

            $run->appendHandler(new PrettyPageHandler());
        }

        $run->register();
    }
}
