<?php

declare(strict_types=1);

namespace Chuck\Error;

use Chuck\RequestInterface;
use Chuck\Error\HttpError;
use Chuck\Util\Log;


class Handler
{
    public function __construct(protected RequestInterface $request)
    {
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
        $code = $exception->getCode();

        if ($exception instanceof HttpError) {
            $response->setStatusCode($code);
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

        $trace = $exception->getTraceAsString();
        $this->log($code, implode("\n#", explode('#', $trace)));

        if ($debug) {
            $trace = htmlspecialchars($trace);
            $trace = implode('<br>#', explode('#', $trace));
            $body .= preg_replace('/^<br>/', '', $trace);
        }

        $response->setBody($body);
        $response->emit();
    }

    public function setup(): callable|null
    {
        $errorLevel = $this->request->getConfig()->get('errorLevel');

        set_error_handler($this->handleError(...), $errorLevel);
        return set_exception_handler($this->handleException(...));
    }

    public function log(int $level, string $message): void
    {
        Log::log($this->request, $level, $message);
    }
}
