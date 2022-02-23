<?php

declare(strict_types=1);

namespace Chuck;

use Chuck\RequestInterface;


class Log
{
    public const DEBUG = 100;
    public const INFO = 200;
    public const WARNING = 300;
    public const ERROR = 400;
    public const ALERT = 500;

    public function __construct(protected RequestInterface $request)
    {
    }

    public function log(
        int $level,
        string $message
    ): void {
        $config = $this->request->getConfig();

        if ($level < $config->get('loglevel', self::DEBUG)) {
            return;
        }

        $levelStr = [
            self::DEBUG => 'DEBUG',
            self::INFO => 'INFO',
            self::WARNING => 'WARNING',
            self::ERROR => 'ERROR',
            self::ALERT => 'ALERT',
        ][$level];
        $message = str_replace("\0", '', $message);
        $logfile = $config->pathOrNull('logfile');

        if ($logfile) {
            $time = date("Y-m-d H:i:s D T");
            error_log("[$time] $levelStr: $message", 3, $logfile);

            if (PHP_SAPI == 'cli') {
                // print it additionally to stderr
                error_log("$levelStr: $message");
            }
        } else {
            error_log("$levelStr: $message");
        }
    }

    public function debug(string $message): void
    {
        $this->log(self::DEBUG, $message);
    }

    public function info(string $message): void
    {
        $this->log(self::INFO, $message);
    }

    public function warning(string $message): void
    {
        $this->log(self::WARNING, $message);
    }

    public function error(string $message): void
    {
        $this->log(self::ERROR, $message);
    }

    public function alert(string $message): void
    {
        $this->log(self::ALERT, $message);
    }
}
