<?php

declare(strict_types=1);

namespace Chuck\Util;

use Chuck\RequestInterface;


class Log
{
    public const DEBUG = 100;
    public const INFO = 200;
    public const WARN = 300;
    public const ERROR = 400;
    public const ALERT = 500;

    public function __construct(protected RequestInterface $request)
    {
    }

    public function log(
        int $level,
        string $message
    ): void {
        $levelStr = [
            self::DEBUG => 'DEBUG',
            self::INFO => 'INFO',
            self::WARN => 'WARNING',
            self::ERROR => 'ERROR',
            self::ALERT => 'ALERT',
        ][$level];
        $message = str_replace("\0", '', $message);
        $logfile = $this->request->getConfig()->get('logfile', false);

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

    public function warn(string $message): void
    {
        $this->log(self::WARN, $message);
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
