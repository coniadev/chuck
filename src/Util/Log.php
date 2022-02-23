<?php

declare(strict_types=1);

namespace Chuck\Util;

use Chuck\RequestInterface;


class Log
{
    public static function log(
        RequestInterface $request,
        int $level,
        string $message
    ): void {
        $message = str_replace("\0", '', $message);
        $logfile = $request->getConfig()->get('logfile', false);

        if ($logfile) {
            error_log($message, 3, $logfile);
        } else {
            error_log($message);
        }
    }
}
