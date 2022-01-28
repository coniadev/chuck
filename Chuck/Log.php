<?php

declare(strict_types=1);

namespace Chuck;

use Monolog\Logger;
use Monolog\Handler\RotatingFileHandler;
use Monolog\Handler\HandlerInterface;

class Log
{
    protected static RequestInterface $request;
    protected static Logger $log;

    public static function init(RequestInterface $request): void
    {
        $config = $request->config;
        $appname = $config->get('appname');
        self::$log = new Logger($appname);

        $path = $config->path('log');

        if (realpath($path)) {
            $file = $path . DIRECTORY_SEPARATOR . "$appname.log";
            $loglevel = self::getLevel($config->get('loglevel'));
            $handler = new RotatingFileHandler($file, 0, $loglevel, true, 0664);
            $handler->setFilenameFormat('{date}-{filename}', 'Y-m-d');
            self::$log->pushHandler($handler);
        }
    }

    protected static function getLevel(string $name): int
    {
        $levels = [
            'DEBUG' => Logger::DEBUG,
            'INFO' => Logger::INFO,
            'NOTICE' => Logger::NOTICE,
            'WARNING' => Logger::WARNING,
            'ERROR' => Logger::ERROR,
            'CRITICAL' => Logger::CRITICAL,
            'ALERT' => Logger::ALERT,
            'EMERGENCY' => Logger::EMERGENCY,
        ];

        return $levels[$name];
    }

    public static function pushHandler(HandlerInterface $handler): void
    {
        self::$log->pushHandler($handler);
    }

    public static function log(int $level, $message, $context = []): void
    {
        self::$log->addRecord($level, (string)$message, $context);
    }

    public static function debug($msg, $context = []): void
    {
        self::$log->log(Logger::DEBUG, $msg, $context);
    }

    public static function info($msg, $context = []): void
    {
        self::$log->log(Logger::INFO, $msg, $context);
    }

    public static function notice($msg, $context = []): void
    {
        self::$log->log(Logger::NOTICE, $msg, $context);
    }

    public static function warning($msg, $context = []): void
    {
        self::$log->log(Logger::WARNING, $msg, $context);
    }

    public static function error($msg, $context = []): void
    {
        self::$log->log(Logger::ERROR, $msg, $context);
    }

    public static function critical($msg, $context = []): void
    {
        self::$log->log(Logger::CRITICAL, $msg, $context);
    }

    public static function alert($msg, $context = []): void
    {
        self::$log->log(Logger::ALERT, $msg, $context);
    }

    public static function emergency($msg, $context = []): void
    {
        self::$log->log(Logger::EMERGENCY, $msg, $context);
    }
}
