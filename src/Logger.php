<?php

declare(strict_types=1);

namespace Conia\Chuck;

use DateTimeInterface;
use Psr\Log\InvalidArgumentException;
use Psr\Log\LoggerInterface as PsrLogger;
use Stringable;
use Throwable;

/** @psalm-api */
class Logger implements PsrLogger
{
    public const DEBUG = 100;
    public const INFO = 200;
    public const NOTICE = 300;
    public const WARNING = 400;
    public const ERROR = 500;
    public const CRITICAL = 600;
    public const ALERT = 700;
    public const EMERGENCY = 800;

    /** @psalm-var array<int, non-empty-string> */
    protected array $levelLabels;

    public function __construct(
        protected int $minimumLevel = self::DEBUG,
        protected ?string $logfile = null,
    ) {
        $this->levelLabels = [
            self::DEBUG => 'DEBUG',
            self::INFO => 'INFO',
            self::NOTICE => 'NOTICE',
            self::WARNING => 'WARNING',
            self::ERROR => 'ERROR',
            self::CRITICAL => 'CRITICAL',
            self::ALERT => 'ALERT',
            self::EMERGENCY => 'EMERGENCY',
        ];
    }

    public function log(
        mixed $level,
        string|Stringable $message,
        array $context = [],
    ): void {
        $message = (string)$message;
        assert(is_int($level) || is_numeric($level));
        $level = (int)$level;

        if ($level < $this->minimumLevel) {
            return;
        }

        try {
            $levelLabel = $this->levelLabels[$level];
        } catch (Throwable) {
            throw new InvalidArgumentException('Unknown log level: ' . (string)$level);
        }

        $message = $this->interpolate(str_replace("\0", '', $message), $context);

        if (is_string($this->logfile)) {
            $time = date('Y-m-d H:i:s D T');
            error_log("[{$time}] {$levelLabel}: {$message}", 3, $this->logfile);

            if (PHP_SAPI == 'cli') {
                // print it additionally to stderr
                error_log("{$levelLabel}: {$message}");
            }
        } else {
            error_log("{$levelLabel}: {$message}");
        }
    }

    public function debug(string|Stringable $message, array $context = []): void
    {
        $this->log(self::DEBUG, $message, $context);
    }

    public function info(string|Stringable $message, array $context = []): void
    {
        $this->log(self::INFO, $message, $context);
    }

    public function notice(string|Stringable $message, array $context = []): void
    {
        $this->log(self::NOTICE, $message, $context);
    }

    public function warning(string|Stringable $message, array $context = []): void
    {
        $this->log(self::WARNING, $message, $context);
    }

    public function error(string|Stringable $message, array $context = []): void
    {
        $this->log(self::ERROR, $message, $context);
    }

    public function critical(string|Stringable $message, array $context = []): void
    {
        $this->log(self::CRITICAL, $message, $context);
    }

    public function alert(string|Stringable $message, array $context = []): void
    {
        $this->log(self::ALERT, $message, $context);
    }

    public function emergency(string|Stringable $message, array $context = []): void
    {
        $this->log(self::EMERGENCY, $message, $context);
    }

    protected function interpolate(string $template, array $context): string
    {
        $substitudes = [];

        /**
         * @psalm-suppress MixedAssignment
         *
         * $value types are exhaustively checked
         */
        foreach ($context as $key => $value) {
            $placeholder = '{' . $key . '}';

            if (strpos($template, $placeholder) === false) {
                continue;
            }

            $substitudes[$placeholder] = match (true) {
                (is_scalar($value) || (is_object($value) && method_exists($value, '__toString'))) => (string)$value,
                $value instanceof DateTimeInterface => $value->format('Y-m-d H:i:s T'),
                is_object($value) => '[Instance of ' . $value::class . ']',
                is_array($value) => '[Array ' . json_encode($value, JSON_UNESCAPED_SLASHES) . ']',
                is_null($value) => '[null]',
                default => '[' . get_debug_type($value) . ']',
            };
        }

        $message = strtr($template, $substitudes);
        $message .= $this->getExceptionMessage($context);

        return $message;
    }

    protected function getExceptionMessage(array $context): string
    {
        $message = '';

        if (
            array_key_exists('exception', $context)
            && $context['exception'] instanceof Throwable
        ) {
            $message .= "\n    Exception Message: " . $context['exception']->getMessage() . "\n\n";
            $message .= implode('    #', explode('#', $context['exception']->getTraceAsString()));
        }

        return $message;
    }
}
