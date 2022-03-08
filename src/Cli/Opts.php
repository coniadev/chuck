<?php

declare(strict_types=1);

namespace Chuck\Cli;

use \ValueError;


/**
 * PHP's native `getopt` stops after the first "non-option" argument
 * which in our case is the command in `php run <command>`
 *
 * `-arg`, `--arg` and even `---arg` are treated equally.
 */
class Opts
{
    protected readonly array $opts;

    public function __construct()
    {
        $this->opts = $this->getOpts();
    }

    protected static function getOpts(): array
    {
        $opts = [];
        $key = null;

        foreach ($_SERVER['argv'] as $arg) {
            if (str_starts_with($arg, '-')) {
                $key = $arg;

                if (!isset($opts[$key])) {
                    $opts[$key] = new Opt();
                }
            } else {
                if ($key) {
                    $opts[$key]->set($arg);
                }
            }
        }

        return $opts;
    }

    public function has(string $key): bool
    {
        return isset($this->opts[$key]);
    }

    protected function validate(string $key): void
    {
        if (!isset($this->opts[$key])) {
            throw new ValueError("Unknown option: $key");
        }

        if (isset($this->opts[$key]) && !$this->opts[$key]->isset()) {
            throw new ValueError("No value given for $key");
        }
    }

    public function get(string $key, string $default = ''): string
    {
        if (func_num_args() === 1) {
            $this->validate($key);

            return $this->opts[$key]->get();
        }

        if (!$this->has($key)) {
            return $default;
        }

        if ($this->opts[$key]->isset()) {
            return $this->opts[$key]->get();
        }

        return $default;
    }

    public function all(string $key, array $default = []): array
    {
        if (func_num_args() === 1) {
            $this->validate($key);

            return $this->opts[$key]->all();
        }

        if (!$this->has($key)) {
            return $default;
        }

        if ($this->opts[$key]->isset()) {
            return $this->opts[$key]->all();
        }

        return $default;
    }
}
