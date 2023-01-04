<?php

declare(strict_types=1);

namespace Conia\Chuck;

use Throwable;
use Conia\Chuck\Exception\OutOfBoundsException;
use Conia\Chuck\Exception\RuntimeException;
use Conia\Chuck\Util\Uri;

class Request
{
    public function params(): array
    {
        // GET parameters have priority
        return array_merge($_POST, $_GET);
    }

    public function param(string $key, ?string $default = null): null|string|array
    {
        // prefer GET parameters
        if (array_key_exists($key, $_GET)) {
            return $_GET[$key];
        }

        if (array_key_exists($key, $_POST)) {
            return $_POST[$key];
        }

        if (func_num_args() > 1) {
            return $default;
        }

        throw new OutOfBoundsException("Key '$key' not found");
    }

    public function scheme(): string
    {
        return Uri::scheme();
    }

    public function origin(): string
    {
        return Uri::origin();
    }

    public function url(bool $stripQuery = false): string
    {
        return Uri::url($stripQuery);
    }

    public function host(bool $stripPort = false): string
    {
        return Uri::host($stripPort);
    }

    public function path(bool $stripQuery = false): string
    {
        return Uri::path($stripQuery);
    }

    public function redirect(string $url, int $code = 302): never
    {
        Uri::redirect($url, $code);
    }

    public function method(): string
    {
        return strtoupper($_SERVER['REQUEST_METHOD'] ?? 'UNKNOWN');
    }

    public function isMethod(string $method): bool
    {
        return strtoupper($method) === $this->method();
    }

    public function body(string $stream = 'php://input'): string
    {
        return file_get_contents($stream);
    }

    public function json(
        string $stream = 'php://input',
        int $flags = JSON_OBJECT_AS_ARRAY,
    ): mixed {
        $body = $this->body($stream);

        if (empty($body)) {
            return null;
        }

        return json_decode(
            $body,
            true,
            512, // PHP default value
            $flags,
        );
    }

    public function hasFile(string $key): bool
    {
        return isset($_FILES[$key]);
    }

    public function hasMultipleFiles(string $key): bool
    {
        /**
         * @psalm-suppress TypeDoesNotContainType
         *
         * Psalm does not support multi file uploads yet and complains
         * about type issues. We need to suppres some of the errors.
         */
        return isset($_FILES[$key]) && is_array($_FILES[$key]['error']);
    }

    /** @param non-empty-string $field */
    public function file(string $field): File
    {
        try {
            return File::fromArray($_FILES[$field]);
        } catch (Throwable) {
            throw new RuntimeException("Cannot read file '$field'");
        }
    }

    /**
     * Transforms the cumbersome PHP multi upload array layout
     * into a sane format.
     *
     * Psalm does not support multi file uploads yet and complains
     * about type issues. We need to suppres some of the errors.
     *
     * @param non-empty-string $field
     * @return list<File>
     * @psalm-suppress TypeDoesNotContainType, InvalidArrayAccess
     */
    public function files(string $field): array
    {
        if (isset($_FILES[$field]['error']) && is_array($_FILES[$field]['error'])) {
            $files = [];

            /**
             * @var int $idx
             * @var int $error
             * */
            foreach ($_FILES[$field]['error'] as $idx => $error) {
                $f = $_FILES[$field] ?? null;

                if ($f) {
                    $files[] = new File(
                        $f['name'][$idx],
                        $f['tmp_name'][$idx],
                        $f['type'][$idx],
                        (int)$f['size'][$idx],
                        $error,
                    );
                }
            }

            return $files;
        }

        return [$this->file($field)];
    }
}
