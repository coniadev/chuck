<?php

declare(strict_types=1);

namespace Chuck\Response;

use \ValueError;


class Headers
{
    const REASON_PHRASES = [
        100 => 'Continue', 101 => 'Switching Protocols',
        200 => 'OK', 201 => 'Created', 202 => 'Accepted', 203 => 'Non-Authoritative Information',
        204 => 'No Content', 205 => 'Reset Content', 206 => 'Partial Content',
        300 => 'Multiple Choices', 301 => 'Moved Permanently', 302 => 'Found', 303 => 'See Other',
        304 => 'Not Modified', 305 => 'Use Proxy', 307 => 'Temporary Redirect',
        400 => 'Bad Request', 401 => 'Unauthorized', 402 => 'Payment Required', 403 => 'Forbidden',
        404 => 'Not Found', 405 => 'Method Not Allowed', 406 => 'Not Acceptable',
        407 => 'Proxy Authentication Required', 408 => 'Request Time-out', 409 => 'Conflict',
        410 => 'Gone', 411 => 'Length Required', 412 => 'Precondition Failed',
        413 => 'Request Entity Too Large', 414 => 'Request-URI Too Large', 415 => 'Unsupported Media Type',
        416 => 'Requested range not satisfiable', 417 => 'Expectation Failed',
        500 => 'Internal Server Error', 501 => 'Not Implemented', 502 => 'Bad Gateway',
        503 => 'Service Unavailable', 504 => 'Gateway Time-out', 505 => 'HTTP Version not supported',
    ];

    /** @var array<never, never>|array<array-key, array{value: array<string>, replace: bool}> */
    protected array $headers = [];
    /** @psalm-var list<string> */
    protected array $emittedHeaders = [];

    public function __construct(
        /** @param list<array{string, string, ?bool}> */
        array $headers = []
    ) {
        foreach ($headers as $header) {
            $this->add($header[0], $header[1], $header[2] ?? true);
        }
    }

    protected function prepareName(string $name): string
    {
        return ucwords(strtolower($name), '-');
    }

    public function add(string $name, string $value, bool $replace = true,): void
    {
        $this->validateHeaderName($name);
        $name = $this->prepareName($name);

        if (array_key_exists($name, $this->headers) && $replace === false) {
            $this->headers[$name] = [
                'value' => array_merge($this->headers[$name]['value'], [$value]),
                'replace' => $replace,
            ];

            return;
        }

        $this->headers[$name] = [
            'value' => [$value],
            'replace' => $replace,
        ];
    }

    public function has(string $name): bool
    {
        return array_key_exists($this->prepareName($name), $this->headers);
    }

    public function list(): array
    {
        return $this->headers;
    }

    /** @return list<string> */
    public function emitted(): array
    {
        return $this->emittedHeaders;
    }

    protected function validateHeaderName(string $name): void
    {
        if (preg_match("/^[0-9A-Za-z-]+$/", $name) !== 1) {
            throw new ValueError(
                'Header name must consist only of the characters a-zA-Z0-9 and -.'
            );
        }
    }

    protected function emitHeader(string $value, bool $replace): void
    {
        $this->emittedHeaders[] = $value;

        if (PHP_SAPI === 'cli') {
            return;
        }

        // In the tests suit we check $this->emittedHeaders
        // @codeCoverageIgnoreStart
        header($value, $replace);
        // @codeCoverageIgnoreEnd
    }

    public function emit(
        int $statusCode = 200,
        string $protocol = '1.1',
        string $charset = 'UTF-8',
        ?string $reasonPhrase = null
    ): void {
        if (!$this->has('Content-Type')) {
            $this->emitHeader('Content-Type: text/html; charset=' . $charset, true);
        } else {
            $ct = $this->headers['Content-Type']['value'][0];

            if (stripos($ct, 'text/') === 0 && stripos($ct, 'charset') === false) {
                // Add missing charset
                $this->headers['Content-Type']['value'][0] .= '; charset=' . $charset;
            }
        }

        foreach ($this->headers as $name => $entry) {
            foreach ($entry['value'] as $value) {
                $this->emitHeader(sprintf('%s: %s', $name, $value), $entry['replace']);
            }
        }

        // Emit status line after general headers to overwrite previous status codes
        $this->emitHeader(sprintf(
            'HTTP/%s %d %s',
            $protocol,
            $statusCode,
            $reasonPhrase ?: self::REASON_PHRASES[$statusCode]
        ), true);
    }
}
