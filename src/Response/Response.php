<?php

declare(strict_types=1);

namespace Chuck\Response;

use \ValueError;


class Response implements ResponseInterface
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


    /** @var array<never, never>|array<string> */
    protected array $writtenHeaders = [];
    /** @var array<never, never>|array<array-key, array{value: array<string>, replace: bool}> */
    protected array $headers = [];
    protected string $charset = 'UTF-8';
    protected string $protocol = '1.1';
    protected ?string $reasonPhrase = null;

    public function __construct(
        protected mixed $body = null,
        protected int $statusCode = 200,
        /** @param list<array{name: string, value: string, replace: bool}> */
        array $headers = [],
    ) {
        foreach ($headers as $header) {
            $this->header($header['name'], $header['value'], $header['replace'] ?? true);
        }
    }

    public function statusCode(int $statusCode, ?string $reasonPhrase = null): self
    {
        $this->statusCode = $statusCode;

        if ($reasonPhrase !== null) {
            $this->reasonPhrase = $reasonPhrase;
        }

        return $this;
    }

    public function getStatusCode(): int
    {
        return $this->statusCode;
    }

    public function charset(string $charset): self
    {
        $this->charset = $charset;

        return $this;
    }

    public function protocol(string $protocol): self
    {
        $this->protocol = $protocol;

        return $this;
    }

    protected function validateHeaderName(string $name): void
    {
        if (preg_match("/^[0-9A-Za-z-]+$/", $name) !== 1) {
            throw new ValueError(
                'Header name must consist only of the characters a-zA-Z0-9 and -.'
            );
        }
    }

    public function header(
        string $name,
        string $value,
        bool $replace = true,
    ): self {
        $this->validateHeaderName($name);
        $name = ucwords(strtolower($name), '-');

        if (array_key_exists($name, $this->headers) && $replace === false) {
            $this->headers[$name] = [
                'value' => array_merge($this->headers[$name]['value'], [$value]),
                'replace' => $replace,
            ];

            return $this;
        }

        $this->headers[$name] = [
            'value' => [$value],
            'replace' => $replace,
        ];

        return $this;
    }

    public function headers(): array
    {
        return $this->headers;
    }

    public function getWrittenHeaderList(): array
    {
        return $this->writtenHeaders;
    }

    public function body(string $body): self
    {
        $this->body = $body;

        return $this;
    }

    public function getBody(): ?string
    {
        return $this->body;
    }

    protected function writeHeader(string $value, bool $replace): void
    {
        if (PHP_SAPI === 'cli') {
            $this->writtenHeaders[] = $value;
        } else {
            // In the tests suit we check $this->writtenHeaders
            // @codeCoverageIgnoreStart
            header($value, $replace);
            // @codeCoverageIgnoreEnd
        }
    }

    public function emit(): void
    {
        if (!array_key_exists('Content-Type', $this->headers)) {
            $this->writeHeader('Content-Type: text/html; charset=' . $this->charset, true);
        } else {
            $ct = $this->headers['Content-Type']['value'][0];

            if (stripos($ct, 'text/') === 0 && stripos($ct, 'charset') === false) {
                // Add missing charset
                $this->headers['Content-Type']['value'][0] .= '; charset=' . $this->charset;
            }
        }

        foreach ($this->headers as $name => $entry) {
            foreach ($entry['value'] as $value) {
                $this->writeHeader(sprintf('%s: %s', $name, $value), $entry['replace']);
            }
        }

        // Emit status line after general headers to overwrite previous status codes
        $this->writeHeader(sprintf(
            'HTTP/%s %d %s',
            $this->protocol,
            $this->statusCode,
            $this->reasonPhrase ?: self::REASON_PHRASES[$this->statusCode]
        ), true);

        if (strtoupper($_SERVER['REQUEST_METHOD']) === 'HEAD') {
            return;
        }

        $body = $this->getBody();
        if ($body !== null) {
            echo $body;
        }
    }
}
