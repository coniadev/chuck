<?php

declare(strict_types=1);

namespace Chuck;

use \InvalidArgumentException;
use Chuck\Body\Body;
use Chuck\Body\File;
use Chuck\Body\Text;

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


class Response implements ResponseInterface
{
    /** @psalm-suppress PropertyNotSetInConstructor */
    protected array $headerList = [];
    protected ?Body $body = null;

    public function __construct(
        protected RequestInterface $request,
        protected int $statusCode = 200,
        string|Body|null $body = null,
        protected array $headers = [],
        protected string $protocol = '1.1',
        protected ?string $reasonPhrase = null,
    ) {
        if (!empty($body)) {
            if (is_string($body)) {
                $this->body = new Text($body);
            } else {
                $this->body = $body;
            }
        }
    }

    public function statusCode(int $statusCode, ?string $reasonPhrase = null): void
    {
        $this->statusCode = $statusCode;

        if ($reasonPhrase !== null) {
            $this->reasonPhrase = $reasonPhrase;
        }
    }

    public function protocol(string $protocol): void
    {
        $this->protocol = $protocol;
    }

    public function getStatusCode(): int
    {
        return $this->statusCode;
    }

    protected function validateHeaderName(string $name): void
    {
        if (preg_match("/^[0-9A-Za-z-]+$/", $name) !== 1) {
            throw new InvalidArgumentException(
                'Header name must consist only of the characters a-zA-Z0-9 and -.'
            );
        }
    }

    public function header(
        string $name,
        string $value,
        bool $replace = true,
    ): void {
        $this->validateHeaderName($name);
        $name = ucwords(strtolower($name), '-');

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

    public function getHeaderList(): array
    {
        return $this->headerList;
    }

    public function getBody(): ?Body
    {
        return $this->body;
    }

    public function body(string|Body $body): void
    {
        if (is_string($body)) {
            $this->body = new Text($body);
        } else {
            $this->body = $body;
        }
    }

    protected function writeHeader(string $value, bool $replace): void
    {
        if (PHP_SAPI === 'cli') {
            $this->headerList[] = $value;
        } else {
            header($value, $replace);
        }
    }

    public function file(
        string $file,
        bool $sendFile = false,
        bool $asDownload = false,
        int $chunkSize = 2 << 20, // 2 MB
        bool $throwNotFound = true, // 2 MB
    ): void {
        $body = new File($this, $file, $chunkSize, $throwNotFound);

        if ($sendFile) $body = $body->sendfile();
        if ($asDownload) $body = $body->download();

        $this->body = $body;
    }

    public function emit(): void
    {
        // Fix Content-Type
        $ct = $this->headers['Content-Type']['value'][0] ?? null;
        if (!array_key_exists('Content-Type', $this->headers)) {
            $this->writeHeader('Content-Type: text/html; charset=UTF-8', true);
        } else {
            $ct = $this->headers['Content-Type']['value'][0];

            if (stripos($ct, 'text/') === 0 && stripos($ct, 'charset') === false) {
                // Add missing charset
                $this->headers['Content-Type']['value'][0] .= '; charset=UTF-8';
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
            $this->reasonPhrase ?: REASON_PHRASES[$this->statusCode]
        ), true);

        // HEAD responses are not allowed to have a body
        if ($this->request->method() === 'HEAD') {
            return;
        }

        if ($this->body !== null) {
            $this->body->emit();
        }
    }
}
