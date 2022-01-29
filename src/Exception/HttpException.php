<?php

declare(strict_types=1);

namespace Chuck\Exception;

use Chuck\RequestInterface;

class HttpException extends \Exception
{
    protected $request;
    protected $title = '';
    protected $message = 'HTTP Error';

    public function __construct(
        RequestInterface $request,
        ?string $message = null,
        int $code = 0,
        ?\Throwable $previous = null
    ) {
        parent::__construct($message ?: $this->message, $code, $previous);
        $this->request = $request;
    }

    public function getRequest(): RequestInterface
    {
        return $this->request;
    }

    public function getTitle(): string
    {
        return $this->title;
    }
}
