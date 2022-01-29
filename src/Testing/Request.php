<?php

declare(strict_types=1);

namespace Chuck\Testing;

use Chuck\Hash;
use Chuck\RequestInterface;
use Chuck\Request as BaseRequest;

class Request extends BaseRequest implements RequestInterface
{
    protected string $url;
    protected string $method = 'GET';
    protected ?array $body = null;
    protected ?array $json = null;
    protected ?array $user = null;
    protected array $permissions = [];

    public function setUrl(string $url): void
    {
        $_SERVER['HTTP_HOST'] = $this->config->get('hostname');

        if (substr($url, 0, 1) === '/') {
            $_SERVER['REQUEST_URI'] = $url;
        } else {
            $_SERVER['REQUEST_URI'] = "/$url";
        }
    }

    public function setMethod(string $method): void
    {
        $_SERVER['REQUEST_METHOD'] = strtoupper($method);
    }

    public function setBody($body, $type = 'post'): void
    {
        if ($type === 'post') {
            foreach ($body as $key => $value) {
                $_POST[$key] = $value;
            }
        }
        $this->body = $body;
    }

    public function setJson(array $json): void
    {
        $this->json = $json;
    }

    public function GET(string $key, string $value): void
    {
        $_GET[$key] = $value;
    }

    public function jsonBody(): ?array
    {
        return $this->json;
    }

    public function authenticateUserId(int $userId, array $permissions = []): void
    {
        $session = $this->session;
        $session->setUser($userId);

        $hash = new Hash($this);
        $this->user = [
            'usr' => $hash->encode($userId)
        ];

        $this->permissions = $permissions;
    }

    public function user(): ?array
    {
        return $this->user;
    }

    public function permissions(): array
    {
        return $this->permissions;
    }
}