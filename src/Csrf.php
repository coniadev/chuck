<?php

declare(strict_types=1);

namespace Chuck;

class Csrf
{
    protected RequestInterface $request;
    protected ConfigInterface $config;

    public function __construct(RequestInterface $request)
    {
        $this->request = $request;
        $this->config = $request->getConfig();

        if (!isset($_SESSION['csrftokens'])) {
            $_SESSION['csrftokens'] = [];
        }
    }

    protected function set(string $page = 'default'): string
    {
        $token = base64_encode(random_bytes(32));
        $_SESSION['csrftokens'][$page] = $token;
        return $token;
    }


    public function get(string $page = 'default'): ?string
    {
        $token = $_SESSION['csrftokens'][$page] ?? $this->set($page);
        return $token;
    }

    public function verify(
        string $page = 'default',
        string $token = null
    ): bool {
        if ($token === null) {
            $token = $_POST['csrftoken'] ?? null;
        }

        if ($token === null) {
            if (isset($_SERVER['HTTP_X_CSRF_TOKEN'])) {
                $token = $_SERVER['HTTP_X_CSRF_TOKEN'];
            }
        }

        if ($token === null) {
            return false;
        }

        return hash_equals($this->get($page), $token);
    }

    public function input($page = 'default', $key = 'csrftoken'): string
    {
        $token = $this->get($page);
        return
            '<input type="hidden" id="' .
            $key .
            '" name="csrftoken" value="' .
            $token .
            '">';
    }
}
