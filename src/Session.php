<?php

declare(strict_types=1);

namespace Chuck;

use Chuck\Util\Http;


class Session implements SessionInterface
{
    protected RequestInterface $request;
    protected ConfigInterface $config;
    protected string $name;

    public function __construct(
        RequestInterface $request,
        ?string $name = null,
        protected string $flashMessagesKey = 'flash_messages',
        protected string $rememberedUriKey = 'remembered_uri',
    ) {
        // TODO:
        // session_set_cookie_params(['SameSite' => 'Strict']);

        $this->request = $request;
        $this->config = $request->getConfig();
        $this->name = $name ?: $this->config->app();
    }

    public function start(): void
    {
        if (!isset($_SESSION)) {
            // If we are run from the command line interface we do not care
            // about headers sent using session_start.
            if (PHP_SAPI === 'cli') {
                $_SESSION = [];
            }
            if (!headers_sent()) {
                session_name($this->name);

                if (!session_start()) {
                    // @codeCoverageIgnoreStart
                    throw new \RuntimeException(__METHOD__ . 'session_start failed.');
                    // @codeCoverageIgnoreEnd
                }
            } else {
                // @codeCoverageIgnoreStart
                throw new \RuntimeException(
                    __METHOD__ . 'Session started after headers sent.'
                );
                // @codeCoverageIgnoreEnd
            }
        }
    }

    public function forget(): void
    {
        // Unset all of the session variables.
        global $_SESSION;
        $_SESSION = [];

        // If it's desired to kill the session, also delete the session cookie.
        // Note: This will destroy the session, and not just the session data!
        if (ini_get("session.use_cookies")) {
            $params = session_get_cookie_params();
            setcookie(
                session_name(),
                '',
                time() - 42000,
                $params["path"],
                $params["domain"],
                $params["secure"],
                $params["httponly"]
            );
        }

        if (PHP_SAPI === 'cli') {
            return;
        }

        // Finally, destroy the session.
        // @codeCoverageIgnoreStart
        session_destroy();
        // @codeCoverageIgnoreEnd
    }

    public function get(string $key, mixed $default = null): mixed
    {
        if (!$this->has($key) && func_num_args() > 1) {
            return $default;
        }

        return $_SESSION[$key];
    }

    public function set(string $key, mixed $value): void
    {
        $_SESSION[$key] = $value;
    }

    public function has(string $key): bool
    {
        return isset($_SESSION[$key]);
    }

    public function unset(string $key): void
    {
        unset($_SESSION[$key]);
    }

    public function regenerate(): void
    {
        if (PHP_SAPI === 'cli') {
            return;
        }

        // @codeCoverageIgnoreStart
        session_regenerate_id(true);
        // @codeCoverageIgnoreEnd
    }

    public function flash(
        string $message,
        string $queue = 'default',
    ): void {
        if (!isset($_SESSION[$this->flashMessagesKey])) {
            $_SESSION[$this->flashMessagesKey] = [];
        }

        $_SESSION[$this->flashMessagesKey][] = [
            'message' => htmlspecialchars($message),
            'queue' => htmlspecialchars($queue),
        ];
    }

    public function popFlashes(?string $queue = null): array
    {
        if ($queue === null) {
            $flashes = $_SESSION[$this->flashMessagesKey];
            $_SESSION[$this->flashMessagesKey] = [];
        } else {
            $key = 0;
            $keys = [];
            $flashes = [];

            foreach ($_SESSION[$this->flashMessagesKey] as $flash) {
                if ($flash['queue'] === $queue) {
                    $flashes[] = $flash;
                    $keys[] = $key;
                }

                $key++;
            }

            foreach (array_reverse($keys) as $key) {
                unset($_SESSION[$this->flashMessagesKey][$key]);
            }
        }

        return $flashes;
    }

    public function hasFlashes(?string $queue = null): bool
    {
        if ($queue) {
            return count(array_filter(
                $_SESSION[$this->flashMessagesKey] ?? [],
                fn (array $f) => $f['queue'] === $queue,
            )) > 0;
        }

        return count($_SESSION[$this->flashMessagesKey] ?? []) > 0;
    }

    public function rememberRequestUri(
        int $expires = 3600,
    ): void {
        $_SESSION[$this->rememberedUriKey] = [
            'uri' => Http::fullRequestUri(),
            'expires' => time() + $expires,
        ];
    }

    public function getRememberedUri(): string
    {
        $rememberedUri = $_SESSION[$this->rememberedUriKey] ?? null;

        if ($rememberedUri) {
            if ($rememberedUri['expires'] > time()) {
                $uri = $rememberedUri['uri'];
                unset($_SESSION[$this->rememberedUriKey]);

                if (filter_var($uri, FILTER_VALIDATE_URL)) {
                    return $uri;
                }
            }

            unset($_SESSION[$this->rememberedUriKey]);
        }

        return '/';
    }
}
