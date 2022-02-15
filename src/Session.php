<?php

declare(strict_types=1);

namespace Chuck;

class Session implements SessionInterface
{
    public readonly Csrf $csrf;

    protected RequestInterface $request;
    protected ConfigInterface $config;

    public function __construct(RequestInterface $request)
    {
        // TODO:
        // session_set_cookie_params(['SameSite' => 'Strict']);

        $this->request = $request;
        $this->config = $request->getConfig();
    }

    public function start(): void
    {
        if (!isset($_SESSION)) {
            // If we are run from the command line interface then we do not care
            // about headers sent using the session_start.
            if (PHP_SAPI === 'cli') {
                $_SESSION = [];
            } elseif (!headers_sent()) {
                if ($this->config->get('session')['model'] !== null) {
                    $this->setupCustomSessions();
                }

                session_name($this->config->get('appname'));
                if (!session_start()) {
                    throw new \Exception(__METHOD__ . 'session_start failed.');
                }
            } else {
                throw new \Exception(
                    __METHOD__ . 'Session started after headers sent.'
                );
            }
        }

        $this->csrf = new Csrf($this->request);


        if (!array_key_exists('flash_messages', $_SESSION)) {
            $_SESSION['flash_messages'] = [];
        }
    }

    protected function setupCustomSessions(): void
    {
        $class = $this->config->get('session')['model'];
        $handler = new $class();

        session_set_save_handler(
            [$handler, 'open'],
            [$handler, 'close'],
            [$handler, 'read'],
            [$handler, 'write'],
            [$handler, 'destroy'],
            [$handler, 'gc']
        );
    }

    public function forget(): void
    {
        // Unset all of the session variables.
        $_SESSION = [];

        if (PHP_SAPI === 'cli') {
            return;
        }

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

        // Finally, destroy the session.
        session_destroy();
    }

    public function get($key)
    {
        return $_SESSION[$key] ?? null;
    }

    public function set(string $key, $value)
    {
        $_SESSION[$key] = $value;
    }

    public function flash(string $type, string $message): void
    {
        $_SESSION['flash_messages'][] = [
            'type' => $type,
            'message' => $message
        ];
    }

    public function popFlash(): array
    {
        $flashes = $_SESSION['flash_messages'];
        $_SESSION['flash_messages'] = [];
        return $flashes;
    }

    public function hasFlashes(): bool
    {
        return count($_SESSION['flash_messages'] ?? []) > 0;
    }

    public function regenerate(): void
    {
        if (PHP_SAPI === 'cli') {
            return;
        }

        session_regenerate_id(true);
    }

    public function setUser($userId): void
    {
        $_SESSION['user_id'] = $userId;
    }

    public function authenticatedUserId(): string|int|null
    {
        return $_SESSION['user_id'] ?? null;
    }

    public function rememberReturnTo(): void
    {
        setcookie('return_to', $_SERVER['REQUEST_URI'], time() + 3600, '/');
    }

    public function returnTo(): string
    {
        $returnTo = $_COOKIE['return_to'] ?? '/';
        setcookie('return_to', '',  time() - 3600, '/');

        return $returnTo;
    }

    // public function remember(Token $token, int $expire): void
    // {
    // setcookie(
    // $this->config->get('appname') . '_auth',
    // $token->get(),
    // $expire,
    // '/'
    // );
    // }

    public function forgetRemembered(): void
    {
        setcookie(
            $this->config->get('appname') . '_auth',
            '',
            time() - 60 * 60 * 24
        );
    }

    public function getAuthToken(): ?string
    {
        return $_COOKIE[$this->config->get('appname') . '_auth'] ?? null;
    }
}
