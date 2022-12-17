<?php

declare(strict_types=1);

namespace Conia\Chuck;

use OutOfBoundsException;
use RuntimeException;
use Conia\Chuck\Util\Uri;

class Session implements SessionInterface
{
    /**
     * @param non-empty-string $flashMessagesKey
     * @param non-empty-string $rememberedUriKey
     */
    public function __construct(
        protected string $name,
        protected string $flashMessagesKey = 'flash_messages',
        protected string $rememberedUriKey = 'remembered_uri',
    ) {
    }

    public function start(): void
    {
        if (session_status() === PHP_SESSION_NONE) {
            if (!headers_sent($file, $line)) {
                session_name($this->name);

                if (!session_start()) {
                    // @codeCoverageIgnoreStart
                    throw new RuntimeException(__METHOD__ . 'session_start failed.');
                    // @codeCoverageIgnoreEnd
                }
            } else {
                // Cannot be provoked in the test suit
                // @codeCoverageIgnoreStart
                throw new RuntimeException(
                    __METHOD__ . 'Session started after headers sent. File: ' .
                        $file . ' line: ' . $line
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

        // Finally, destroy the session.
        session_destroy();
    }

    /**
     * @param non-empty-string $key
     */
    public function get(string $key, mixed $default = null): mixed
    {
        if ($this->has($key)) {
            return $_SESSION[$key];
        } else {
            if (func_num_args() > 1) {
                return $default;
            }

            throw new OutOfBoundsException(
                "The session key '$key' does not exist"
            );
        }
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
        if (session_status() == PHP_SESSION_ACTIVE) {
            // The session is always inactive when PHP_SAPI === 'cli'
            // e. g. when tests are run
            // @codeCoverageIgnoreStart
            session_regenerate_id(true);
            // @codeCoverageIgnoreEnd
        }
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
            'uri' => Uri::url(),
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
