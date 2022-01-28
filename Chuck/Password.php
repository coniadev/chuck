<?php

declare(strict_types=1);

namespace Chuck;

class Password
{
    public function __construct(array $values)
    {
        $this->password = trim($values['password'] ?? '');
        $this->repeat = trim($values['password_repeat'] ?? '');
        $this->fullName = trim($values['full_name']);
        $this->displayName = trim($values['display_name'] ?? '');
        $this->email = trim($values['email']);
        $this->error = null;
    }

    public function isSet(): bool
    {
        return !empty($this->password) || !empty($this->repeat);
    }

    public function valid(): bool
    {
        if (
            $this->password === $this->fullName
            || $this->password === $this->displayName
            || $this->password === $this->email
        ) {
            $this->error = _('-password-same-name-error-');
            return false;
        }

        if ($this->password !== $this->repeat) {
            $this->error = _('-password-repeat-match-error-');
            return false;
        }

        if (Util::entropy($this->password) < 40.0) {
            $this->error = _('-weak-password-');
            return false;
        }

        return true;
    }

    public function encrypt(): string
    {
        return password_hash($this->password, PASSWORD_ARGON2ID);
    }

    public function getError(): ?string
    {
        return $this->error;
    }
}
