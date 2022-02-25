<?php

declare(strict_types=1);

use Chuck\Tests\Setup\TestCase;
use Chuck\Util\Password;

uses(TestCase::class);


test('Password strength', function () {
    $pw = new Password();

    expect($pw->strongEnough('1'))->toBe(false);
    expect($pw->strongEnough('abcdef'))->toBe(false);
    expect($pw->strongEnough('evil-chuck-666'))->toBe(true);
});


test('Password hash (default argon2)', function () {
    $pw = new Password();

    expect(str_starts_with($pw->hash('evil-chuck-666'), '$argon2id$v'))->toBe(true);
});


test('Password verify', function () {
    $pw = new Password();
    $hash = $pw->hash('evil-chuck-666');

    expect($pw->valid('evil-chuck-666', $hash))->toBe(true);
    expect($pw->valid('evil-chuck-660', $hash))->toBe(false);
});


test('Password init from config', function () {
    $hasArgon = Password::hasArgon2();

    if ($hasArgon) {
        $pw = Password::fromConfig($this->config());
        expect(str_starts_with($pw->hash('evil-chuck-666'), '$argon2id$v'))->toBe(true);
    }

    $pw = Password::fromConfig($this->config([
        'password.algorithm' => PASSWORD_BCRYPT,
    ]));
    expect(str_starts_with($pw->hash('evil-chuck-666'), '$2y$'))->toBe(true);
});
