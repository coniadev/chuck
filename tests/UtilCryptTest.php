<?php

declare(strict_types=1);

use Chuck\Tests\Setup\TestCase;
use Chuck\Util\Crypt;

uses(TestCase::class);


test('Encryption and decryption', function () {
    expect(Crypt::decrypt(
        Crypt::encrypt('Symbolic', 'secret-key'),
        'secret-key'
    ))->toBe('Symbolic');
});


test('Encryption and decryption with alternate algo', function () {
    expect(Crypt::decrypt(
        Crypt::encrypt('Symbolic', 'secret-key', 'aes-256-cbc'),
        'secret-key',
        'aes-256-cbc'
    ))->toBe('Symbolic');
});


test('Failing encryption', function () {
    Crypt::encrypt('Symbolic', 'secret-key', 'wrong-algo');
})->throws(ValueError::class, 'Cipher algorithm');


test('Failing decryption', function () {
    Crypt::decrypt('Symbolic', 'secret-key', 'wrong-algo');
})->throws(ValueError::class, 'Cipher algorithm');
