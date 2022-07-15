<?php

declare(strict_types=1);

use Conia\Chuck\File;
use Conia\Chuck\Tests\Setup\{TestCase, C};

uses(TestCase::class);


beforeEach(function () {
    $this->tmpFile = C::tmp() . 'chuck-test-file.php';
    $this->tmpFileNewName = C::tmp() . 'chuck-new-test-file.php';
    @unlink($this->tmpFile);
    @unlink($this->tmpFileNewName);
});


afterEach(function () {
    @unlink($this->tmpFile);
    @unlink($this->tmpFileNewName);
});


test('Instantiation', function () {
    $this->setupFile();
    $file = new File($_FILES['myfile']);

    expect(str_ends_with($file->tmpName, 'TestCase.php'))->toBe(true);
    expect($file->name)->toBe('chuck-test-file.php');
    expect($file->size)->toBe(123);
    expect($file->error)->toBe(UPLOAD_ERR_OK);
    expect($file->type)->toBe('text/plain');
});


test('Instantiation failing', function () {
    $this->setupFiles(); // Uploaded as HTML array
    new File($_FILES['myfile']);
})->throws(RuntimeException::class, 'HTML array');


test('Validation', function () {
    $this->setupFile();
    $file = new File($_FILES['myfile']);

    expect($file->isValid())->toBe(true);

    $file = new File($_FILES['failingfile']);

    expect($file->isValid())->toBe(false);
});


test('Move with force', function () {
    $this->setupFile();
    $file = new File($_FILES['myfile']);

    expect($file->move(C::tmp()))->toBe($this->tmpFile);
    expect($file->move($this->tmpFile))->toBe($this->tmpFile);
    expect($file->move($this->tmpFileNewName))->toBe($this->tmpFileNewName);

    $file = new File($_FILES['failingfile']);

    expect($file->isValid())->toBe(false);
});


test('Move without force', function () {
    $this->setupFile();
    $file = new File($_FILES['myfile']);

    touch($this->tmpFile);
    $file->move(C::tmp(), false);
})->throws(RuntimeException::class, 'File already exists');


test('Move failing file', function () {
    $this->setupFile();
    $file = new File($_FILES['failingfile']);

    $file->move(C::tmp());
})->throws(RuntimeException::class, 'file is invalid');
