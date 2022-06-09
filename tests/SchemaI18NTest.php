<?php

declare(strict_types=1);

use Chuck\SchemaI18N;


test('Translated valid values', function () {
    $testData = [
        'de' => [
            'text' => 'die13',
            'int' => 13,
            'required' => 'vorhanden',
        ],
        'en' => [
            'text' => 'the23',
            'int' => '23',
            'required' => 'present',
        ]
    ];

    $schema = new class(langs: ['de', 'en']) extends SchemaI18N
    {
        protected function rules(): void
        {
            $this->add('int', 'Int', 'int');
            $this->add('text', 'Text', 'text');
            $this->add('required', 'Required', 'text', 'required');
        }
    };

    expect($schema->validate($testData))->toBeTrue();
    $errors = $schema->errors();
    expect($errors['errors'])->toHaveCount(0);
    expect($errors['map'])->toHaveCount(0);
    $values = $schema->values();
    $pristine = $schema->pristineValues();
    expect($values['en']['int'])->toBe(23);
    expect($pristine['en']['int'])->toBe('23');
});


test('Translated failing values', function () {
    $testData = [
        'de' => [
            'text' => 'die13',
            'int' => 13,
        ],
        'en' => [
            'text' => 'the13',
            'int' => 'error',
        ]
    ];

    $schema = new class(langs: ['de', 'en']) extends SchemaI18N
    {
        protected function rules(): void
        {
            $this->add('int', 'Int', 'int');
            $this->add('text', 'Text', 'text');
            $this->add('required', 'Required', 'text', 'required');
        }
    };

    expect($schema->validate($testData))->toBeFalse();
    $errors = $schema->errors();
    expect($errors['errors'])->toHaveCount(3);
    expect($errors['map'])->toHaveCount(2);
    expect($errors['map']['int'][0])->toEqual('-schema-invalid-integer-Int- (en)');
    expect($errors['map']['required'][0])->toEqual('-schema-required-Required- (de)');
    expect($errors['map']['required'][1])->toEqual('-schema-required-Required- (en)');
});


test('Empty field name', function () {
    $schema = new class(langs: ['de', 'en']) extends SchemaI18N
    {
        protected function rules(): void
        {
            $this->add('', 'Int', 'int');
        }
    };
    $schema->validate([]);
})->throws(ValueError::class, 'must not be empty');


test('Empty languages array', function () {
    $schema = new class(langs: []) extends SchemaI18N
    {
        protected function rules(): void
        {
            $this->add('int', 'Int', 'int');
        }
    };
    $schema->validate([]);
})->throws(ValueError::class, 'at least one language');


test('Overwritten ::rules missing', function () {
    $schema = new class(langs: []) extends SchemaI18N
    {
    };
    $schema->validate([]);
})->throws(RuntimeException::class, 'not implemented');
