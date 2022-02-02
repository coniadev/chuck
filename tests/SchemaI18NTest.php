<?php

declare(strict_types=1);

use Chuck\SchemaI18N;


test('Translated value', function () {
    $testData = [
        'de' => [
            'text' => 'the13',
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
