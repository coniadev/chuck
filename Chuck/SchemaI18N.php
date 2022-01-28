<?php

declare(strict_types=1);

namespace Chuck;


abstract class SchemaI18N implements SchemaInterface
{
    protected array $rules = [];
    protected array $errorList = [];
    protected array $errorMap = [];
    protected array $values = [];
    protected array $pristineValues = [];

    public function __construct(
        protected bool $list = false,
        protected bool $keepUnknown = false,
        protected array $langs = [],
        protected ?string $title = null,
    ) {
    }

    protected function add(
        string $field,
        string $label,
        string|SchemaInterface $type,
        string ...$validators
    ) {
        if (!$field) {
            throw new \ErrorException(
                'Schema definition error: field must not be empty'
            );
        }

        $this->rules[] = [
            'field' => $field,
            'type' => $type,
            'label' => $label,
            'validators' => $validators,
        ];
    }

    public function validate(?array $data): bool
    {
        $this->errorList = [];
        $this->errorMap = [];
        $this->rules = [];
        $this->values = [];
        $this->pristineValues = [];

        $this->rules();

        if (count($this->langs) === 0) {
            throw new \ErrorException(
                'There must be at least one language defined in SchemaI18N objects'
            );
        }

        foreach ($this->langs as $lang) {
            $schema = new class(
                list: $this->list,
                keepUnknown: $this->keepUnknown,
                langs: $this->langs,
                title: $this->title,
            ) extends \Chuck\Schema
            {
                public static array $staticRules = [];

                protected function rules(): void
                {
                    foreach (self::$staticRules as $rule) {
                        $this->add(
                            $rule['field'],
                            $rule['label'],
                            $rule['type'],
                            ...$rule['validators']
                        );
                    }
                }
            };

            foreach ($this->rules as $rule) {
                $schema::$staticRules[] = $rule;
            }

            // Add the language id (de, en, etc.) to the error message
            if (!$schema->validate($data[$lang])) {
                $errors = $schema->errors();

                foreach ($errors['errors'] as $error) {
                    $error['error'] = $error['error'] . " ($lang)";
                    $this->errorList[] = $error;
                }


                foreach ($errors['map'] as $field => $mapErrors) {
                    $innerResult = [];

                    foreach ($mapErrors as $mapError) {
                        $innerResult[] = $mapError . " ($lang)";
                    }

                    $this->errorMap = array_merge_recursive(
                        $this->errorMap,
                        [$field => $innerResult],
                    );
                }
            }

            $this->values[$lang] = $schema->values();
            $this->pristineValues[$lang] = $schema->pristineValues();
        }

        return count($this->errorList) === 0;
    }

    public function errors(bool $grouped = false): array
    {
        $result = [
            'isList' => $this->list,
            'errors' => array_values($this->errorList),
            'map' => $this->errorMap,
        ];

        return $result;
    }

    protected function rules(): void
    {
        // Must be implemented in child classes
        throw new \ErrorException('not implemented');
    }

    public function values(): array
    {
        return $this->values;
    }

    public function pristineValues(): array
    {
        return $this->pristineValues;
    }
}
