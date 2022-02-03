<?php

declare(strict_types=1);

namespace Chuck\Model;


/**
 * Takes an array and allows item property access to its elements.
 */
class Item
{
    private $_data = [];

    public function __construct(public array $arr)
    {
        $this->_data = $arr;
    }

    public function __get(string $name)
    {
        return $this->_data[$name];
    }

    public function __set(string $name, mixed $value)
    {
        $this->_data[$name] = $value;
    }
}
