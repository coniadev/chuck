<?php

declare(strict_types=1);

namespace Chuck\Model;

use \PDO;

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


class Query
{
    protected $db;
    protected $script;
    protected $stmt;

    public function __construct($db, $script, $params)
    {
        $this->db = $db;
        $this->script = $script;

        if (count($params) > 0) {
            $this->stmt = $this->db->getConn()->prepare($this->script);
            $this->bindParameters($params);
        } else {
            $this->stmt = $this->db->getConn()->query($this->script);
        }

        if ($db->printSql) {
            error_log(
                "\n\n-----------------------------------------------\n\n" .
                    $this->interpolate($script, $params) .
                    "\n------------------------------------------------\n"
            );
        }
    }

    protected function bindParameters(array $params): void
    {
        foreach ($params as $param => $value) {
            $p = ':' . $param;

            switch (gettype($value)) {
                case 'boolean':
                    $this->stmt->bindValue($p, $value, PDO::PARAM_BOOL);
                    break;
                case 'integer':
                    $this->stmt->bindValue($p, $value, PDO::PARAM_INT);
                    break;
                case 'string':
                    $this->stmt->bindValue($p, $value, PDO::PARAM_STR);
                    break;
                case 'NULL':
                    $this->stmt->bindValue($p, $value, PDO::PARAM_NULL);
                    break;
                case 'array':
                    $this->stmt->bindValue($p, '{' . implode(', ', $value) . '}');
                    break;
                default:
                    $this->stmt->bindValue($p, $value);
                    break;
            }
        }
    }

    protected function nullIfNot($value)
    {
        if (is_array($value)) {
            return $value;
        }

        return $value ?: null;
    }

    public function one(
        array|string|null $hashKey = null,
        bool $asUid = false
    ): ?array {
        $this->stmt->execute();
        $result = $this->nullIfNot($this->stmt->fetch($this->db->getFetchMode()));

        if ($hashKey !== null && $result) {
            if (is_array($hashKey)) {
                foreach ($hashKey as $hk) {
                    $result[$hk] = $this->db->encode($result[$hk]);
                }
            } else {
                if ($asUid) {
                    $targetKey = 'uid';
                } else {
                    $targetKey = $hashKey;
                }

                $result[$targetKey] = $this->db->encode($result[$hashKey]);
            }
        }

        return $result;
    }

    public function item(
        array|string|null $hashKey = null,
        bool $asUid = false
    ): ?Item {
        $result = $this->one($hashKey, $asUid);
        if ($result === null) {
            return null;
        }

        return new Item($result);
    }

    public function all(
        array|string|null $hashKey = null,
        bool $asUid = false
    ): ?iterable {
        $this->stmt->execute();
        $result = $this->nullIfNot($this->stmt->fetchAll($this->db->getFetchMode()));

        if ($hashKey !== null && $result) {
            return $this->db->encodeList($result, $hashKey, $asUid);
        }

        return $result;
    }

    public function allFlatList(): ?iterable
    {
        $this->stmt->execute();
        return $this->nullIfNot($this->stmt->fetchAll(\PDO::FETCH_NUM));
    }

    public function items(
        array|string|null $hashKey = null,
        bool $asUid = false
    ): ?iterable {
        $result = $this->all($hashKey, $asUid);
        if ($result === null) {
            return null;
        }

        return array_map(fn ($item) => new Item($item), $result);
    }

    public function run(): bool
    {
        return $this->stmt->execute();
    }

    public function len(): int
    {
        $this->stmt->execute();
        return $this->stmt->rowCount();
    }

    /**
     * Replaces any parameter placeholders in a query with the
     * value of that parameter and returns the query as string.
     */
    public function interpolate($query, $params): string
    {
        // This method only supports named bindings
        $map = [];

        foreach ($params as $key => $value) {
            $key = ':' . $key;

            if (is_string($value)) {
                $map[$key] = "'" . $value . "'";
                continue;
            }

            if (is_array($value)) {
                $map[$key] = '{' . implode("','", $value) . '}';
                continue;
            }

            if (is_null($value)) {
                $map[$key] = 'NULL';
                continue;
            }

            $map[$key] = (string)$value;
        }

        return strtr($query, $map);
    }
}
