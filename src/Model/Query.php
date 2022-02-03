<?php

declare(strict_types=1);

namespace Chuck\Model;

use \PDO;

use Chuck\Util\Arrays;


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

enum ArgType
{
    case Args;
    case Assoc;
}


class Query
{
    protected $db;
    protected $script;
    protected $stmt;
    protected $argsType;

    public function __construct($db, $script, $args)
    {
        $this->db = $db;
        $this->script = $script;
        $argsCount = count($args);

        if ($argsCount > 0) {
            $this->stmt = $this->db->getConn()->prepare($this->script);

            if ($argsCount === 1 && Arrays::isAssoc($args[0])) {
                $this->bindArgs($args[0], ArgType::Assoc);
            } else {
                $this->bindArgs($args, ArgType::Args);
            }
        } else {
            $this->stmt = $this->db->getConn()->query($this->script);
        }

        if ($db->printSql) {
            error_log(
                "\n\n-----------------------------------------------\n\n" .
                    $this->interpolate($script, $args) .
                    "\n------------------------------------------------\n"
            );
        }
    }

    protected function bindArgs(array $args, ArgType $argType): void
    {
        foreach ($args as $a => $value) {
            if ($argType = ArgType::Assoc) {
                $arg = ':' . $a;
            }

            switch (gettype($value)) {
                case 'boolean':
                    $this->stmt->bindValue($arg, $value, PDO::PARAM_BOOL);
                    break;
                case 'integer':
                    $this->stmt->bindValue($arg, $value, PDO::PARAM_INT);
                    break;
                case 'string':
                    $this->stmt->bindValue($arg, $value, PDO::PARAM_STR);
                    break;
                case 'NULL':
                    $this->stmt->bindValue($arg, $value, PDO::PARAM_NULL);
                    break;
                case 'array':
                    $this->stmt->bindValue($arg, '{' . implode(', ', $value) . '}');
                    break;
                default:
                    $this->stmt->bindValue($arg, $value);
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
        bool $asUid = false,
        int $fetchMode = null,
    ): ?array {
        $fetchMode = $fetchMode ?? $this->db->getFetchMode();

        $this->db->connect();
        error_log(print_r($this->stmt, true));
        $this->stmt->execute();
        $result = $this->nullIfNot($this->stmt->fetch($fetchMode));

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
        bool $asUid = false,
        int $fetchMode = null,
    ): ?Item {
        $result = $this->one($hashKey, $asUid, $fetchMode);

        if ($result === null) {
            return null;
        }

        return new Item($result);
    }

    public function all(
        array|string|null $hashKey = null,
        bool $asUid = false,
        int $fetchMode = null,
    ): ?iterable {
        $fetchMode = $fetchMode ?? $this->db->getFetchMode();

        $this->db->connect();
        $this->stmt->execute();
        $fetchMode = $this->db->getFetchMode();
        $result = $this->nullIfNot($this->stmt->fetchAll($fetchMode));

        if ($hashKey !== null && $result) {
            return $this->db->encodeList($result, $hashKey, $asUid);
        }

        return $result;
    }

    public function allFlatList(): ?iterable
    {
        $this->db->connect();
        $this->stmt->execute();
        return $this->nullIfNot($this->stmt->fetchAll(\PDO::FETCH_NUM));
    }

    public function items(
        array|string|null $hashKey = null,
        bool $asUid = false,
        int $fetchMode = null,
    ): ?iterable {
        $result = $this->all($hashKey, $asUid, $fetchMode);
        if ($result === null) {
            return null;
        }

        foreach ($result as $item) {
            yield new Item($item);
        }
    }

    public function run(): bool
    {
        $this->db->connect();
        return $this->stmt->execute();
    }

    public function len(): int
    {
        $this->db->connect();
        $this->stmt->execute();
        return $this->stmt->rowCount();
    }

    /**
     * Replaces any parameter placeholders in a query with the
     * value of that parameter and returns the query as string.
     */
    public function interpolate($query, $args): string
    {
        // This method only supports named bindings
        $map = [];

        foreach ($args as $key => $value) {
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
