<?php

declare(strict_types=1);

namespace Chuck\Model;

use \PDO;

use Chuck\Util\Arrays;


enum ArgType
{
    case Args;
    case Assoc;
}


class Query implements QueryInterface
{
    protected $db;
    protected $script;
    protected $stmt;
    protected $argsType;
    protected $executed = false;

    public function __construct(DatabaseInterface $db, string $script, array $args)
    {
        $this->db = $db;
        $this->script = $script;
        $argsCount = count($args);

        if ($argsCount > 0) {
            $this->stmt = $this->db->getConn()->prepare($this->script);

            if ($argsCount === 1 && is_array($args[0])) {
                if (Arrays::isAssoc($args[0])) {
                    $this->bindArgs($args[0], ArgType::Assoc);
                } else {
                    $this->bindArgs($args[0], ArgType::Args);
                }
            } else {
                $this->bindArgs($args, ArgType::Args);
            }
        } else {
            $this->stmt = $this->db->getConn()->query($this->script);
        }

        if ($db->shouldPrintScript()) {
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
            if ($argType === ArgType::Assoc) {
                $arg = ':' . $a;
            } else {
                $arg = $a + 1; // question mark placeholders ar 1-indexed
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

    protected function nullIfNot(mixed $value): mixed
    {
        if (is_array($value)) {
            return $value;
        }

        return $value ?: null;
    }

    public function one(
        int $fetchMode = null,
    ): ?array {
        $this->db->connect();

        if (!$this->executed) {
            $this->stmt->execute();
            $this->executed = true;
        }

        $result = $this->nullIfNot($this->stmt->fetch($fetchMode ?? $this->db->getFetchMode()));

        return $result;
    }

    public function item(
        int $fetchMode = null,
    ): ?Item {
        $result = $this->one($fetchMode);

        if ($result === null) {
            return null;
        }

        return new Item($result);
    }

    public function all(
        int $fetchMode = null,
    ): iterable {
        $this->db->connect();
        $this->stmt->execute();
        $result = $this->stmt->fetchAll($fetchMode ?? $this->db->getFetchMode());

        return $result;
    }

    public function items(
        int $fetchMode = null,
    ): iterable {
        $result = $this->all($fetchMode);

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
