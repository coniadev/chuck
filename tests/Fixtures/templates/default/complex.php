<?php require 'header.php'; ?>

<body>
    <h1><?= $this->headline ?></h1>
    <table>
        <?php foreach ($this->array as $key => $value) : ?>
            <tr>
                <td><?= $this->e($key) ?></td>
                <?php foreach ($value as $item) : ?>
                    <td><?= $item ?></td>
                <?php endforeach ?>
            </tr>
        <?php endforeach ?>
    </table><?= $this->html->raw() ?>
</body>

</html>
