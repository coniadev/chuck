SELECT
*
FROM
members
ORDER BY name
<?php if ($order == 'desc') : ?>
    DESC;
<?php else : ?>
    ASC;
<?php endif ?>
