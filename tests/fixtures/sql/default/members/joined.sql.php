SELECT
member, -- :year
<?php if ($interestedInNames ?? false) : ?>
    name,
<?php endif ?>
<?php if ($testPrinting ?? false) : ?>
    'Mantas '' --' AS mantas, -- :year
    name AS secondName,
    /*
    * Flattening Of Emotions :year
    */
    ' :year
    Secret Face :year
    Human ' AS secret, -- :year

<?php endif ?>
left,
joined
FROM members WHERE joined = :year
ORDER BY member;
