rule bibtex 
{
  meta:
    description = "Detects sus code"
  strings:
    $a = "@article{"
    $b = "@book{"
    $d = "@conference{"
    $e = "@inbook{"
    $f = "@incollection{"
    $g = "@inproceedings{"
    $h = "@manual{"
    $i = "@masterthesis{"
    $j = "@misc{"
    $k = "@phdthesis{"
    $l = "@proceedings{"
    $m = "@techreport{"
    $n = "@unpublished{"
  condition:
      any of them
}
