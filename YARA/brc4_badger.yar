rule brc4_badger
{
meta:
    description = "Identifies strings from Brute Ratel v1.1"
strings:
    $a = "\"chkin\":"
    $b = "\"kimche\":"
condition:
    $a or $b
}
