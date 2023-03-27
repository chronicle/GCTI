rule BruteRatel_badger
{
  strings:
       //mov eax, 0x00
       // push eax
       //mov eax, 0x00
       // push eax
       //mov eax, 0x00
       // push eax
       //mov eax, 0x00
       // push eax
       //mov eax, 0x00
       // push eax
       //mov eax, 0x00
       // push eax
       $code = { B8 00 00 00 00 50 B8 00 00 00 00 50 B8 00 00 00 00 50 B8 00 00 00 00 50 B8 00 00 00 00 50 B8 00 00 00 00 50}
  condition:
      all of them
}
