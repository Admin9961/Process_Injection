Lo script è imperfetto, e ben lontano dal pareggiare Shellter in fatto a capacità, ma offre comunque delle feature interessanti, e può bypassare alcuni antivirus se usato correttamente.

1. Esegue un PE file (.exe) e mappa sul terminal tutte le sezioni, con descrizioni dettagliate;
2. Aggiunge l'.EXE alle eccezioni di DEP e ASLR prima di procedere all'iniezione, interfacciandosi con Powershell (per sfruttare quest'abilità dovrete eseguirlo come Amministratore). Questo step assicurerà che potrete iniettare codice anche in sezioni pazze, completamente indisturbati;
3. Tecnica del PH (Process Hollowing) con WriteProcessMemory;


La sintassi per passargli shellcode come argomento è "python injector.py esempio.exe esempio.bin". Lo shellcode in questione dev'essere presentato sotto forma di raw binary file (.bin) che vi conviene criptare per conto vostro allo scopo di superare almeno l'analisi statica.

TODO:
1. Modificare la descrizione delle sezioni per includere nella descrizione i permessi (RWX) di ciascuna sezione individuata;
2. Includere un metodo che può bypassare l'antivirus in situazioni delicate. Se si pianifica di sfruttare lo script per iniettare una normale reverse shell va bene, ma se si intende iniettare qualcosa di più specifico (come Meterpreter) c'è più lavoro da fare con offuscamento ecc.
3. Implementare un metodo per rendere il risultato dell'injection più silenzioso (ad esempio sopprimere la GUI dell'app originale, un MUST ben noto per ottenere una backdoor di tutto rispetto)

Tuttavia, oltre che a shellcode per trasformare l'app in una backdoor, lo script può essere usato anche a scopi di debugging, perché accetta in input qualsiasi tipo di dati binari. Ovviamente è fornito solo a scopo educativo, non voglio la pula in casa 🚨 🚨 🚨
