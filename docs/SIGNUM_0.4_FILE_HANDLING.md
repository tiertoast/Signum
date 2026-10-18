# Signum 0.4-A.3.1 — Signing Workflow & File Handling

## M1 — Diagnosi riproducibile

18 ottobre 2026. Branch `codex/signum-0.4-file-handling` da HEAD effettivo A.3
`22fc4e0` (codice candidata build 3: `68bf61b`). Main `be84a1e`, file review
non tracciato preservato. Worktree verificati senza aprire altri checkout.
Il collaudo DigitalDNA positivo della build 3 è riferito dall'utente.

Baseline rieseguita prima delle modifiche al prodotto: Swift **221/221**, PKCS#11
**40/40**, PAdES Debug **63/63**. Release verificata con configurazione CMake
esplicita: lo script storico test-pades-local.sh imposta sempre Debug, anche
se CMAKE_BUILD_TYPE viene passato come variabile ambiente. Non confondere quel
run con Release; evidenza corretta separata `04a31-baseline-native-release.log`.

Percorso: NSOpenPanel/FileDropResolution → addDocuments MainActor → capture su
Task separata → fclonefileat dal descriptor originale → lettura/hash del clone
privato → DocumentSnapshot → batch → SigningJob. L'originale non è un input della
firma successiva. Il codice già usa descriptor stabili, clone CoW sullo stesso
volume, symlink rifiutati e snapshot 0700/0400. Non usa birthtime come condizione.

**Causa dimostrata del falso positivo:** DocumentSnapshot.unchanged confronta
device/inode/dimensione/mtime/**ctime**. L'ultimo guard di capture attribuisce a
una modifica del documento qualsiasi variazione di questi campi, ma anche errori
di fstat o mancato binding al percorso finiscono nello stesso messaggio.
Un aggiornamento xattr può cambiare solo ctime, lasciando byte e mtime invariati.

Test deterministico `FileAcquisitionTests.testMetadataOnlyChangeDoesNotRejectCoherentPDF`:
al primo read del clone, fsetxattr sul descriptor dell'originale. Assert su
dimensione/mtime invariati e ctime variato, poi verifica byte originali/snapshot.
**Eseguito sulla baseline del prodotto: 1 test, 1 fallimento**, proprio con
«Il documento è cambiato durante l'acquisizione». Nessun sleep casuale o file
personale. Log `04a31-m1-reproduction.log`. Il commit M1 contiene intenzionalmente
questa regressione ancora rossa, prima del fix M2.

Questa è una causa riprodotta, non una prova che Spotlight/quarantena/browser
abbiano modificato i metadati dei PDF del collaudo. Quei file non sono stati letti.
Limiti individuati separatamente: CAdES 16 MiB, PAdES 64 MiB, sessione 128 MiB;
IPC firma trasporta attributi/digest e certificato, non l'intero documento.
Il clone è su disco ma DocumentSnapshot conserva anche una Data completa; CMS
costruisce ulteriori Data. Non basta alzare una costante per promettere 200 MiB.
