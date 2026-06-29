# firmina

Un semplice strumento da riga di comando per firmare digitalmente in CADES (.p7m/.p7s) usando le chiavette di firma bit4id di Infocert.

Fa internamente uso di openssl (che dev'essere già installato per funzionare) ma si porta dietro le librerie necessarie per utilizzare le chiavette PKCS#11 e in particolare i driver proprietari per le chiavi bit4id usate da Infocert.

È possibile scaricarlo dentro `~/.local/bin` in modo da averlo nel PATH e usarlo negli script o in qualsiasi terminale.

## Perché?

Il supporto per le firme digitali su Linux non è un granché, gli strumenti che esistono sono pesanti, gestiti da aziende private che vogliono solo sbarrare la spunta del supporto a linux.

## Utilizzo

Molto facile da usare, basta vedere l'output del comando di help:

```
❯ firmina sign --help
Firma un documento in CADES usando una smart key

Usage: firmina sign [OPTIONS] <INPUT_PATH>

Arguments:
  <INPUT_PATH>  File da firmare

Options:
  -p, --pin <PIN>                  Pin della firma
  -o, --output-path <OUTPUT_PATH>  Percorso del file firmato
  -d, --detach                     Se produrre la firma separatamente
  -h, --help                       Print help
```

```
❯ firmina extract --help
Estrai il contenuto di un file p7m

Usage: firmina extract [OPTIONS] <INPUT_PATH>

Arguments:
  <INPUT_PATH>  File da estrarre

Options:
  -o, --output-path <OUTPUT_PATH>  Percorso del file estratto, se non specificato viene messo a fianco dell'originale
  -h, --help                       Print help
```
