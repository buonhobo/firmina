Si tratta di un semplice wrapper su openssl che include al suo interno le librerie necessarie per utilizzare le chiavette di firma bit4id di infocert. Io ho solo questo tipo di chiave e non ho potuto provare con nessun'altra.

E' possibile scaricare l'eseguibile e metterlo in ~/.local/bin per poter usare firmina dal terminale in qualsiasi momento

**openssl deve essere installato per far funzionare il programma.**

Molto facile da usare, basta vedere l'output del comando di help:

```
❯ firmina --help
Usage: firmina [OPTIONS] <INPUT_PATH>

Arguments:
  <INPUT_PATH>  File da firmare

Options:
  -p, --pin <PIN>                  Pin della firma
  -o, --output-path <OUTPUT_PATH>  Percorso del file firmato
  -d, --detach                     Se produrre la firma separatamente
  -h, --help                       Print help
```

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
