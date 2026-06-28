Si tratta di un semplice wrapper su openssl che include al suo interno le librerie necessarie per utilizzare le chiavette di firma bit4id di infocert. Io ho solo questo tipo di chiave e non ho potuto provare con nessun'altra.

openssl deve essere installato per far funzionare il programma.

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

- L'unico parametro obbligatorio e' il percorso del file fa firmare.
- Il PIN puo' essere inserito subito, altrimenti verra' richiesto dal programma.
- `--detach` permette di produrre la firma con un .p7s invece di un .p7m, la differenza e' che il .p7s non include il file originale al suo interno.
- `--output-path` permette di specificare il percorso del file criptato. Se non e' specificato allora il file sara' piazzato a fianco dell'originale, con .p7m (oppure .p7s) aggiunto alla fine.
