## essd sign

Create signed DSSE envelope for an arbitrary payload

```
essd sign [flags]
```

### Options

```
      --canonicalize-json     encode payload using canonical JSON (specified payload MUST be JSON)
  -h, --help                  help for sign
  -k, --key string            path of SSH key to sign with
  -o, --output string         output path to write envelope
  -t, --payload-type string   payload type for DSSE envelope
      --sigstore              sign with Sigstore
```

### SEE ALSO

* [essd](essd.md)	 - A tool to sign, verify, and inspect DSSE envelopes

