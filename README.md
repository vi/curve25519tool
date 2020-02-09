# curve25519tool
Command-line tool to use curve25519-donna library

Allows to generate private and public keys, derive shared keys (without the hashing step), sign and verify signatures.

There are pre-built executables on Github Releases.

```
$ curve25519tool --help
Usage: curve25519tool <command> [<args>]

Use curve25519 and ed25519 from command line

Options:
  --help            display usage information

Commands:
  gen               Generate new private curve25519 key and print it
                    as hex to stdout
  massage           Set and clear bits from a 32-byte hex string specified on
                    stdin for it to be suitable x25519 private key
  pub               Read private key from stdin and print public key to stdout.
  base              Print basepoint (9) as hex.
  mul               Read private key from stdin and public key from command line
                    argument, then print shared key as hex to stdout
  sign              Sign stdin data using private key read from specified file
  verify            Verify signature of data supplied to stdin

$ curve25519tool gen
6071c98d7db4d7fead9b9409c06aa39d691c6065d584d2bc2127fb5ecfa18d64

$ echo 6071c98d7db4d7fead9b9409c06aa39d691c6065d584d2bc2127fb5ecfa18d64 | curve25519tool pub
f36adf3861d5b0e8ea1e999368f4a558832ed8b4b44accc337848ec847bf5779

$ echo 6071c98d7db4d7fead9b9409c06aa39d691c6065d584d2bc2127fb5ecfa18d64 | curve25519tool mul 0900000000000000000000000000000000000000000000000000000000000000
f36adf3861d5b0e8ea1e999368f4a558832ed8b4b44accc337848ec847bf5779
```

Currently signing slightly differs from a typical ed25519:

* Randomness is not derived from a hash of a seed. It can be specified explicitly. Private curve25519 point is used explicitly instead of deriving one from a hash
* Typically unused highest bit of a signature stores sign bit to help to convert curve25519 pubkey to a ed25519 pubkey.
