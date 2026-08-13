# P4-C durable checkpoint confidentiality and secret minimization

## Security property

The default agent must not persist content-bearing LangGraph checkpoint state or pending writes as readable plaintext in its local checkpoint database. A copied checkpoint database without the local synthetic encryption key must not reveal user messages, tool arguments, tool results, or pending-write values. Content-bearing values must remain inside authenticated encryption envelopes, while only structural storage metadata remains plaintext.

P4-C composes with the earlier checkpoint controls rather than replacing them: P4-A still constrains Python type reconstruction, and P4-B still authenticates checkpoint rows, pending writes, and the monotonic chain. P4-C encrypts serialized checkpoint and pending-write payloads before P4-B integrity digests are computed.

## Trust boundary

The default API constructs `ConfidentialDurableIntegrityCheckpointer`. Its serializer first applies the P4-A strict serializer and then wraps the serialized bytes with local AES-256-GCM. The P4-B SQLite saver stores ciphertext and authenticates that ciphertext with its existing local HMAC/anchor mechanism. On load, P4-B integrity and rollback checks run before the P4-C serializer decrypts and hands plaintext bytes to the strict P4-A deserializer.

The local AES-GCM key and key identifier are synthetic lab material. The key is not held by KMS, HSM, a secret manager, or an independent trust domain. Structural fields needed to address and order rows remain plaintext, including thread/checkpoint identifiers, generations, type tags, task identifiers, channels, and integrity digests. LangGraph control metadata also remains plaintext and is subject to a structural key-name guard that rejects content-bearing metadata names such as message, prompt, password, token, credential, arguments, and tool result.

## Adversarial cases

P4-C evaluates three local file-disclosure paths against the P4-B integrity-only baseline and the encrypted default boundary: checkpoint payload plaintext disclosure, pending-write plaintext disclosure, and attempts to place sensitive content under a plaintext metadata key. The hardened path also verifies that reopening with the wrong encryption key fails closed and that legacy P4-B plaintext checkpoint rows are not silently accepted as P4-C ciphertext.

## Benign cases

The evaluation verifies a legitimate durable reopen with the exact P4-A application types preserved and a legitimate LangGraph interrupt/resume after constructing a new encrypted saver and graph instance. These cases ensure the confidentiality boundary does not disable normal local checkpoint persistence.

## Residual risk and non-claims

P4-C is a local synthetic confidentiality control, not a production encryption-at-rest certification. An attacker who obtains the repository/process and therefore the embedded synthetic AES-GCM key can decrypt checkpoint payloads. Structural SQLite metadata and LangGraph control metadata remain plaintext. The metadata guard is structural minimization, not general DLP, and cannot prove that every innocently named metadata value is nonsensitive. SQLite file remnants, backups, operating-system paging, crash dumps, process memory, logs outside this checkpoint database, and other stores are outside this control.

Production deployment would still require externalized key custody and rotation, controlled migration/re-encryption, backup encryption, storage permissions, process isolation, key revocation procedures, and operational recovery design. P4-C performs no network requests and introduces no real external operations.
