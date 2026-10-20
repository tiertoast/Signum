#include <stdint.h>
#include <stddef.h>
// Packed DER: big-endian uint32 length, DER, repeated. First entry is the leaf.
// No system store, filesystem lookup, network, AIA or revocation access.
// disposition: 1 verified; 0 insufficient/unsupported; -1 definite invalidity.
int signum_path_validate(const uint8_t *packed, size_t packed_length,
                         const uint8_t *anchor, size_t anchor_length, int64_t when,
                         char *path_hashes, size_t path_capacity, char *reason, size_t reason_capacity);
