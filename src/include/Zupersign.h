#include <signer.h>
#include <stdint.h>

#pragma clang assume_nonnull begin

#ifdef __cplusplus
extern "C" {
#endif

enum {
    ZSIGN_PRESERVE_IDENTIFIER = 1 << 0,
    ZSIGN_PRESERVE_ENTITLEMENTS = 1 << 1,
    ZSIGN_PRESERVE_FLAGS = 1 << 2,
};

/// Ad-hoc sign exactly one shallow bundle or Mach-O file, without signing nested
/// code or changing provisioning profiles. Entitlements are an XML plist, or NULL
/// with length zero when not supplied.
///
/// On failure, returns -1 and an error string which the caller must free().
int zsign_sign_adhoc(const char *path,
                     const void * _Nullable entitlements_xml, size_t xml_len,
                     uint32_t preserve_metadata,
                     char * _Nullable * _Nonnull exception);

int zsign_sign(const char *app_directory,
               const void *cert_data,
               size_t cert_len,
               const void *private_key_data,
               size_t private_key_len,
               const entitlements_data_t *entitlements,
               size_t num_entitlements,
               void (*progress)(const void *, double),
               const void *progressContext,
               char * _Nullable * _Nonnull exception);

void *zsign_analyze(const char *path,
                    size_t *out_len,
                    char * _Nullable * _Nonnull exception);

#ifdef __cplusplus
}
#endif

#pragma clang assume_nonnull end
