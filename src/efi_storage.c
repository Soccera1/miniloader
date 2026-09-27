/* SPDX-License-Identifier: GPL-3.0-or-later */
#include "ml_uefi.h"
#if ML_ENABLE_TPM12
#include "ml_tpm12.h"
#endif

#define CONFIG_PATH "\\boot\\miniloader.conf"

static EFI_STATUS storage_read_max(ml_uefi_volume *volume, const char *path,
                                   UINT64 max_size, VOID **buffer, UINTN *size);

#if ML_ENABLE_TPM12
typedef struct ml_efi_tcg_protocol ml_efi_tcg_protocol;
struct ml_efi_tcg_protocol {
    VOID *StatusCheck;
    VOID *HashAll;
    VOID *LogEvent;
    EFI_STATUS (EFIAPI *PassThroughToTpm)(ml_efi_tcg_protocol *This,
        UINT32 InputParameterBlockSize, UINT8 *InputParameterBlock,
        UINT32 OutputParameterBlockSize, UINT8 *OutputParameterBlock);
    VOID *HashLogExtendEvent;
};

static EFI_GUID ml_efi_tcg_protocol_guid = {
    0xf541796d, 0xa62e, 0x4954,
    { 0xa7, 0x75, 0x95, 0x84, 0xf6, 0x1b, 0x9c, 0xdd }
};

static int firmware_tpm12_submit(void *context,
                                 const UINT8 *command, size_t command_size,
                                 UINT8 *response, size_t response_capacity,
                                 size_t *response_size)
{
    ml_efi_tcg_protocol *protocol = (ml_efi_tcg_protocol *)context;
    EFI_STATUS status;
    UINT32 declared_size;
    if (!protocol || !protocol->PassThroughToTpm || !command || !response ||
        !response_size || command_size > UINT32_MAX ||
        response_capacity > UINT32_MAX) return 0;
    SetMem(response, (UINTN)response_capacity, 0);
    status = protocol->PassThroughToTpm(protocol, (UINT32)command_size,
        (UINT8 *)command, (UINT32)response_capacity, response);
    if (EFI_ERROR(status)) return 0;
    declared_size = ((UINT32)response[2] << 24) |
                    ((UINT32)response[3] << 16) |
                    ((UINT32)response[4] << 8) | response[5];
    if (declared_size < 10 || declared_size > response_capacity) return 0;
    *response_size = declared_size;
    return 1;
}
#endif

#if ML_ENABLE_TPM2
typedef struct ml_efi_tcg2_protocol ml_efi_tcg2_protocol;
struct ml_efi_tcg2_protocol {
    VOID *GetCapability;
    VOID *GetEventLog;
    VOID *HashLogExtendEvent;
    EFI_STATUS (EFIAPI *SubmitCommand)(ml_efi_tcg2_protocol *This,
        UINT32 InputParameterBlockSize, UINT8 *InputParameterBlock,
        UINT32 OutputParameterBlockSize, UINT8 *OutputParameterBlock);
};

static EFI_GUID ml_efi_tcg2_protocol_guid = {
    0x607f766c, 0x7455, 0x42be,
    { 0x93, 0x0b, 0xe4, 0xd7, 0x6d, 0xb2, 0x72, 0x0f }
};

static int firmware_tpm2_submit(void *context,
                                const UINT8 *command, size_t command_size,
                                UINT8 *response, size_t response_capacity,
                                size_t *response_size)
{
    ml_efi_tcg2_protocol *protocol =
        (ml_efi_tcg2_protocol *)context;
    UINT32 output_size;
    EFI_STATUS status;
    if (!protocol || !protocol->SubmitCommand || !command || !response ||
        !response_size || command_size > UINT32_MAX ||
        response_capacity > UINT32_MAX) return 0;
    SetMem(response, (UINTN)response_capacity, 0);
    status = protocol->SubmitCommand(protocol, (UINT32)command_size,
        (UINT8 *)command, (UINT32)response_capacity, response);
    if (EFI_ERROR(status)) return 0;
    output_size = ((UINT32)response[2] << 24) |
                  ((UINT32)response[3] << 16) |
                  ((UINT32)response[4] << 8) | response[5];
    if (output_size < 10 || output_size > response_capacity) return 0;
    *response_size = output_size;
    return 1;
}
#endif

static EFI_GUID file_info_guid = EFI_FILE_INFO_ID;

static UINTN ascii_length(const char *text)
{
    UINTN n = 0;
    while (text[n]) n++;
    return n;
}

static int ascii_equal(const char *a, const char *b)
{
    UINTN i = 0;
    while (a[i] && b[i]) {
        CHAR8 ca = a[i], cb = b[i];
        if (ca >= 'A' && ca <= 'Z') ca = (CHAR8)(ca + ('a' - 'A'));
        if (cb >= 'A' && cb <= 'Z') cb = (CHAR8)(cb + ('a' - 'A'));
        if (ca != cb) return 0;
        i++;
    }
    return a[i] == b[i];
}

static void guid_char(UINT16 value, CHAR16 *out, UINTN *position, UINTN digits)
{
    static const CHAR16 hex[] = L"0123456789abcdef";
    UINTN i;
    for (i = 0; i < digits; ++i) {
        UINTN shift = (digits - i - 1) * 4;
        out[(*position)++] = hex[(value >> shift) & 0xf];
    }
}

static void guid_char32(UINT32 value, CHAR16 *out, UINTN *position, UINTN digits)
{
    static const CHAR16 hex[] = L"0123456789abcdef";
    UINTN i;
    for (i = 0; i < digits; ++i) {
        UINTN shift = (digits - i - 1) * 4;
        out[(*position)++] = hex[(value >> shift) & 0xf];
    }
}

static void partition_guid(EFI_HANDLE handle, CHAR16 out[37])
{
    EFI_DEVICE_PATH_PROTOCOL *node = NULL;
    EFI_STATUS status;
    out[0] = L'\0';
    status = BS->HandleProtocol(handle, &gEfiDevicePathProtocolGuid, (VOID **)&node);
    if (EFI_ERROR(status) || !node) return;
    while (node->Type != END_DEVICE_PATH_TYPE || node->SubType != END_ENTIRE_DEVICE_PATH_SUBTYPE) {
        UINTN length = (UINTN)node->Length[0] | ((UINTN)node->Length[1] << 8);
        if (length < sizeof(EFI_DEVICE_PATH_PROTOCOL)) return;
        if (node->Type == MEDIA_DEVICE_PATH && node->SubType == MEDIA_HARDDRIVE_DP &&
            length >= sizeof(HARDDRIVE_DEVICE_PATH)) {
            HARDDRIVE_DEVICE_PATH *hd = (HARDDRIVE_DEVICE_PATH *)node;
            if (hd->SignatureType == SIGNATURE_TYPE_GUID && hd->MBRType == MBR_TYPE_EFI_PARTITION_TABLE_HEADER) {
                EFI_GUID guid;
                UINTN p = 0, i;
                CopyMem(&guid, hd->Signature, sizeof(guid));
                guid_char32(guid.Data1, out, &p, 8); out[p++] = L'-';
                guid_char(guid.Data2, out, &p, 4); out[p++] = L'-';
                guid_char(guid.Data3, out, &p, 4); out[p++] = L'-';
                for (i = 0; i < 2; ++i) guid_char(guid.Data4[i], out, &p, 2);
                out[p++] = L'-';
                for (i = 2; i < 8; ++i) guid_char(guid.Data4[i], out, &p, 2);
                out[p] = L'\0';
                return;
            }
        }
        if (node->Type == END_DEVICE_PATH_TYPE) return;
        node = (EFI_DEVICE_PATH_PROTOCOL *)((UINT8 *)node + length);
    }
}

static int uuid_matches(const CHAR16 *guid, const char *uuid)
{
    UINTN i = 0;
    if (!guid[0]) return 0;
    if (uuid[0] == 'p' && uuid[1] == 'a' && uuid[2] == 'r' && uuid[3] == 't' &&
        uuid[4] == 'u' && uuid[5] == 'u' && uuid[6] == 'i' && uuid[7] == 'd' && uuid[8] == ':')
        uuid += 9;
    while (guid[i] && uuid[i]) {
        CHAR16 c = guid[i];
        char d = uuid[i];
        if (c >= L'A' && c <= L'Z') c = (CHAR16)(c + (L'a' - L'A'));
        if (d >= 'A' && d <= 'Z') d = (char)(d + ('a' - 'A'));
        if (c != (CHAR16)(UINT8)d) return 0;
        i++;
    }
    return guid[i] == L'\0' && uuid[i] == '\0';
}

#if ML_ENABLE_FS_XFS || ML_ENABLE_FS_EXT2 || ML_ENABLE_FS_EXT4 || ML_ENABLE_FS_VFAT || ML_ENABLE_FS_BTRFS || ML_ENABLE_FS_ZFS || ML_ENABLE_LVM || ML_ENABLE_LUKS1 || ML_ENABLE_LUKS2
static void copy_storage_message(ml_config_error *parse_error,
                                 const char *message)
{
    UINTN length;
    if (!parse_error || !message || parse_error->message[0]) return;
    length = ascii_length(message);
    if (length >= sizeof(parse_error->message))
        length = sizeof(parse_error->message) - 1;
    CopyMem(parse_error->message, (VOID *)message, length);
    parse_error->message[length] = '\0';
}
#endif

#if ML_ENABLE_LUKS1 || ML_ENABLE_LUKS2
#define ML_LUKS_PASSPHRASE_MAX 128u

static void wipe_bytes(VOID *buffer, UINTN size)
{
    volatile UINT8 *p = (volatile UINT8 *)buffer;
    while (size--) *p++ = 0;
}

static EFI_STATUS read_passphrase(CHAR8 *buffer, UINTN capacity,
                                  UINTN *length, const char *version)
{
    UINTN used = 0;
    EFI_STATUS status;
    EFI_EVENT event;
    if (!buffer || !capacity || !length || !ST || !ST->ConIn)
        return EFI_INVALID_PARAMETER;
    *length = 0;
    SetMem(buffer, capacity, 0);
    ml_console_ascii("Unlock ");
    ml_console_ascii(version);
    ml_console_ascii(" volume (printable ASCII, hidden): ");
    event = ST->ConIn->WaitForKey;
    for (;;) {
        EFI_INPUT_KEY key;
        UINTN index;
        status = BS->WaitForEvent(1, &event, &index);
        if (EFI_ERROR(status)) {
            wipe_bytes(buffer, capacity);
            return status;
        }
        status = ST->ConIn->ReadKeyStroke(ST->ConIn, &key);
        if (status == EFI_NOT_READY) continue;
        if (EFI_ERROR(status)) {
            wipe_bytes(buffer, capacity);
            return status;
        }
        if (key.UnicodeChar == '\r' || key.UnicodeChar == '\n') {
            ml_console_ascii("\r\n");
            if (used == 0) {
                ml_console_ascii("Passphrase cannot be empty.\r\n");
                wipe_bytes(buffer, capacity);
                return EFI_INVALID_PARAMETER;
            }
            *length = used;
            return EFI_SUCCESS;
        }
        if (key.UnicodeChar == 0x1b) {
            ml_console_ascii("\r\nUnlock cancelled.\r\n");
            wipe_bytes(buffer, capacity);
            return EFI_ABORTED;
        }
        if (key.UnicodeChar == 0x08 || key.UnicodeChar == 0x7f) {
            if (used) buffer[--used] = 0;
            continue;
        }
        if (key.UnicodeChar < 0x20 || key.UnicodeChar > 0x7e) {
            ml_console_ascii("\r\nOnly printable ASCII passphrases are supported by this prompt.\r\n");
            wipe_bytes(buffer, capacity);
            return EFI_UNSUPPORTED;
        }
        if (used + 1 >= capacity) {
            ml_console_ascii("\r\nPassphrase is too long for this build.\r\n");
            wipe_bytes(buffer, capacity);
            return EFI_BAD_BUFFER_SIZE;
        }
        buffer[used++] = (CHAR8)key.UnicodeChar;
    }
}
#endif

#if ML_ENABLE_LUKS1
#if ML_ENABLE_TPM12
static int luks1_uuid_from_header(const UINT8 *header, char uuid[37])
{
    UINTN i;
    static const UINTN dash_positions[] = { 8, 13, 18, 23 };
    if (!header || !uuid) return 0;
    for (i = 0; i < 36; ++i) {
        UINT8 c = header[168 + i];
        if (i == dash_positions[0] || i == dash_positions[1] ||
            i == dash_positions[2] || i == dash_positions[3]) {
            if (c != '-') return 0;
        } else if (!((c >= '0' && c <= '9') ||
                     (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F'))) {
            return 0;
        }
        if (c >= 'A' && c <= 'F') c = (UINT8)(c + ('a' - 'A'));
        uuid[i] = (char)c;
    }
    if (header[204] != 0) return 0;
    uuid[36] = '\0';
    return 1;
}

static EFI_STATUS find_tpm12_sidecar(ml_uefi_storage *storage,
                                     const char *uuid,
                                     VOID **sidecar, UINTN *sidecar_size)
{
    char path[96];
    UINTN i, matches = 0;
    VOID *found = NULL;
    UINTN found_size = 0;
    EFI_STATUS status;
    static const char prefix[] = "/boot/miniloader/tpm12/";
    UINTN p = 0;
    if (!storage || !uuid || !sidecar || !sidecar_size)
        return EFI_INVALID_PARAMETER;
    while (prefix[p]) { path[p] = prefix[p]; ++p; }
    for (i = 0; i < 36; ++i) path[p++] = uuid[i];
    {
        static const char suffix[] = ".json";
        UINTN j;
        for (j = 0; suffix[j]; ++j) path[p++] = suffix[j];
    }
    path[p] = '\0';
    *sidecar = NULL;
    *sidecar_size = 0;
    for (i = 0; i < storage->volume_count; ++i) {
        VOID *candidate = NULL;
        UINTN candidate_size = 0;
        if (storage->volumes[i].kind != ML_VOLUME_UEFI_FS) continue;
        status = storage_read_max(&storage->volumes[i], path,
            ML_TPM12_MAX_ENVELOPE_BYTES * 2u, &candidate, &candidate_size);
        if (EFI_ERROR(status)) continue;
        ++matches;
        if (matches == 1) {
            found = candidate;
            found_size = candidate_size;
        } else {
            BS->FreePool(candidate);
        }
    }
    if (matches > 1) {
        if (found) BS->FreePool(found);
        return EFI_ACCESS_DENIED;
    }
    if (matches == 0) return EFI_NOT_FOUND;
    *sidecar = found;
    *sidecar_size = found_size;
    return EFI_SUCCESS;
}

static int try_tpm12_luks1_unlock(ml_uefi_storage *storage,
                                 const ml_block_device *device,
                                 const UINT8 *header,
                                 ml_luks1_volume *volume,
                                 const char **message)
{
    char uuid[37];
    VOID *sidecar = NULL;
    UINTN sidecar_size = 0;
    CHAR8 secret[ML_LUKS_PASSPHRASE_MAX];
    size_t secret_size = 0;
    ml_efi_tcg_protocol *tpm = NULL;
    EFI_STATUS status;
    ml_luks1_result result;
    int ok = 0;
    if (!luks1_uuid_from_header(header, uuid)) return 0;
    status = find_tpm12_sidecar(storage, uuid, &sidecar, &sidecar_size);
    if (EFI_ERROR(status)) return 0;
    status = BS->LocateProtocol(&ml_efi_tcg_protocol_guid, NULL, (VOID **)&tpm);
    if (EFI_ERROR(status) || !tpm) {
        ml_console_ascii("TPM 1.2 is unavailable; falling back to passphrase.\r\n");
        goto done;
    }
    if (!ml_tpm12_unseal_sidecar(firmware_tpm12_submit, tpm,
            (const UINT8 *)sidecar, sidecar_size, uuid,
            (UINT8 *)secret, sizeof(secret), &secret_size)) {
        ml_console_ascii("TPM 1.2 unseal failed or PCR policy did not match; falling back to passphrase.\r\n");
        goto done;
    }
    result = ml_luks1_open(volume, device, secret, secret_size,
        storage->luks_scratch, ML_LUKS1_SCRATCH_BYTES, message);
    wipe_bytes(secret, sizeof(secret));
    wipe_bytes(storage->luks_scratch, ML_LUKS1_SCRATCH_BYTES);
    if (result == ML_LUKS1_OK) {
        ml_console_ascii("LUKS1 volume unlocked with TPM 1.2.\r\n");
        ok = 1;
    } else {
        ml_console_ascii("TPM 1.2 secret did not unlock this volume; falling back to passphrase.\r\n");
    }
done:
    wipe_bytes(secret, sizeof(secret));
    if (sidecar) BS->FreePool(sidecar);
    wipe_bytes(uuid, sizeof(uuid));
    return ok;
}
#endif

static EFI_STATUS unlock_luks_candidate(ml_uefi_storage *storage,
                                        const ml_block_device *device,
                                        ml_luks1_volume **unlocked,
                                        ml_config_error *parse_error)
{
    UINT8 header[208];
    UINT16 version;
    UINTN attempt;
    ml_luks1_volume *volume;
    const char *message = NULL;
    EFI_STATUS status;

    if (unlocked) *unlocked = NULL;
    if (!storage || !device || !unlocked) return EFI_INVALID_PARAMETER;
    if (ml_block_read(device, 0, header, 8) != ML_BLOCK_OK)
        return EFI_SUCCESS;
    if (header[0] != 'L' || header[1] != 'U' || header[2] != 'K' ||
        header[3] != 'S' || header[4] != 0xba || header[5] != 0xbe)
        return EFI_SUCCESS;
    version = (UINT16)(((UINT16)header[6] << 8) | header[7]);
    if (version != 1) {
#if ML_ENABLE_LUKS2
        if (version == 2) return EFI_SUCCESS;
#endif
        storage->unsupported_luks_count++;
        copy_storage_message(parse_error, version == 2
            ? "LUKS2 encrypted volumes are not supported by this build"
            : "encrypted volume has an unsupported LUKS header version");
        return EFI_SUCCESS;
    }
    if (storage->luks_volume_count >= ML_MAX_LUKS_DEVICES) {
        storage->unsupported_luks_count++;
        copy_storage_message(parse_error, "too many LUKS1 volumes for this build");
        return EFI_SUCCESS;
    }
    if (!storage->luks_volumes) {
        status = BS->AllocatePool(EfiLoaderData,
            ML_MAX_LUKS_DEVICES * sizeof(*storage->luks_volumes),
            (VOID **)&storage->luks_volumes);
        if (EFI_ERROR(status)) return status;
        SetMem(storage->luks_volumes,
            ML_MAX_LUKS_DEVICES * sizeof(*storage->luks_volumes), 0);
        status = BS->AllocatePool(EfiLoaderData, ML_LUKS1_SCRATCH_BYTES,
                                  &storage->luks_scratch);
        if (EFI_ERROR(status)) return status;
        SetMem(storage->luks_scratch, ML_LUKS1_SCRATCH_BYTES, 0);
    }
    volume = &storage->luks_volumes[storage->luks_volume_count];
#if ML_ENABLE_TPM12
    if (ml_block_read(device, 0, header, sizeof(header)) == ML_BLOCK_OK &&
        try_tpm12_luks1_unlock(storage, device, header, volume, &message)) {
        storage->luks_volume_count++;
        *unlocked = volume;
        wipe_bytes(header, sizeof(header));
        return EFI_SUCCESS;
    }
#endif
    for (attempt = 0; attempt < 3; ++attempt) {
        CHAR8 passphrase[ML_LUKS_PASSPHRASE_MAX];
        UINTN passphrase_size = 0;
        ml_luks1_result result;
        status = read_passphrase(passphrase, sizeof(passphrase),
                                 &passphrase_size, "LUKS1");
        if (EFI_ERROR(status)) {
            wipe_bytes(passphrase, sizeof(passphrase));
            if (status == EFI_ABORTED || status == EFI_UNSUPPORTED ||
                status == EFI_INVALID_PARAMETER || status == EFI_BAD_BUFFER_SIZE) {
                storage->unsupported_luks_count++;
                if (status == EFI_ABORTED)
                    copy_storage_message(parse_error, "LUKS1 unlock was cancelled");
                else if (status == EFI_INVALID_PARAMETER)
                    copy_storage_message(parse_error, "LUKS1 passphrase cannot be empty");
                else if (status == EFI_UNSUPPORTED)
                    copy_storage_message(parse_error,
                        "LUKS1 passphrase prompt requires printable ASCII");
                else
                    copy_storage_message(parse_error,
                        "LUKS1 passphrase exceeds the 127-byte prompt limit");
                return EFI_SUCCESS;
            }
            return status;
        }
        result = ml_luks1_open(volume, device, passphrase, passphrase_size,
            storage->luks_scratch, ML_LUKS1_SCRATCH_BYTES, &message);
        wipe_bytes(passphrase, sizeof(passphrase));
        wipe_bytes(storage->luks_scratch, ML_LUKS1_SCRATCH_BYTES);
        if (result == ML_LUKS1_OK) {
            storage->luks_volume_count++;
            *unlocked = volume;
            ml_console_ascii("LUKS1 volume unlocked.\r\n");
            return EFI_SUCCESS;
        }
        if (result == ML_LUKS1_WRONG_PASSPHRASE && attempt < 2) {
            ml_console_ascii("Incorrect passphrase. Try again.\r\n");
            continue;
        }
        storage->unsupported_luks_count++;
        if (result == ML_LUKS1_WRONG_PASSPHRASE)
            copy_storage_message(parse_error,
                "LUKS1 unlock failed after three passphrase attempts");
        else
            copy_storage_message(parse_error, message ? message :
                "LUKS1 volume could not be opened");
        wipe_bytes(volume, sizeof(*volume));
        return EFI_SUCCESS;
    }
    return EFI_SUCCESS;
}
#endif

#if ML_ENABLE_LUKS2
#if ML_ENABLE_KDF_ARGON2ID
static int allocate_argon_pool(void *context, UINT8 **memory, size_t size)
{
    VOID *allocation = NULL;
    EFI_STATUS status;
    (void)context;
    if (size > (size_t)(UINTN)(~(UINTN)0)) return 1;
    status = BS->AllocatePool(EfiLoaderData, (UINTN)size, &allocation);
    if (EFI_ERROR(status)) return 1;
    *memory = (UINT8 *)allocation;
    return 0;
}

static void release_argon_pool(void *context, UINT8 *memory, size_t size)
{
    (void)context;
    (void)size;
    if (memory) BS->FreePool(memory);
}
#endif

static EFI_STATUS unlock_luks2_candidate(ml_uefi_storage *storage,
                                         const ml_block_device *device,
                                         ml_luks2_volume **unlocked,
                                         ml_config_error *parse_error)
{
    UINT8 header[8];
    UINT16 version;
    UINTN attempt;
    ml_luks2_volume *volume;
    const char *message = NULL;
    EFI_STATUS status;

    if (unlocked) *unlocked = NULL;
    if (!storage || !device || !unlocked) return EFI_INVALID_PARAMETER;
    if (ml_block_read(device, 0, header, sizeof(header)) != ML_BLOCK_OK)
        return EFI_SUCCESS;
    if (header[0] != 'L' || header[1] != 'U' || header[2] != 'K' ||
        header[3] != 'S' || header[4] != 0xba || header[5] != 0xbe)
        return EFI_SUCCESS;
    version = (UINT16)(((UINT16)header[6] << 8) | header[7]);
    if (version != 2) {
#if ML_ENABLE_LUKS1
        if (version == 1) return EFI_SUCCESS;
#endif
        storage->unsupported_luks_count++;
        copy_storage_message(parse_error,
            "encrypted volume has an unsupported LUKS header version");
        return EFI_SUCCESS;
    }
    if (storage->luks2_volume_count >= ML_MAX_LUKS_DEVICES) {
        storage->unsupported_luks_count++;
        copy_storage_message(parse_error, "too many LUKS2 volumes for this build");
        return EFI_SUCCESS;
    }
    if (!storage->luks2_volumes) {
        status = BS->AllocatePool(EfiLoaderData,
            ML_MAX_LUKS_DEVICES * sizeof(*storage->luks2_volumes),
            (VOID **)&storage->luks2_volumes);
        if (EFI_ERROR(status)) return status;
        SetMem(storage->luks2_volumes,
            ML_MAX_LUKS_DEVICES * sizeof(*storage->luks2_volumes), 0);
        status = BS->AllocatePool(EfiLoaderData, ML_LUKS2_SCRATCH_BYTES,
                                  &storage->luks2_scratch);
        if (EFI_ERROR(status)) return status;
        SetMem(storage->luks2_scratch, ML_LUKS2_SCRATCH_BYTES, 0);
    }
    volume = &storage->luks2_volumes[storage->luks2_volume_count];
#if ML_ENABLE_TPM2
    {
        ml_tpm2_token token;
        CHAR8 sealed_secret[128];
        size_t sealed_secret_size = 0;
        ml_luks2_result token_result;
        ml_efi_tcg2_protocol *tpm2 = NULL;
        const char *token_message = NULL;
        token_result = ml_luks2_read_tpm2_token(device, &token,
            storage->luks2_scratch, ML_LUKS2_SCRATCH_BYTES,
            &token_message);
        if (token_result == ML_LUKS2_OK &&
            !EFI_ERROR(BS->LocateProtocol(&ml_efi_tcg2_protocol_guid, NULL,
                                          (VOID **)&tpm2)) &&
            ml_tpm2_unseal(firmware_tpm2_submit, tpm2, &token,
                           (UINT8 *)sealed_secret, sizeof(sealed_secret),
                           &sealed_secret_size)) {
            ml_luks2_result tpm_result = ml_luks2_open(volume, device,
                sealed_secret, sealed_secret_size, storage->luks2_scratch,
                ML_LUKS2_SCRATCH_BYTES,
#if ML_ENABLE_KDF_ARGON2ID
                allocate_argon_pool, release_argon_pool, NULL,
#else
                NULL, NULL, NULL,
#endif
                &message);
            wipe_bytes(sealed_secret, sizeof(sealed_secret));
            wipe_bytes(storage->luks2_scratch, ML_LUKS2_SCRATCH_BYTES);
            wipe_bytes(&token, sizeof(token));
            if (tpm_result == ML_LUKS2_OK) {
                storage->luks2_volume_count++;
                *unlocked = volume;
                ml_console_ascii("LUKS2 volume unlocked with TPM2.\r\n");
                return EFI_SUCCESS;
            }
            ml_console_ascii("TPM2 secret did not unlock this volume; falling back to passphrase.\r\n");
        } else {
            wipe_bytes(sealed_secret, sizeof(sealed_secret));
            wipe_bytes(&token, sizeof(token));
            if (token_result == ML_LUKS2_OK)
                ml_console_ascii("TPM2 is unavailable or the PCR policy did not match; falling back to passphrase.\r\n");
            else if (token_result != ML_LUKS2_UNSUPPORTED && token_message)
                ml_console_ascii("TPM2 token could not be read; falling back to passphrase.\r\n");
        }
    }
#endif
    for (attempt = 0; attempt < 3; ++attempt) {
        CHAR8 passphrase[ML_LUKS_PASSPHRASE_MAX];
        UINTN passphrase_size = 0;
        ml_luks2_result result;
        status = read_passphrase(passphrase, sizeof(passphrase),
                                 &passphrase_size, "LUKS2");
        if (EFI_ERROR(status)) {
            wipe_bytes(passphrase, sizeof(passphrase));
            if (status == EFI_ABORTED || status == EFI_UNSUPPORTED ||
                status == EFI_INVALID_PARAMETER || status == EFI_BAD_BUFFER_SIZE) {
                storage->unsupported_luks_count++;
                if (status == EFI_ABORTED)
                    copy_storage_message(parse_error, "LUKS2 unlock was cancelled");
                else if (status == EFI_INVALID_PARAMETER)
                    copy_storage_message(parse_error, "LUKS2 passphrase cannot be empty");
                else if (status == EFI_UNSUPPORTED)
                    copy_storage_message(parse_error,
                        "LUKS2 passphrase prompt requires printable ASCII");
                else
                    copy_storage_message(parse_error,
                        "LUKS2 passphrase exceeds the 127-byte prompt limit");
                return EFI_SUCCESS;
            }
            return status;
        }
        result = ml_luks2_open(volume, device, passphrase, passphrase_size,
            storage->luks2_scratch, ML_LUKS2_SCRATCH_BYTES,
#if ML_ENABLE_KDF_ARGON2ID
            allocate_argon_pool, release_argon_pool, NULL,
#else
            NULL, NULL, NULL,
#endif
            &message);
        wipe_bytes(passphrase, sizeof(passphrase));
        wipe_bytes(storage->luks2_scratch, ML_LUKS2_SCRATCH_BYTES);
        if (result == ML_LUKS2_OK) {
            storage->luks2_volume_count++;
            *unlocked = volume;
            ml_console_ascii("LUKS2 volume unlocked.\r\n");
            return EFI_SUCCESS;
        }
        if (result == ML_LUKS2_WRONG_PASSPHRASE && attempt < 2) {
            ml_console_ascii("Incorrect passphrase. Try again.\r\n");
            continue;
        }
        storage->unsupported_luks_count++;
        if (result == ML_LUKS2_WRONG_PASSPHRASE)
            copy_storage_message(parse_error,
                "LUKS2 unlock failed after three passphrase attempts");
        else
            copy_storage_message(parse_error, message ? message :
                "LUKS2 volume could not be opened");
        wipe_bytes(volume, sizeof(*volume));
        return EFI_SUCCESS;
    }
    return EFI_SUCCESS;
}
#endif

#if ML_ENABLE_FS_EXT2 || ML_ENABLE_FS_EXT4
static EFI_STATUS ext_status(ml_extfs_result result)
{
    switch (result) {
    case ML_EXTFS_OK: return EFI_SUCCESS;
    case ML_EXTFS_NOT_FOUND:
    case ML_EXTFS_NOT_FILE: return EFI_NOT_FOUND;
    case ML_EXTFS_UNSUPPORTED: return EFI_UNSUPPORTED;
    case ML_EXTFS_IO: return EFI_DEVICE_ERROR;
    case ML_EXTFS_RANGE: return EFI_BAD_BUFFER_SIZE;
    case ML_EXTFS_BAD_FORMAT: return EFI_VOLUME_CORRUPTED;
    default: return EFI_INVALID_PARAMETER;
    }
}

static EFI_STATUS ext_storage_read_max(ml_uefi_volume *volume, const char *path,
                                       UINT64 max_size, VOID **buffer, UINTN *size)
{
    ml_extfs_file file;
    const char *message = NULL;
    char normalized_path[ML_VALUE_MAX];
    UINTN i, path_length, read_size;
    size_t amount = 0;
    VOID *data = NULL;
    EFI_STATUS status;
    ml_extfs_result result;

    if (!volume || !path || !buffer || !size)
        return EFI_INVALID_PARAMETER;
    *buffer = NULL;
    *size = 0;
    path_length = ascii_length(path);
    if (path_length >= ML_VALUE_MAX) return EFI_BAD_BUFFER_SIZE;
    for (i = 0; i < path_length; ++i)
        normalized_path[i] = path[i] == '\\' ? '/' : path[i];
    normalized_path[path_length] = '\0';
    result = ml_extfs_open(&file, &volume->extfs, normalized_path, &message);
    if (result != ML_EXTFS_OK) return ext_status(result);
    if (file.size > max_size || file.size > (UINT64)(~(UINTN)0))
        return EFI_BAD_BUFFER_SIZE;
    read_size = (UINTN)file.size;
    status = BS->AllocatePool(EfiLoaderData, read_size ? read_size : 1, &data);
    if (EFI_ERROR(status)) return status;
    result = ml_extfs_read(&file, 0, data, read_size, &amount, &message);
    if (result != ML_EXTFS_OK || amount != read_size) {
        BS->FreePool(data);
        return result == ML_EXTFS_OK ? EFI_END_OF_FILE : ext_status(result);
    }
    *buffer = data;
    *size = read_size;
    return EFI_SUCCESS;
}
#endif

#if ML_ENABLE_FS_XFS
static EFI_STATUS xfs_status(ml_xfs_result result)
{
    switch (result) {
    case ML_XFS_OK: return EFI_SUCCESS;
    case ML_XFS_NOT_FOUND:
    case ML_XFS_NOT_FILE: return EFI_NOT_FOUND;
    case ML_XFS_UNSUPPORTED: return EFI_UNSUPPORTED;
    case ML_XFS_IO: return EFI_DEVICE_ERROR;
    case ML_XFS_RANGE: return EFI_BAD_BUFFER_SIZE;
    case ML_XFS_BAD_FORMAT: return EFI_VOLUME_CORRUPTED;
    default: return EFI_INVALID_PARAMETER;
    }
}

static EFI_STATUS xfs_storage_read_max(ml_uefi_volume *volume, const char *path,
                                       UINT64 max_size, VOID **buffer,
                                       UINTN *size)
{
    ml_xfs_file file;
    const char *message = NULL;
    char normalized_path[ML_VALUE_MAX];
    UINTN i, path_length, read_size;
    size_t amount = 0;
    VOID *data = NULL;
    EFI_STATUS status;
    ml_xfs_result result;

    if (!volume || !path || !buffer || !size) return EFI_INVALID_PARAMETER;
    *buffer = NULL;
    *size = 0;
    path_length = ascii_length(path);
    if (path_length >= ML_VALUE_MAX) return EFI_BAD_BUFFER_SIZE;
    for (i = 0; i < path_length; ++i)
        normalized_path[i] = path[i] == '\\' ? '/' : path[i];
    normalized_path[path_length] = '\0';
    result = ml_xfs_open(&file, &volume->xfs, normalized_path, &message);
    if (result != ML_XFS_OK) return xfs_status(result);
    if (file.size > max_size || file.size > (UINT64)(~(UINTN)0)) {
        ml_xfs_close_file(&file);
        return EFI_BAD_BUFFER_SIZE;
    }
    read_size = (UINTN)file.size;
    status = BS->AllocatePool(EfiLoaderData, read_size ? read_size : 1, &data);
    if (EFI_ERROR(status)) { ml_xfs_close_file(&file); return status; }
    result = ml_xfs_read(&file, 0, data, read_size, &amount, &message);
    ml_xfs_close_file(&file);
    if (result != ML_XFS_OK || amount != read_size) {
        BS->FreePool(data);
        return result == ML_XFS_OK ? EFI_END_OF_FILE : xfs_status(result);
    }
    *buffer = data;
    *size = read_size;
    return EFI_SUCCESS;
}
#endif

#if ML_ENABLE_FS_BTRFS
static EFI_STATUS btrfs_status(ml_btrfs_result result)
{
    switch (result) {
    case ML_BTRFS_OK: return EFI_SUCCESS;
    case ML_BTRFS_NOT_FOUND:
    case ML_BTRFS_NOT_FILE: return EFI_NOT_FOUND;
    case ML_BTRFS_UNSUPPORTED: return EFI_UNSUPPORTED;
    case ML_BTRFS_IO: return EFI_DEVICE_ERROR;
    case ML_BTRFS_RANGE: return EFI_BAD_BUFFER_SIZE;
    case ML_BTRFS_BAD_FORMAT: return EFI_VOLUME_CORRUPTED;
    default: return EFI_INVALID_PARAMETER;
    }
}

static EFI_STATUS btrfs_storage_read_max(ml_uefi_volume *volume,
                                         const char *path, UINT64 max_size,
                                         VOID **buffer, UINTN *size)
{
    ml_btrfs_file file;
    const char *message = NULL;
    char normalized_path[ML_VALUE_MAX];
    UINTN i, path_length, read_size;
    size_t amount = 0;
    VOID *data = NULL;
    EFI_STATUS status;
    ml_btrfs_result result;
    if (!volume || !path || !buffer || !size) return EFI_INVALID_PARAMETER;
    *buffer = NULL;
    *size = 0;
    path_length = ascii_length(path);
    if (path_length >= ML_VALUE_MAX) return EFI_BAD_BUFFER_SIZE;
    for (i = 0; i < path_length; ++i)
        normalized_path[i] = path[i] == '\\' ? '/' : path[i];
    normalized_path[path_length] = '\0';
    result = ml_btrfs_open(&file, &volume->btrfs, normalized_path, &message);
    if (result != ML_BTRFS_OK) return btrfs_status(result);
    if (file.size > max_size || file.size > (UINT64)(~(UINTN)0)) {
        ml_btrfs_close_file(&file);
        return EFI_BAD_BUFFER_SIZE;
    }
    read_size = (UINTN)file.size;
    status = BS->AllocatePool(EfiLoaderData, read_size ? read_size : 1, &data);
    if (EFI_ERROR(status)) { ml_btrfs_close_file(&file); return status; }
    result = ml_btrfs_read(&file, 0, data, read_size, &amount, &message);
    ml_btrfs_close_file(&file);
    if (result != ML_BTRFS_OK || amount != read_size) {
        BS->FreePool(data);
        return result == ML_BTRFS_OK ? EFI_END_OF_FILE : btrfs_status(result);
    }
    *buffer = data;
    *size = read_size;
    return EFI_SUCCESS;
}
#endif

#if ML_ENABLE_FS_ZFS
static EFI_STATUS zfs_status(ml_zfs_result result)
{
    switch (result) {
    case ML_ZFS_OK: return EFI_SUCCESS;
    case ML_ZFS_NOT_FOUND:
    case ML_ZFS_NOT_FILE: return EFI_NOT_FOUND;
    case ML_ZFS_UNSUPPORTED: return EFI_UNSUPPORTED;
    case ML_ZFS_IO: return EFI_DEVICE_ERROR;
    case ML_ZFS_RANGE: return EFI_BAD_BUFFER_SIZE;
    case ML_ZFS_BAD_FORMAT: return EFI_VOLUME_CORRUPTED;
    default: return EFI_INVALID_PARAMETER;
    }
}

static EFI_STATUS zfs_storage_read_max(ml_uefi_volume *volume, const char *path,
                                       UINT64 max_size, VOID **buffer,
                                       UINTN *size)
{
    ml_zfs_file file;
    const char *message = NULL;
    char normalized_path[ML_VALUE_MAX];
    UINTN i, path_length, read_size;
    size_t amount = 0;
    VOID *data = NULL;
    EFI_STATUS status;
    ml_zfs_result result;
    if (!volume || !path || !buffer || !size) return EFI_INVALID_PARAMETER;
    *buffer = NULL;
    *size = 0;
    path_length = ascii_length(path);
    if (path_length >= ML_VALUE_MAX) return EFI_BAD_BUFFER_SIZE;
    for (i = 0; i < path_length; ++i)
        normalized_path[i] = path[i] == '\\' ? '/' : path[i];
    normalized_path[path_length] = '\0';
    result = ml_zfs_open(&file, &volume->zfs, normalized_path, &message);
    if (result != ML_ZFS_OK) return zfs_status(result);
    if (file.size > max_size || file.size > (UINT64)(~(UINTN)0)) {
        ml_zfs_close_file(&file);
        return EFI_BAD_BUFFER_SIZE;
    }
    read_size = (UINTN)file.size;
    status = BS->AllocatePool(EfiLoaderData, read_size ? read_size : 1, &data);
    if (EFI_ERROR(status)) { ml_zfs_close_file(&file); return status; }
    result = ml_zfs_read(&file, 0, data, read_size, &amount, &message);
    ml_zfs_close_file(&file);
    if (result != ML_ZFS_OK || amount != read_size) {
        BS->FreePool(data);
        return result == ML_ZFS_OK ? EFI_END_OF_FILE : zfs_status(result);
    }
    *buffer = data;
    *size = read_size;
    return EFI_SUCCESS;
}
#endif

#if ML_ENABLE_FS_VFAT
static EFI_STATUS vfat_status(ml_vfat_result result)
{
    switch (result) {
    case ML_VFAT_OK: return EFI_SUCCESS;
    case ML_VFAT_NOT_FOUND:
    case ML_VFAT_NOT_FILE: return EFI_NOT_FOUND;
    case ML_VFAT_UNSUPPORTED: return EFI_UNSUPPORTED;
    case ML_VFAT_IO: return EFI_DEVICE_ERROR;
    case ML_VFAT_RANGE: return EFI_BAD_BUFFER_SIZE;
    case ML_VFAT_BAD_FORMAT: return EFI_VOLUME_CORRUPTED;
    default: return EFI_INVALID_PARAMETER;
    }
}

static EFI_STATUS vfat_storage_read_max(ml_uefi_volume *volume, const char *path,
                                        UINT64 max_size, VOID **buffer,
                                        UINTN *size)
{
    ml_vfat_file file;
    const char *message = NULL;
    UINTN read_size;
    size_t amount = 0;
    VOID *data = NULL;
    EFI_STATUS status;
    ml_vfat_result result;
    if (!volume || !path || !buffer || !size)
        return EFI_INVALID_PARAMETER;
    *buffer = NULL;
    *size = 0;
    result = ml_vfat_open(&file, &volume->vfat, path, &message);
    if (result != ML_VFAT_OK) return vfat_status(result);
    if (file.size > max_size || file.size > (UINT64)(~(UINTN)0))
        return EFI_BAD_BUFFER_SIZE;
    read_size = (UINTN)file.size;
    status = BS->AllocatePool(EfiLoaderData, read_size ? read_size : 1, &data);
    if (EFI_ERROR(status)) return status;
    result = ml_vfat_read(&file, 0, data, read_size, &amount, &message);
    if (result != ML_VFAT_OK || amount != read_size) {
        BS->FreePool(data);
        return result == ML_VFAT_OK ? EFI_END_OF_FILE : vfat_status(result);
    }
    *buffer = data;
    *size = read_size;
    return EFI_SUCCESS;
}
#endif

static EFI_STATUS storage_read_max(ml_uefi_volume *volume, const char *path,
                                   UINT64 max_size, VOID **buffer, UINTN *size)
{
    CHAR16 wide_path[ML_VALUE_MAX];
    EFI_FILE_HANDLE file = NULL;
    EFI_FILE_INFO *info = NULL;
    UINTN i, info_size = 0, read_size;
    EFI_STATUS status;
    VOID *data = NULL;

    if (!volume || !path || !buffer || !size) return EFI_INVALID_PARAMETER;
    if (volume->kind == ML_VOLUME_EXT_FS) {
#if ML_ENABLE_FS_EXT2 || ML_ENABLE_FS_EXT4
        return ext_storage_read_max(volume, path, max_size, buffer, size);
#else
        return EFI_UNSUPPORTED;
#endif
    }
    if (volume->kind == ML_VOLUME_XFS_FS) {
#if ML_ENABLE_FS_XFS
        return xfs_storage_read_max(volume, path, max_size, buffer, size);
#else
        return EFI_UNSUPPORTED;
#endif
    }
    if (volume->kind == ML_VOLUME_BTRFS_FS) {
#if ML_ENABLE_FS_BTRFS
        return btrfs_storage_read_max(volume, path, max_size, buffer, size);
#else
        return EFI_UNSUPPORTED;
#endif
    }
#if ML_ENABLE_FS_ZFS
    if (volume->kind == ML_VOLUME_ZFS_FS)
        return zfs_storage_read_max(volume, path, max_size, buffer, size);
#endif
    if (volume->kind == ML_VOLUME_VFAT_FS) {
#if ML_ENABLE_FS_VFAT
        return vfat_storage_read_max(volume, path, max_size, buffer, size);
#else
        return EFI_UNSUPPORTED;
#endif
    }
    if (!volume->root) return EFI_INVALID_PARAMETER;
    *buffer = NULL;
    *size = 0;
    if (ascii_length(path) >= ML_VALUE_MAX) return EFI_BAD_BUFFER_SIZE;
    for (i = 0; path[i]; ++i) {
        CHAR8 c = path[i];
        wide_path[i] = (c == '/') ? L'\\' : (CHAR16)(UINT8)c;
    }
    wide_path[i] = L'\0';

    status = volume->root->Open(volume->root, &file, wide_path, EFI_FILE_MODE_READ, 0);
    if (EFI_ERROR(status)) return status;
    status = file->GetInfo(file, &file_info_guid, &info_size, NULL);
    if (status != EFI_BUFFER_TOO_SMALL || info_size < SIZE_OF_EFI_FILE_INFO) {
        file->Close(file);
        return EFI_DEVICE_ERROR;
    }
    status = BS->AllocatePool(EfiLoaderData, info_size, (VOID **)&info);
    if (EFI_ERROR(status)) {
        file->Close(file);
        return status;
    }
    status = file->GetInfo(file, &file_info_guid, &info_size, info);
    if (EFI_ERROR(status)) goto done;
    if (info->FileSize > max_size || info->FileSize > (UINT64)(~(UINTN)0)) {
        status = EFI_BAD_BUFFER_SIZE;
        goto done;
    }
    read_size = (UINTN)info->FileSize;
    status = BS->AllocatePool(EfiLoaderData, read_size ? read_size : 1, &data);
    if (EFI_ERROR(status)) goto done;
    {
        UINTN total = 0;
        while (total < read_size) {
            UINTN amount = read_size - total;
            status = file->Read(file, &amount, (UINT8 *)data + total);
            if (EFI_ERROR(status)) goto done;
            if (amount == 0) { status = EFI_END_OF_FILE; goto done; }
            total += amount;
        }
    }
    *buffer = data;
    *size = read_size;
    data = NULL;
    status = EFI_SUCCESS;

done:
    if (data) BS->FreePool(data);
    if (info) BS->FreePool(info);
    file->Close(file);
    return status;
}

EFI_STATUS ml_storage_read(ml_uefi_volume *volume, const char *path,
                           VOID **buffer, UINTN *size)
{
    return storage_read_max(volume, path, ML_MAX_IMAGE_BYTES, buffer, size);
}

static EFI_STATUS scan_config(ml_uefi_storage *storage, ml_uefi_volume *volume,
                              UINTN *found, VOID **config_data,
                              UINTN *config_size, ml_config_error *parse_error)
{
    VOID *candidate = NULL;
    UINTN candidate_size = 0;
    EFI_STATUS status = storage_read_max(volume, CONFIG_PATH,
        ML_CONFIG_MAX_BYTES, &candidate, &candidate_size);
    if (status == EFI_NOT_FOUND) return EFI_SUCCESS;
    if (status == EFI_BAD_BUFFER_SIZE) {
        if (parse_error) {
            static const char oversized[] = "configuration exceeds 64 KiB";
            parse_error->line = 0;
            CopyMem(parse_error->message, (VOID *)oversized, sizeof(oversized));
        }
        return EFI_INVALID_PARAMETER;
    }
    if (EFI_ERROR(status)) return status;
    ++*found;
    if (*found == 1) {
        *config_data = candidate;
        *config_size = candidate_size;
        storage->config_volume = volume;
    } else {
        BS->FreePool(candidate);
    }
    return EFI_SUCCESS;
}

#if ML_ENABLE_FS_XFS || ML_ENABLE_FS_EXT2 || ML_ENABLE_FS_EXT4 || ML_ENABLE_FS_VFAT || ML_ENABLE_FS_BTRFS || ML_ENABLE_FS_ZFS
static int same_partition(const CHAR16 *a, const CHAR16 *b)
{
    UINTN i = 0;
    if (!a[0] || !b[0]) return 0;
    while (a[i] && b[i]) {
        CHAR16 ca = a[i], cb = b[i];
        if (ca >= L'A' && ca <= L'Z') ca = (CHAR16)(ca + (L'a' - L'A'));
        if (cb >= L'A' && cb <= L'Z') cb = (CHAR16)(cb + (L'a' - L'A'));
        if (ca != cb) return 0;
        ++i;
    }
    return a[i] == b[i];
}
#endif

#if ML_ENABLE_FS_EXT2 || ML_ENABLE_FS_EXT4
static EFI_STATUS mount_ext_candidate(ml_uefi_storage *storage,
                                     EFI_HANDLE handle,
                                     const CHAR16 partition_id[37],
                                     const ml_block_device *device,
                                     UINTN *found, VOID **config_data,
                                     UINTN *config_size,
                                     ml_config_error *parse_error)
{
    UINTN i;
    ml_uefi_volume *volume;
    const char *message = NULL;
    ml_extfs_result result;
    EFI_STATUS status;

    if (!storage || !device || !found || !config_data || !config_size)
        return EFI_INVALID_PARAMETER;
    if (partition_id && partition_id[0]) {
        for (i = 0; i < storage->volume_count; ++i)
            if (same_partition(storage->volumes[i].partition_guid, partition_id))
                return EFI_SUCCESS;
    }
    if (storage->volume_count >= ML_MAX_VOLUMES) return EFI_OUT_OF_RESOURCES;
    if (!storage->extfs_scratch) {
        status = BS->AllocatePool(EfiLoaderData, ML_EXTFS_MAX_BLOCK_SIZE,
                                  &storage->extfs_scratch);
        if (EFI_ERROR(status)) return status;
    }
    volume = &storage->volumes[storage->volume_count];
    volume->handle = handle;
    volume->kind = ML_VOLUME_EXT_FS;
    if (partition_id) CopyMem(volume->partition_guid, (VOID *)partition_id,
                              sizeof(volume->partition_guid));
    result = ml_extfs_mount(&volume->extfs, device, storage->extfs_scratch,
                            ML_EXTFS_MAX_BLOCK_SIZE, &message);
    if (result != ML_EXTFS_OK) {
        if (result == ML_EXTFS_UNSUPPORTED) {
            storage->unsupported_ext_count++;
            copy_storage_message(parse_error, message);
        }
        SetMem(volume, sizeof(*volume), 0);
        return EFI_SUCCESS;
    }
    ml_extfs_format_uuid(&volume->extfs, volume->filesystem_uuid);
    storage->volume_count++;
    return scan_config(storage, volume, found, config_data, config_size,
                       parse_error);
}
#endif

#if ML_ENABLE_FS_XFS
static EFI_STATUS mount_xfs_candidate(ml_uefi_storage *storage,
                                      EFI_HANDLE handle,
                                      const CHAR16 partition_id[37],
                                      const ml_block_device *device,
                                      UINTN *found, VOID **config_data,
                                      UINTN *config_size,
                                      ml_config_error *parse_error)
{
    UINTN i;
    ml_uefi_volume *volume;
    const char *message = NULL;
    ml_xfs_result result;
    if (!storage || !device || !found || !config_data || !config_size)
        return EFI_INVALID_PARAMETER;
    if (partition_id && partition_id[0]) {
        for (i = 0; i < storage->volume_count; ++i)
            if (same_partition(storage->volumes[i].partition_guid, partition_id))
                return EFI_SUCCESS;
    }
    if (storage->volume_count >= ML_MAX_VOLUMES) return EFI_OUT_OF_RESOURCES;
    volume = &storage->volumes[storage->volume_count];
    volume->handle = handle;
    volume->kind = ML_VOLUME_XFS_FS;
    if (partition_id) CopyMem(volume->partition_guid, (VOID *)partition_id,
                              sizeof(volume->partition_guid));
    result = ml_xfs_mount(&volume->xfs, device, &message);
    if (result != ML_XFS_OK) {
        if (result == ML_XFS_UNSUPPORTED || result == ML_XFS_BAD_FORMAT) {
            storage->unsupported_xfs_count++;
            copy_storage_message(parse_error, message);
        }
        SetMem(volume, sizeof(*volume), 0);
        return EFI_SUCCESS;
    }
    CopyMem(volume->filesystem_uuid, volume->xfs.uuid,
            sizeof(volume->filesystem_uuid));
    storage->volume_count++;
    return scan_config(storage, volume, found, config_data, config_size,
                       parse_error);
}
#endif

#if ML_ENABLE_FS_VFAT
static EFI_STATUS mount_vfat_candidate(ml_uefi_storage *storage,
                                       EFI_HANDLE handle,
                                       const CHAR16 partition_id[37],
                                       const ml_block_device *device,
                                       UINTN *found, VOID **config_data,
                                       UINTN *config_size,
                                       ml_config_error *parse_error)
{
    UINTN i;
    ml_uefi_volume *volume;
    const char *message = NULL;
    ml_vfat_result result;
    if (!storage || !device || !found || !config_data || !config_size)
        return EFI_INVALID_PARAMETER;
    if (partition_id && partition_id[0]) {
        for (i = 0; i < storage->volume_count; ++i)
            if (same_partition(storage->volumes[i].partition_guid, partition_id))
                return EFI_SUCCESS;
    }
    if (handle) {
        for (i = 0; i < storage->volume_count; ++i)
            if (storage->volumes[i].handle == handle &&
                storage->volumes[i].root)
                return EFI_SUCCESS;
    }
    if (storage->volume_count >= ML_MAX_VOLUMES) return EFI_OUT_OF_RESOURCES;
    volume = &storage->volumes[storage->volume_count];
    volume->handle = handle;
    volume->kind = ML_VOLUME_VFAT_FS;
    if (partition_id) CopyMem(volume->partition_guid, (VOID *)partition_id,
                              sizeof(volume->partition_guid));
    result = ml_vfat_mount(&volume->vfat, device, &message);
    if (result != ML_VFAT_OK) {
        if (result == ML_VFAT_UNSUPPORTED) {
            storage->unsupported_vfat_count++;
            copy_storage_message(parse_error, message);
        }
        SetMem(volume, sizeof(*volume), 0);
        return EFI_SUCCESS;
    }
    storage->volume_count++;
    return scan_config(storage, volume, found, config_data, config_size,
                       parse_error);
}
#endif

#if ML_ENABLE_FS_BTRFS
static EFI_STATUS mount_btrfs_candidate(ml_uefi_storage *storage,
                                        EFI_HANDLE handle,
                                        const CHAR16 partition_id[37],
                                        const ml_block_device *device,
                                        UINTN *found, VOID **config_data,
                                        UINTN *config_size,
                                        ml_config_error *parse_error)
{
    UINTN i;
    ml_uefi_volume *volume;
    const char *message = NULL;
    ml_btrfs_result result;
    if (!storage || !device || !found || !config_data || !config_size)
        return EFI_INVALID_PARAMETER;
    if (partition_id && partition_id[0]) {
        for (i = 0; i < storage->volume_count; ++i)
            if (same_partition(storage->volumes[i].partition_guid, partition_id))
                return EFI_SUCCESS;
    }
    if (storage->volume_count >= ML_MAX_VOLUMES) return EFI_OUT_OF_RESOURCES;
    volume = &storage->volumes[storage->volume_count];
    volume->handle = handle;
    volume->kind = ML_VOLUME_BTRFS_FS;
    if (partition_id) CopyMem(volume->partition_guid, (VOID *)partition_id,
                              sizeof(volume->partition_guid));
    result = ml_btrfs_mount(&volume->btrfs, device, &message);
    if (result != ML_BTRFS_OK) {
        if (result == ML_BTRFS_UNSUPPORTED || result == ML_BTRFS_BAD_FORMAT) {
            storage->unsupported_btrfs_count++;
            copy_storage_message(parse_error, message);
        }
        SetMem(volume, sizeof(*volume), 0);
        return EFI_SUCCESS;
    }
    CopyMem(volume->filesystem_uuid, volume->btrfs.uuid,
            sizeof(volume->filesystem_uuid));
    storage->volume_count++;
    return scan_config(storage, volume, found, config_data, config_size,
                       parse_error);
}
#endif

#if ML_ENABLE_FS_ZFS
static EFI_STATUS mount_zfs_candidate(ml_uefi_storage *storage,
                                      EFI_HANDLE handle,
                                      const CHAR16 partition_id[37],
                                      const ml_block_device *device,
                                      UINTN *found, VOID **config_data,
                                      UINTN *config_size,
                                      ml_config_error *parse_error)
{
    UINTN i;
    ml_uefi_volume *volume;
    const char *message = NULL;
    ml_zfs_result result;
    if (!storage || !device || !found || !config_data || !config_size)
        return EFI_INVALID_PARAMETER;
    if (partition_id && partition_id[0]) {
        for (i = 0; i < storage->volume_count; ++i)
            if (same_partition(storage->volumes[i].partition_guid, partition_id))
                return EFI_SUCCESS;
    }
    if (storage->volume_count >= ML_MAX_VOLUMES) return EFI_OUT_OF_RESOURCES;
    volume = &storage->volumes[storage->volume_count];
    volume->handle = handle;
    volume->kind = ML_VOLUME_ZFS_FS;
    if (partition_id) CopyMem(volume->partition_guid, (VOID *)partition_id,
                              sizeof(volume->partition_guid));
    result = ml_zfs_mount(&volume->zfs, device, &message);
    if (result != ML_ZFS_OK) {
        if (result == ML_ZFS_UNSUPPORTED || result == ML_ZFS_BAD_FORMAT) {
            storage->unsupported_zfs_count++;
            copy_storage_message(parse_error, message);
        }
        SetMem(volume, sizeof(*volume), 0);
        return EFI_SUCCESS;
    }
    for (i = 0; i < storage->volume_count; ++i) {
        if (storage->volumes[i].kind == ML_VOLUME_ZFS_FS &&
            ascii_equal(storage->volumes[i].filesystem_uuid,
                        volume->zfs.uuid)) {
            ml_zfs_unmount(&volume->zfs);
            SetMem(volume, sizeof(*volume), 0);
            return EFI_SUCCESS;
        }
    }
    CopyMem(volume->filesystem_uuid, volume->zfs.uuid,
            sizeof(volume->filesystem_uuid));
    storage->volume_count++;
    return scan_config(storage, volume, found, config_data, config_size,
                       parse_error);
}
#endif

#if ML_ENABLE_FS_ZFS && (ML_ENABLE_LVM || ML_ENABLE_LUKS1 || ML_ENABLE_LUKS2)
static int append_zfs_device(const ml_block_device **devices, UINTN *count,
                             const ml_block_device *device)
{
    UINTN i;
    if (!devices || !count || !device) return 0;
    for (i = 0; i < *count; ++i)
        if (devices[i] == device) return 1;
    if (*count >= ML_MAX_STACK_DEVICES) return 0;
    devices[(*count)++] = device;
    return 1;
}
#endif

EFI_STATUS ml_storage_init(ml_uefi_storage *storage, EFI_HANDLE image_handle,
                           ml_config *config, ml_config_error *parse_error)
{
    EFI_HANDLE *fs_handles = NULL, *block_handles = NULL;
    UINTN fs_count = 0, i, found = 0;
#if ML_ENABLE_FS_XFS || ML_ENABLE_FS_EXT2 || ML_ENABLE_FS_EXT4 || ML_ENABLE_FS_VFAT || ML_ENABLE_FS_BTRFS || ML_ENABLE_FS_ZFS || ML_ENABLE_LVM || ML_ENABLE_LUKS1 || ML_ENABLE_LUKS2
    UINTN block_count = 0;
#if ML_ENABLE_FS_BTRFS || ML_ENABLE_FS_ZFS || ML_ENABLE_LVM || ML_ENABLE_LUKS1 || ML_ENABLE_LUKS2
    UINTN scan_device_count = 0;
#endif
    const ml_block_device **block_device_list = NULL;
#endif
    EFI_STATUS status;
    VOID *config_data = NULL;
    UINTN config_size = 0;
    EFI_LOADED_IMAGE_PROTOCOL *loaded = NULL;

    if (!storage || !config) return EFI_INVALID_PARAMETER;
    SetMem(storage, sizeof(*storage), 0);
    if (parse_error) SetMem(parse_error, sizeof(*parse_error), 0);
    status = BS->AllocatePool(EfiLoaderData,
        ML_MAX_VOLUMES * sizeof(*storage->volumes), (VOID **)&storage->volumes);
    if (EFI_ERROR(status)) return status;
    SetMem(storage->volumes, ML_MAX_VOLUMES * sizeof(*storage->volumes), 0);

    status = BS->LocateHandleBuffer(ByProtocol, &gEfiSimpleFileSystemProtocolGuid,
                                    NULL, &fs_count, &fs_handles);
    if (EFI_ERROR(status) && status != EFI_NOT_FOUND) {
        ml_storage_close(storage);
        return status;
    }
    if (fs_count > ML_MAX_VOLUMES) {
        if (fs_handles) BS->FreePool(fs_handles);
        ml_storage_close(storage);
        return EFI_OUT_OF_RESOURCES;
    }

    (VOID)BS->HandleProtocol(image_handle, &gEfiLoadedImageProtocolGuid, (VOID **)&loaded);
    if (loaded && loaded->DeviceHandle) {
        for (i = 0; i < fs_count; ++i) {
            if (fs_handles[i] == loaded->DeviceHandle) {
                EFI_HANDLE boot_handle = fs_handles[i];
                fs_handles[i] = fs_handles[0];
                fs_handles[0] = boot_handle;
                break;
            }
        }
    }

    for (i = 0; i < fs_count; ++i) {
        ml_uefi_volume *volume = &storage->volumes[storage->volume_count];
        VOID *interface = NULL;
        status = BS->HandleProtocol(fs_handles[i], &gEfiSimpleFileSystemProtocolGuid,
                                    &interface);
        if (EFI_ERROR(status) || !interface) continue;
        volume->handle = fs_handles[i];
        volume->fs = (EFI_SIMPLE_FILE_SYSTEM_PROTOCOL *)interface;
        status = volume->fs->OpenVolume(volume->fs, &volume->root);
        if (EFI_ERROR(status) || !volume->root) continue;
        partition_guid(volume->handle, volume->partition_guid);
        storage->volume_count++;
        status = scan_config(storage, volume, &found, &config_data,
                             &config_size, parse_error);
        if (EFI_ERROR(status)) goto fail;
    }

#if ML_ENABLE_FS_XFS || ML_ENABLE_FS_EXT2 || ML_ENABLE_FS_EXT4 || ML_ENABLE_FS_VFAT || ML_ENABLE_FS_BTRFS || ML_ENABLE_FS_ZFS || ML_ENABLE_LVM || ML_ENABLE_LUKS1 || ML_ENABLE_LUKS2
    status = BS->LocateHandleBuffer(ByProtocol, &gEfiBlockIoProtocolGuid,
                                    NULL, &block_count, &block_handles);
    if (EFI_ERROR(status) && status != EFI_NOT_FOUND) goto fail;
    if (block_count > ML_MAX_BLOCK_DEVICES) {
        status = EFI_OUT_OF_RESOURCES;
        goto fail;
    }
    if (block_count) {
        status = BS->AllocatePool(EfiLoaderData,
            block_count * sizeof(*storage->block_devices),
            (VOID **)&storage->block_devices);
        if (EFI_ERROR(status)) goto fail;
        SetMem(storage->block_devices,
               block_count * sizeof(*storage->block_devices), 0);
        status = BS->AllocatePool(EfiLoaderData,
            ML_MAX_STACK_DEVICES * sizeof(*block_device_list),
            (VOID **)&block_device_list);
        if (EFI_ERROR(status)) goto fail;
    }
    if (loaded && loaded->DeviceHandle) {
        for (i = 0; i < block_count; ++i) {
            if (block_handles[i] == loaded->DeviceHandle) {
                EFI_HANDLE boot_handle = block_handles[i];
                block_handles[i] = block_handles[0];
                block_handles[0] = boot_handle;
                break;
            }
        }
    }
    for (i = 0; i < block_count; ++i) {
        EFI_BLOCK_IO_PROTOCOL *protocol;
        VOID *interface = NULL;
        status = BS->HandleProtocol(block_handles[i], &gEfiBlockIoProtocolGuid,
                                    &interface);
        if (EFI_ERROR(status) || !interface) continue;
        protocol = (EFI_BLOCK_IO_PROTOCOL *)interface;
        if (!protocol->Media || !protocol->Media->MediaPresent) continue;
        status = ml_uefi_block_init(
            &storage->block_devices[storage->block_device_count], protocol);
        if (EFI_ERROR(status)) continue;
        storage->block_devices[storage->block_device_count].handle = block_handles[i];
        block_device_list[storage->block_device_count] =
            &storage->block_devices[storage->block_device_count].device;
        storage->block_device_count++;
    }
#if ML_ENABLE_FS_BTRFS || ML_ENABLE_FS_ZFS || ML_ENABLE_LVM || ML_ENABLE_LUKS1 || ML_ENABLE_LUKS2
    scan_device_count = storage->block_device_count;
#endif

#if ML_ENABLE_LUKS1
    for (i = 0; i < storage->block_device_count; ++i) {
        ml_luks1_volume *unlocked = NULL;
        status = unlock_luks_candidate(storage,
            &storage->block_devices[i].device, &unlocked, parse_error);
        if (EFI_ERROR(status)) goto fail;
        if (unlocked) {
            if (scan_device_count >= ML_MAX_STACK_DEVICES) {
                status = EFI_OUT_OF_RESOURCES;
                goto fail;
            }
            block_device_list[scan_device_count++] = &unlocked->device;
        }
}
#endif

#if ML_ENABLE_LUKS2
    for (i = 0; i < storage->block_device_count; ++i) {
        ml_luks2_volume *unlocked = NULL;
        status = unlock_luks2_candidate(storage,
            &storage->block_devices[i].device, &unlocked, parse_error);
        if (EFI_ERROR(status)) goto fail;
        if (unlocked) {
            if (scan_device_count >= ML_MAX_STACK_DEVICES) {
                status = EFI_OUT_OF_RESOURCES;
                goto fail;
            }
            block_device_list[scan_device_count++] = &unlocked->device;
        }
}
#endif

#if ML_ENABLE_FS_BTRFS
    if (scan_device_count) {
        status = BS->AllocatePool(EfiLoaderData,
            scan_device_count * sizeof(*storage->btrfs_devices),
            (VOID **)&storage->btrfs_devices);
        if (EFI_ERROR(status)) goto fail;
        CopyMem(storage->btrfs_devices, (VOID *)block_device_list,
                scan_device_count * sizeof(*storage->btrfs_devices));
        storage->btrfs_device_count = scan_device_count;
    }
    ml_btrfs_set_devices(storage->btrfs_devices, storage->btrfs_device_count);
#endif

#if ML_ENABLE_LVM
    if (scan_device_count) {
        const char *lvm_message = NULL;
        ml_lvm_result lvm_result;
        size_t lvm_vg_count = 0;
        status = BS->AllocatePool(EfiLoaderData,
            ML_LVM_MAX_VGS * sizeof(*storage->lvm_vgs),
            (VOID **)&storage->lvm_vgs);
        if (EFI_ERROR(status)) goto fail;
        SetMem(storage->lvm_vgs,
               ML_LVM_MAX_VGS * sizeof(*storage->lvm_vgs), 0);
        status = BS->AllocatePool(EfiLoaderData, ML_LVM_SCRATCH_BYTES,
                                  &storage->lvm_scratch);
        if (EFI_ERROR(status)) goto fail;
        lvm_result = ml_lvm_scan_all(storage->lvm_vgs, ML_LVM_MAX_VGS,
            &lvm_vg_count, block_device_list,
            scan_device_count, storage->lvm_scratch,
            ML_LVM_SCRATCH_BYTES, &lvm_message);
        if (lvm_result != ML_LVM_OK) {
            if (lvm_result != ML_LVM_NOT_FOUND) {
                storage->unsupported_lvm_count++;
                copy_storage_message(parse_error, lvm_message);
            }
            BS->FreePool(storage->lvm_scratch);
            BS->FreePool(storage->lvm_vgs);
            storage->lvm_scratch = NULL;
            storage->lvm_vgs = NULL;
            storage->lvm_vg_count = 0;
        } else {
            storage->lvm_vg_count = (UINTN)lvm_vg_count;
#if ML_ENABLE_FS_XFS || ML_ENABLE_FS_EXT2 || ML_ENABLE_FS_EXT4 || ML_ENABLE_FS_VFAT || ML_ENABLE_FS_BTRFS || ML_ENABLE_FS_ZFS || ML_ENABLE_LUKS1 || ML_ENABLE_LUKS2
            UINTN vg_index, lv_index;
            for (vg_index = 0; vg_index < storage->lvm_vg_count; ++vg_index) {
                for (lv_index = 0;
                     lv_index < storage->lvm_vgs[vg_index].lv_count;
                     ++lv_index) {
                    CHAR16 empty_partition[37];
                    SetMem(empty_partition, sizeof(empty_partition), 0);
#if ML_ENABLE_LUKS1
                    {
                        ml_luks1_volume *unlocked = NULL;
                        status = unlock_luks_candidate(storage,
                            &storage->lvm_vgs[vg_index].lvs[lv_index].device,
                            &unlocked, parse_error);
                        if (EFI_ERROR(status)) goto fail;
}
#endif
#if ML_ENABLE_LUKS2
                    {
                        ml_luks2_volume *unlocked = NULL;
                        status = unlock_luks2_candidate(storage,
                            &storage->lvm_vgs[vg_index].lvs[lv_index].device,
                            &unlocked, parse_error);
                        if (EFI_ERROR(status)) goto fail;
                    }
#endif
#if ML_ENABLE_FS_EXT2 || ML_ENABLE_FS_EXT4
                    status = mount_ext_candidate(storage, NULL, empty_partition,
                        &storage->lvm_vgs[vg_index].lvs[lv_index].device, &found,
                        &config_data, &config_size, parse_error);
                    if (EFI_ERROR(status)) goto fail;
#endif
#if ML_ENABLE_FS_XFS
                    status = mount_xfs_candidate(storage, NULL, empty_partition,
                        &storage->lvm_vgs[vg_index].lvs[lv_index].device, &found,
                        &config_data, &config_size, parse_error);
                    if (EFI_ERROR(status)) goto fail;
#endif
#if ML_ENABLE_FS_VFAT
                    status = mount_vfat_candidate(storage, NULL, empty_partition,
                        &storage->lvm_vgs[vg_index].lvs[lv_index].device, &found,
                        &config_data, &config_size, parse_error);
                    if (EFI_ERROR(status)) goto fail;
#endif
#if ML_ENABLE_FS_BTRFS
                    status = mount_btrfs_candidate(storage, NULL, empty_partition,
                        &storage->lvm_vgs[vg_index].lvs[lv_index].device, &found,
                        &config_data, &config_size, parse_error);
                    if (EFI_ERROR(status)) goto fail;
#endif
                }
            }
#endif
        }
    }
#endif

#if ML_ENABLE_FS_ZFS
    {
        CHAR16 empty_partition[37];
#if ML_ENABLE_LVM
        UINTN vg_index, lv_index;
        for (vg_index = 0; vg_index < storage->lvm_vg_count; ++vg_index)
            for (lv_index = 0;
                 lv_index < storage->lvm_vgs[vg_index].lv_count; ++lv_index)
                if (!append_zfs_device(block_device_list, &scan_device_count,
                        &storage->lvm_vgs[vg_index].lvs[lv_index].device)) {
                    status = EFI_OUT_OF_RESOURCES;
                    goto fail;
                }
#endif
#if ML_ENABLE_LUKS1
        for (i = 0; i < storage->luks_volume_count; ++i)
            if (!append_zfs_device(block_device_list, &scan_device_count,
                                   &storage->luks_volumes[i].device)) {
                status = EFI_OUT_OF_RESOURCES;
                goto fail;
            }
#endif
#if ML_ENABLE_LUKS2
        for (i = 0; i < storage->luks2_volume_count; ++i)
            if (!append_zfs_device(block_device_list, &scan_device_count,
                                   &storage->luks2_volumes[i].device)) {
                status = EFI_OUT_OF_RESOURCES;
                goto fail;
            }
#endif
        if (scan_device_count) {
            status = BS->AllocatePool(EfiLoaderData,
                scan_device_count * sizeof(*storage->zfs_devices),
                (VOID **)&storage->zfs_devices);
            if (EFI_ERROR(status)) goto fail;
            CopyMem(storage->zfs_devices, (VOID *)block_device_list,
                    scan_device_count * sizeof(*storage->zfs_devices));
            storage->zfs_device_count = scan_device_count;
        }
        ml_zfs_set_devices(storage->zfs_devices, storage->zfs_device_count);
        for (i = 0; i < scan_device_count; ++i) {
            SetMem(empty_partition, sizeof(empty_partition), 0);
            status = mount_zfs_candidate(storage, NULL, empty_partition,
                block_device_list[i], &found, &config_data, &config_size,
                parse_error);
            if (EFI_ERROR(status)) goto fail;
        }
    }
#endif

#if ML_ENABLE_FS_XFS || ML_ENABLE_FS_EXT2 || ML_ENABLE_FS_EXT4 || ML_ENABLE_FS_VFAT || ML_ENABLE_FS_BTRFS || ML_ENABLE_FS_ZFS
    for (i = 0; i < storage->block_device_count; ++i) {
        CHAR16 partition_id[37];
        partition_guid(storage->block_devices[i].handle, partition_id);
#if ML_ENABLE_FS_EXT2 || ML_ENABLE_FS_EXT4
        status = mount_ext_candidate(storage,
            storage->block_devices[i].handle, partition_id,
            &storage->block_devices[i].device, &found, &config_data,
            &config_size, parse_error);
        if (EFI_ERROR(status)) goto fail;
#endif
#if ML_ENABLE_FS_XFS
        status = mount_xfs_candidate(storage,
            storage->block_devices[i].handle, partition_id,
            &storage->block_devices[i].device, &found, &config_data,
            &config_size, parse_error);
        if (EFI_ERROR(status)) goto fail;
#endif
#if ML_ENABLE_FS_VFAT
        status = mount_vfat_candidate(storage,
            storage->block_devices[i].handle, partition_id,
            &storage->block_devices[i].device, &found, &config_data,
            &config_size, parse_error);
        if (EFI_ERROR(status)) goto fail;
#endif
#if ML_ENABLE_FS_BTRFS
        status = mount_btrfs_candidate(storage,
            storage->block_devices[i].handle, partition_id,
            &storage->block_devices[i].device, &found, &config_data,
            &config_size, parse_error);
        if (EFI_ERROR(status)) goto fail;
#endif
    }
#if ML_ENABLE_LUKS1
    for (i = 0; i < storage->luks_volume_count; ++i) {
        CHAR16 empty_partition[37];
        SetMem(empty_partition, sizeof(empty_partition), 0);
#if ML_ENABLE_FS_EXT2 || ML_ENABLE_FS_EXT4
        status = mount_ext_candidate(storage, NULL, empty_partition,
            &storage->luks_volumes[i].device, &found, &config_data,
            &config_size, parse_error);
        if (EFI_ERROR(status)) goto fail;
#endif
#if ML_ENABLE_FS_XFS
        status = mount_xfs_candidate(storage, NULL, empty_partition,
            &storage->luks_volumes[i].device, &found, &config_data,
            &config_size, parse_error);
        if (EFI_ERROR(status)) goto fail;
#endif
#if ML_ENABLE_FS_VFAT
        status = mount_vfat_candidate(storage, NULL, empty_partition,
            &storage->luks_volumes[i].device, &found, &config_data,
            &config_size, parse_error);
        if (EFI_ERROR(status)) goto fail;
#endif
#if ML_ENABLE_FS_BTRFS
        status = mount_btrfs_candidate(storage, NULL, empty_partition,
            &storage->luks_volumes[i].device, &found, &config_data,
            &config_size, parse_error);
        if (EFI_ERROR(status)) goto fail;
#endif
}
#endif
#if ML_ENABLE_LUKS2
    for (i = 0; i < storage->luks2_volume_count; ++i) {
        CHAR16 empty_partition[37];
        SetMem(empty_partition, sizeof(empty_partition), 0);
#if ML_ENABLE_FS_EXT2 || ML_ENABLE_FS_EXT4
        status = mount_ext_candidate(storage, NULL, empty_partition,
            &storage->luks2_volumes[i].device, &found, &config_data,
            &config_size, parse_error);
        if (EFI_ERROR(status)) goto fail;
#endif
#if ML_ENABLE_FS_XFS
        status = mount_xfs_candidate(storage, NULL, empty_partition,
            &storage->luks2_volumes[i].device, &found, &config_data,
            &config_size, parse_error);
        if (EFI_ERROR(status)) goto fail;
#endif
#if ML_ENABLE_FS_VFAT
        status = mount_vfat_candidate(storage, NULL, empty_partition,
            &storage->luks2_volumes[i].device, &found, &config_data,
            &config_size, parse_error);
        if (EFI_ERROR(status)) goto fail;
#endif
#if ML_ENABLE_FS_BTRFS
        status = mount_btrfs_candidate(storage, NULL, empty_partition,
            &storage->luks2_volumes[i].device, &found, &config_data,
            &config_size, parse_error);
        if (EFI_ERROR(status)) goto fail;
#endif
    }
#endif
#endif
#endif
    if (fs_handles) BS->FreePool(fs_handles);
    if (block_handles) BS->FreePool(block_handles);
#if ML_ENABLE_FS_XFS || ML_ENABLE_FS_EXT2 || ML_ENABLE_FS_EXT4 || ML_ENABLE_FS_VFAT || ML_ENABLE_FS_BTRFS || ML_ENABLE_FS_ZFS || ML_ENABLE_LVM || ML_ENABLE_LUKS1 || ML_ENABLE_LUKS2
    if (block_device_list) BS->FreePool(block_device_list);
#endif
    if (found == 0) {
        status = (storage->unsupported_ext_count || storage->unsupported_lvm_count ||
                  storage->unsupported_vfat_count || storage->unsupported_xfs_count ||
                  storage->unsupported_btrfs_count || storage->unsupported_zfs_count
#if ML_ENABLE_LUKS1 || ML_ENABLE_LUKS2
                  || storage->unsupported_luks_count
#endif
                 )
            ? EFI_UNSUPPORTED : EFI_NOT_FOUND;
        ml_storage_close(storage);
        return status;
    }
    if (found != 1) {
        BS->FreePool(config_data);
        ml_storage_close(storage);
        return EFI_ACCESS_DENIED;
    }
    if (!ml_config_parse((const char *)config_data, config_size, config, parse_error)) {
        BS->FreePool(config_data);
        ml_storage_close(storage);
        return EFI_INVALID_PARAMETER;
    }
    BS->FreePool(config_data);
    return EFI_SUCCESS;

fail:
    if (fs_handles) BS->FreePool(fs_handles);
    if (block_handles) BS->FreePool(block_handles);
#if ML_ENABLE_FS_XFS || ML_ENABLE_FS_EXT2 || ML_ENABLE_FS_EXT4 || ML_ENABLE_FS_VFAT || ML_ENABLE_FS_BTRFS || ML_ENABLE_FS_ZFS || ML_ENABLE_LVM || ML_ENABLE_LUKS1 || ML_ENABLE_LUKS2
    if (block_device_list) BS->FreePool(block_device_list);
#endif
    if (config_data) BS->FreePool(config_data);
    ml_storage_close(storage);
    return status;
}

ml_uefi_volume *ml_storage_find_volume(ml_uefi_storage *storage,
                                      const char *fs_uuid)
{
    UINTN i, matches = 0;
    ml_uefi_volume *match = NULL;
    if (!storage || !fs_uuid) return NULL;
    if (ascii_equal(fs_uuid, "boot") || ascii_equal(fs_uuid, "*"))
        return storage->config_volume;
    for (i = 0; i < storage->volume_count; ++i) {
        if (uuid_matches(storage->volumes[i].partition_guid, fs_uuid) ||
            (storage->volumes[i].filesystem_uuid[0] &&
             ascii_equal(storage->volumes[i].filesystem_uuid, fs_uuid))) {
            match = &storage->volumes[i];
            matches++;
        }
    }
    return matches == 1 ? match : NULL;
}

void ml_storage_close(ml_uefi_storage *storage)
{
    UINTN i;
    if (!storage) return;
    for (i = 0; i < storage->volume_count; ++i)
        if (storage->volumes[i].root) storage->volumes[i].root->Close(storage->volumes[i].root);
#if ML_ENABLE_FS_XFS
    for (i = 0; i < storage->volume_count; ++i)
        if (storage->volumes[i].kind == ML_VOLUME_XFS_FS)
            ml_xfs_unmount(&storage->volumes[i].xfs);
#endif
#if ML_ENABLE_FS_BTRFS
    for (i = 0; i < storage->volume_count; ++i)
        if (storage->volumes[i].kind == ML_VOLUME_BTRFS_FS)
            ml_btrfs_unmount(&storage->volumes[i].btrfs);
    ml_btrfs_set_devices(NULL, 0);
    if (storage->btrfs_devices) BS->FreePool(storage->btrfs_devices);
#endif
#if ML_ENABLE_FS_ZFS
    for (i = 0; i < storage->volume_count; ++i)
        if (storage->volumes[i].kind == ML_VOLUME_ZFS_FS)
            ml_zfs_unmount(&storage->volumes[i].zfs);
    ml_zfs_set_devices(NULL, 0);
    if (storage->zfs_devices) BS->FreePool(storage->zfs_devices);
#endif
#if ML_ENABLE_FS_XFS || ML_ENABLE_FS_EXT2 || ML_ENABLE_FS_EXT4 || ML_ENABLE_FS_VFAT || ML_ENABLE_FS_BTRFS || ML_ENABLE_FS_ZFS || ML_ENABLE_LVM || ML_ENABLE_LUKS1 || ML_ENABLE_LUKS2
    for (i = 0; i < storage->block_device_count; ++i)
        ml_uefi_block_close(&storage->block_devices[i]);
    if (storage->block_devices) BS->FreePool(storage->block_devices);
#endif
#if ML_ENABLE_LUKS1
    if (storage->luks_volumes) {
        for (i = 0; i < storage->luks_volume_count; ++i)
            wipe_bytes(&storage->luks_volumes[i],
                       sizeof(storage->luks_volumes[i]));
        BS->FreePool(storage->luks_volumes);
    }
    if (storage->luks_scratch) {
        wipe_bytes(storage->luks_scratch, ML_LUKS1_SCRATCH_BYTES);
        BS->FreePool(storage->luks_scratch);
}
#endif
#if ML_ENABLE_LUKS2
    if (storage->luks2_volumes) {
        for (i = 0; i < storage->luks2_volume_count; ++i)
            wipe_bytes(&storage->luks2_volumes[i],
                       sizeof(storage->luks2_volumes[i]));
        BS->FreePool(storage->luks2_volumes);
    }
    if (storage->luks2_scratch) {
        wipe_bytes(storage->luks2_scratch, ML_LUKS2_SCRATCH_BYTES);
        BS->FreePool(storage->luks2_scratch);
    }
#endif
#if ML_ENABLE_LVM
    if (storage->lvm_scratch) BS->FreePool(storage->lvm_scratch);
    if (storage->lvm_vgs) BS->FreePool(storage->lvm_vgs);
#endif
    if (storage->extfs_scratch) BS->FreePool(storage->extfs_scratch);
    if (storage->volumes) BS->FreePool(storage->volumes);
    SetMem(storage, sizeof(*storage), 0);
}
