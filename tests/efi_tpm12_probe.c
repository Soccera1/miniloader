/* SPDX-License-Identifier: GPL-3.0-or-later */
#include <efi.h>

typedef struct ml_tcg_protocol ml_tcg_protocol;
struct ml_tcg_protocol {
    VOID *StatusCheck;
    VOID *HashAll;
    VOID *LogEvent;
    EFI_STATUS (EFIAPI *PassThroughToTpm)(ml_tcg_protocol *This,
        UINT32 InputParameterBlockSize, UINT8 *InputParameterBlock,
        UINT32 OutputParameterBlockSize, UINT8 *OutputParameterBlock);
    VOID *HashLogExtendEvent;
};

static EFI_GUID tcg_protocol_guid = {
    0xf541796d, 0xa62e, 0x4954,
    { 0xa7, 0x75, 0x95, 0x84, 0xf6, 0x1b, 0x9c, 0xdd }
};

static void report(EFI_SYSTEM_TABLE *system_table, const CHAR16 *message)
{
    if (system_table && system_table->ConOut)
        system_table->ConOut->OutputString(system_table->ConOut,
                                           (CHAR16 *)message);
}

EFI_STATUS EFIAPI efi_main(EFI_HANDLE image_handle,
                           EFI_SYSTEM_TABLE *system_table)
{
    static UINT8 command[14] = {
        0x00, 0xc1, 0x00, 0x00, 0x00, 0x0e,
        0x00, 0x00, 0x00, 0x46, 0x00, 0x00, 0x00, 0x10
    };
    UINT8 response[64] = {0};
    UINT32 response_size;
    ml_tcg_protocol *protocol = NULL;
    EFI_STATUS status;
    (void)image_handle;
    status = system_table->BootServices->LocateProtocol(&tcg_protocol_guid,
        NULL, (VOID **)&protocol);
    if (EFI_ERROR(status) || !protocol || !protocol->PassThroughToTpm) {
        report(system_table, L"MINILOADER_TCG_PROTOCOL_MISSING\r\n");
        return EFI_NOT_FOUND;
    }
    status = protocol->PassThroughToTpm(protocol, sizeof(command), command,
        sizeof(response), response);
    if (EFI_ERROR(status)) {
        report(system_table, L"MINILOADER_TCG_SUBMIT_EFI_ERROR\r\n");
        return EFI_DEVICE_ERROR;
    }
    response_size = ((UINT32)response[2] << 24) |
                    ((UINT32)response[3] << 16) |
                    ((UINT32)response[4] << 8) | response[5];
    if (response_size != 30) {
        report(system_table, L"MINILOADER_TCG_SIZE_MISMATCH\r\n");
        return EFI_DEVICE_ERROR;
    }
    if (response[0] != 0x00 || response[1] != 0xc4) {
        report(system_table, L"MINILOADER_TCG_TAG_MISMATCH\r\n");
        return EFI_DEVICE_ERROR;
    }
    if (response[6] || response[7] || response[8] || response[9]) {
        report(system_table, L"MINILOADER_TCG_TPM_ERROR\r\n");
        return EFI_DEVICE_ERROR;
    }
    if (response[10] != 0 || response[11] != 0 ||
        response[12] != 0 || response[13] != 16) {
        report(system_table, L"MINILOADER_TCG_SUBMIT_FAILED\r\n");
        return EFI_DEVICE_ERROR;
    }
    report(system_table, L"MINILOADER_TCG_SUBMIT_OK\r\n");
    return EFI_SUCCESS;
}
