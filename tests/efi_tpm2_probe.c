/* SPDX-License-Identifier: GPL-3.0-or-later */
#include <efi.h>

typedef struct ml_tcg2_protocol ml_tcg2_protocol;
struct ml_tcg2_protocol {
    VOID *GetCapability;
    VOID *GetEventLog;
    VOID *HashLogExtendEvent;
    EFI_STATUS (EFIAPI *SubmitCommand)(ml_tcg2_protocol *This,
        UINT32 InputParameterBlockSize, UINT8 *InputParameterBlock,
        UINT32 OutputParameterBlockSize, UINT8 *OutputParameterBlock);
};

static EFI_GUID tcg2_protocol_guid = {
    0x607f766c, 0x7455, 0x42be,
    { 0x93, 0x0b, 0xe4, 0xd7, 0x6d, 0xb2, 0x72, 0x0f }
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
    static UINT8 command[12] = {
        0x80, 0x01, 0x00, 0x00, 0x00, 0x0c,
        0x00, 0x00, 0x01, 0x7b, 0x00, 0x10
    };
    UINT8 response[64] = {0};
    UINT32 response_size;
    ml_tcg2_protocol *protocol = NULL;
    EFI_STATUS status;
    (void)image_handle;
    status = system_table->BootServices->LocateProtocol(&tcg2_protocol_guid,
        NULL, (VOID **)&protocol);
    if (EFI_ERROR(status) || !protocol || !protocol->SubmitCommand) {
        report(system_table, L"MINILOADER_TCG2_PROTOCOL_MISSING\r\n");
        return EFI_NOT_FOUND;
    }
    status = protocol->SubmitCommand(protocol, sizeof(command), command,
        sizeof(response), response);
    if (EFI_ERROR(status)) {
        report(system_table, L"MINILOADER_TCG2_SUBMIT_EFI_ERROR\r\n");
        return EFI_DEVICE_ERROR;
    }
    response_size = ((UINT32)response[2] << 24) |
                    ((UINT32)response[3] << 16) |
                    ((UINT32)response[4] << 8) | response[5];
    if (response_size < 12 || response[0] != 0x80 ||
        response[1] != 0x01 || response[6] || response[7] ||
        response[8] || response[9] || response_size != 28 ||
        response[10] != 0 || response[11] != 16) {
        report(system_table, L"MINILOADER_TCG2_SUBMIT_FAILED\r\n");
        return EFI_DEVICE_ERROR;
    }
    report(system_table, L"MINILOADER_TCG2_SUBMIT_OK\r\n");
    return EFI_SUCCESS;
}
