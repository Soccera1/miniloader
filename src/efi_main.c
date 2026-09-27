/* SPDX-License-Identifier: GPL-3.0-or-later */
#include "ml_uefi.h"

static void report_error(EFI_STATUS status, const ml_config_error *parse_error)
{
    if (status == EFI_NOT_FOUND) {
        ml_console_ascii("MiniLoader: /boot/miniloader.conf was not found on any firmware-visible volume.\r\n");
    } else if (status == EFI_ACCESS_DENIED) {
        ml_console_ascii("MiniLoader: more than one /boot/miniloader.conf was found; refusing an ambiguous configuration.\r\n");
    } else if (status == EFI_INVALID_PARAMETER && parse_error &&
               parse_error->message[0]) {
        ml_console_ascii("MiniLoader: configuration error at line ");
        {
            char line[24];
            UINTN n = parse_error->line, p = sizeof(line);
            line[--p] = '\0';
            do { line[--p] = (char)('0' + n % 10); n /= 10; } while (n && p > 1);
            ml_console_ascii(line + p);
        }
        ml_console_ascii(": ");
        ml_console_ascii(parse_error->message);
        ml_console_ascii("\r\n");
    } else if (status == EFI_UNSUPPORTED && parse_error &&
               parse_error->message[0]) {
        ml_console_ascii("MiniLoader: ");
        ml_console_ascii(parse_error->message);
        ml_console_ascii("\r\n");
    } else if (status == EFI_UNSUPPORTED) {
        ml_console_ascii("MiniLoader: the selected filesystem has unsupported features or a path type this build cannot read.\r\n");
    } else {
        ml_console_ascii("MiniLoader: EFI operation failed (status ");
        {
            static const char hex[] = "0123456789abcdef";
            char digits[19];
            UINTN i;
            digits[0] = '0'; digits[1] = 'x';
            for (i = 0; i < 16; ++i) digits[2 + i] = hex[(status >> ((15 - i) * 4)) & 0xf];
            digits[18] = '\0';
            ml_console_ascii(digits);
        }
        ml_console_ascii(").\r\n");
    }
    ml_console_ascii("Press any key to return to firmware.\r\n");
    {
        EFI_INPUT_KEY key;
        EFI_EVENT event = ST->ConIn->WaitForKey;
        UINTN index;
        if (!EFI_ERROR(BS->WaitForEvent(1, &event, &index)))
            (VOID)ST->ConIn->ReadKeyStroke(ST->ConIn, &key);
    }
}

EFI_STATUS EFIAPI efi_main(EFI_HANDLE image_handle, EFI_SYSTEM_TABLE *system_table)
{
    ml_config *config = NULL;
    ml_config_error parse_error;
    ml_uefi_storage storage;
    EFI_STATUS status;
    UINTN selected;
    ml_uefi_volume *volume;

    ST = system_table;
    BS = system_table->BootServices;
    if (ST && ST->ConOut) {
        ST->ConOut->ClearScreen(ST->ConOut);
        ml_console_ascii("MiniLoader starting...\r\n");
    }
    SetMem(&parse_error, sizeof(parse_error), 0);
    status = BS->AllocatePool(EfiLoaderData, sizeof(*config), (VOID **)&config);
    if (EFI_ERROR(status)) {
        report_error(status, NULL);
        return status;
    }
    status = ml_storage_init(&storage, image_handle, config, &parse_error);
    if (EFI_ERROR(status)) {
        report_error(status, &parse_error);
        BS->FreePool(config);
        return status;
    }
    status = ml_boot_menu(config, &selected);
    if (!EFI_ERROR(status)) {
        const ml_entry *entry = &config->entries[selected];
        volume = ml_storage_find_volume(&storage, entry->fs_uuid);
        if (!volume) {
            ml_console_ascii("MiniLoader: fs_uuid does not identify exactly one firmware-visible partition: ");
            ml_console_ascii(entry->fs_uuid);
            ml_console_ascii("\r\n");
            status = EFI_NOT_FOUND;
        } else {
            ml_console_ascii("Starting ");
            ml_console_ascii(entry->name);
            ml_console_ascii("...\r\n");
            status = ml_boot_entry(image_handle, volume, entry);
        }
    }
    if (EFI_ERROR(status)) report_error(status, NULL);
    ml_storage_close(&storage);
    BS->FreePool(config);
    return status;
}
