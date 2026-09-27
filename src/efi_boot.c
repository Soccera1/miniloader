/* SPDX-License-Identifier: GPL-3.0-or-later */
#include "ml_uefi.h"

static VOID *active_initrd;
static UINTN active_initrd_size;

static UINTN ascii_length(const char *text)
{
    UINTN length = 0;
    while (text[length]) length++;
    return length;
}

typedef struct __attribute__((packed)) {
    EFI_DEVICE_PATH_PROTOCOL vendor_header;
    EFI_GUID vendor_guid;
    EFI_DEVICE_PATH_PROTOCOL end_header;
} ml_initrd_device_path;

static EFI_STATUS EFIAPI initrd_load_file(EFI_LOAD_FILE2_PROTOCOL *protocol,
                                          EFI_DEVICE_PATH_PROTOCOL *path,
                                          BOOLEAN boot_policy,
                                          UINTN *buffer_size,
                                          VOID *buffer)
{
    (void)protocol;
    (void)path;
    if (!buffer_size) return EFI_INVALID_PARAMETER;
    if (boot_policy) return EFI_UNSUPPORTED;
    if (!buffer || *buffer_size < active_initrd_size) {
        *buffer_size = active_initrd_size;
        return EFI_BUFFER_TOO_SMALL;
    }
    CopyMem(buffer, active_initrd, active_initrd_size);
    *buffer_size = active_initrd_size;
    return EFI_SUCCESS;
}

static EFI_LOAD_FILE2_PROTOCOL initrd_protocol = { initrd_load_file };
static ml_initrd_device_path initrd_path = {
    { MEDIA_DEVICE_PATH, MEDIA_VENDOR_DP, {0, 0} },
    { 0x5568e427, 0x68fc, 0x4f3d, {0xac, 0x74, 0xca, 0x55, 0x52, 0x31, 0xcc, 0x68} },
    { END_DEVICE_PATH_TYPE, END_ENTIRE_DEVICE_PATH_SUBTYPE, {0, 0} }
};

static void output_ascii(const char *text)
{
    CHAR16 chunk[128];
    UINTN i = 0, at = 0;
    if (!text || !ST || !ST->ConOut) return;
    while (text[at]) {
        i = 0;
        while (text[at] && i + 1 < sizeof(chunk) / sizeof(chunk[0]))
            chunk[i++] = (CHAR16)(UINT8)text[at++];
        chunk[i] = L'\0';
        ST->ConOut->OutputString(ST->ConOut, chunk);
    }
}

void ml_console_ascii(const char *text)
{
    output_ascii(text);
}

static void print_menu(const ml_config *config, UINTN selected, UINTN seconds_left)
{
    UINTN i;
    CHAR16 title[] = L"MiniLoader - select an entry\r\n\r\n";
    CHAR16 timeout_text[] = L"\r\nUse Up/Down and Enter. Booting in ";
    CHAR16 suffix[] = L" seconds.\r\n";
    CHAR16 number[2];

    ST->ConOut->ClearScreen(ST->ConOut);
    ST->ConOut->SetAttribute(ST->ConOut, 0x0f);
    ST->ConOut->OutputString(ST->ConOut, title);
    for (i = 0; i < config->entry_count; ++i) {
        CHAR16 line[ML_NAME_MAX + 16];
        UINTN p = 0, j;
        if (i == selected) ST->ConOut->SetAttribute(ST->ConOut, 0x1f);
        else ST->ConOut->SetAttribute(ST->ConOut, 0x07);
        line[p++] = (i == selected) ? L'>' : L' ';
        line[p++] = L' ';
        for (j = 0; config->entries[i].name[j] && p + 3 < sizeof(line) / sizeof(line[0]); ++j)
            line[p++] = (CHAR16)(UINT8)config->entries[i].name[j];
        line[p++] = L'\r';
        line[p++] = L'\n';
        line[p] = L'\0';
        ST->ConOut->OutputString(ST->ConOut, line);
    }
    ST->ConOut->SetAttribute(ST->ConOut, 0x07);
    ST->ConOut->OutputString(ST->ConOut, timeout_text);
    number[0] = (CHAR16)(L'0' + (seconds_left / 10) % 10);
    number[1] = (CHAR16)(L'0' + seconds_left % 10);
    {
        CHAR16 digits[3] = {number[0], number[1], L'\0'};
        ST->ConOut->OutputString(ST->ConOut, digits);
    }
    ST->ConOut->OutputString(ST->ConOut, suffix);
}

EFI_STATUS ml_boot_menu(const ml_config *config, UINTN *selected)
{
    EFI_INPUT_KEY key;
    UINTN current, tick;
    UINTN remaining;
    EFI_STATUS status;
    if (!config || !selected || config->entry_count == 0 || config->default_index < 0)
        return EFI_INVALID_PARAMETER;
    current = (UINTN)config->default_index;
    remaining = config->timeout_seconds;
    if (remaining == 0) { *selected = current; return EFI_SUCCESS; }

    print_menu(config, current, remaining);
    for (;;) {
        for (tick = 0; tick < 10; ++tick) {
            status = ST->ConIn->ReadKeyStroke(ST->ConIn, &key);
            if (!EFI_ERROR(status)) {
                if (key.ScanCode == SCAN_UP) {
                    current = current == 0 ? config->entry_count - 1 : current - 1;
                    print_menu(config, current, remaining);
                } else if (key.ScanCode == SCAN_DOWN) {
                    current = (current + 1) % config->entry_count;
                    print_menu(config, current, remaining);
                } else if (key.UnicodeChar == CHAR_CARRIAGE_RETURN) {
                    *selected = current;
                    return EFI_SUCCESS;
                } else if (key.UnicodeChar == 0x1b) {
                    *selected = (UINTN)config->default_index;
                    return EFI_SUCCESS;
                }
            }
            BS->Stall(100000);
        }
        if (remaining > 0) remaining--;
        if (remaining == 0) { *selected = current; return EFI_SUCCESS; }
        print_menu(config, current, remaining);
    }
}

static EFI_STATUS install_initrd_protocol(VOID *initrd, UINTN initrd_size,
                                          EFI_HANDLE *handle)
{
    active_initrd = initrd;
    active_initrd_size = initrd_size;
    initrd_path.vendor_header.Length[0] = (UINT8)(sizeof(VENDOR_DEVICE_PATH) & 0xff);
    initrd_path.vendor_header.Length[1] = (UINT8)(sizeof(VENDOR_DEVICE_PATH) >> 8);
    initrd_path.end_header.Length[0] = (UINT8)sizeof(EFI_DEVICE_PATH_PROTOCOL);
    initrd_path.end_header.Length[1] = 0;
    *handle = NULL;
    return BS->InstallMultipleProtocolInterfaces(handle,
        &gEfiLoadFile2ProtocolGuid, &initrd_protocol,
        &gEfiDevicePathProtocolGuid, &initrd_path,
        NULL);
}

static void uninstall_initrd_protocol(EFI_HANDLE handle)
{
    if (handle) {
        BS->UninstallMultipleProtocolInterfaces(handle,
            &gEfiLoadFile2ProtocolGuid, &initrd_protocol,
            &gEfiDevicePathProtocolGuid, &initrd_path,
            NULL);
    }
    active_initrd = NULL;
    active_initrd_size = 0;
}

static EFI_STATUS launch(EFI_HANDLE image_handle, ml_uefi_volume *volume,
                         const char *image_path, const char *cmdline,
                         const char *initrd_path_ascii)
{
    VOID *image_bytes = NULL, *initrd_bytes = NULL;
    UINTN image_size = 0, initrd_size = 0;
    CHAR16 *load_options = NULL;
    UINTN option_count = 0, i;
    EFI_HANDLE child = NULL, initrd_handle = NULL;
    EFI_LOADED_IMAGE_PROTOCOL *loaded = NULL;
    EFI_STATUS status;

    status = ml_storage_read(volume, image_path, &image_bytes, &image_size);
    if (EFI_ERROR(status)) return status;
    if (image_size == 0) { BS->FreePool(image_bytes); return EFI_LOAD_ERROR; }
    if (initrd_path_ascii) {
        status = ml_storage_read(volume, initrd_path_ascii, &initrd_bytes, &initrd_size);
        if (EFI_ERROR(status)) { BS->FreePool(image_bytes); return status; }
    }

    status = BS->LoadImage(FALSE, image_handle, NULL, image_bytes, image_size, &child);
    BS->FreePool(image_bytes);
    if (EFI_ERROR(status)) goto done;
    status = BS->HandleProtocol(child, &gEfiLoadedImageProtocolGuid, (VOID **)&loaded);
    if (EFI_ERROR(status) || !loaded) { status = EFI_LOAD_ERROR; goto done; }
    loaded->DeviceHandle = volume->handle;

    if (cmdline) {
        option_count = ascii_length(cmdline);
        status = BS->AllocatePool(EfiLoaderData, (option_count + 1) * sizeof(CHAR16),
                                  (VOID **)&load_options);
        if (EFI_ERROR(status)) goto done;
        for (i = 0; i < option_count; ++i) load_options[i] = (CHAR16)(UINT8)cmdline[i];
        load_options[option_count] = L'\0';
        loaded->LoadOptions = load_options;
        loaded->LoadOptionsSize = (UINT32)((option_count + 1) * sizeof(CHAR16));
    }

    if (initrd_bytes) {
        status = install_initrd_protocol(initrd_bytes, initrd_size, &initrd_handle);
        if (EFI_ERROR(status)) goto done;
    }
    (VOID)BS->SetWatchdogTimer(0, 0, 0, NULL);
    status = BS->StartImage(child, NULL, NULL);

done:
    uninstall_initrd_protocol(initrd_handle);
    if (initrd_bytes) BS->FreePool(initrd_bytes);
    if (load_options) BS->FreePool(load_options);
    if (child) (VOID)BS->UnloadImage(child);
    return status;
}

EFI_STATUS ml_boot_entry(EFI_HANDLE image_handle, ml_uefi_volume *volume,
                         const ml_entry *entry)
{
    if (!image_handle || !volume || !entry) return EFI_INVALID_PARAMETER;
    if (entry->type == ML_ENTRY_EFI)
        return launch(image_handle, volume, entry->path, NULL, NULL);
    if (entry->type == ML_ENTRY_LINUX)
        return launch(image_handle, volume, entry->kernel, entry->cmdline, entry->initrd);
    return EFI_UNSUPPORTED;
}
