/* SPDX-License-Identifier: GPL-3.0-or-later */
#include "ml_config.h"
#include <assert.h>
#include <stdio.h>
#include <string.h>

static void parses_entries_and_default(void)
{
    const char config_text[] =
        "timeout = 7\n"
        "default = rescue\n"
        "[linux-main]\n"
        "type=linux\n"
        "fs_uuid=01234567-89ab-cdef-0123-456789abcdef\n"
        "kernel=\\EFI\\Linux\\vmlinuz.efi\n"
        "initrd=\\EFI\\Linux\\initrd.img\n"
        "cmdline=root=UUID=abc quiet\n"
        "\n"
        "[rescue]\n"
        "type=efi\n"
        "fs_uuid=boot\n"
        "path=\\EFI\\Tools\\shell.efi\n";
    ml_config config;
    ml_config_error error;
    assert(ml_config_parse(config_text, sizeof(config_text) - 1, &config, &error));
    assert(config.timeout_seconds == 7);
    assert(config.entry_count == 2);
    assert(config.default_index == 1);
    assert(config.entries[0].type == ML_ENTRY_LINUX);
    assert(strcmp(config.entries[0].cmdline, "root=UUID=abc quiet") == 0);
    assert(config.entries[1].type == ML_ENTRY_EFI);
}

static void rejects_bad_configs(void)
{
    const char *cases[] = {
        "timeout=3601\n[a]\ntype=efi\nfs_uuid=boot\npath=x\n",
        "[a]\ntype=linux\nfs_uuid=boot\nkernel=k\ninitrd=i\n",
        "[a]\ntype=efi\nfs_uuid=boot\npath=x\npath=y\n",
        "[a]\ntype=efi\nfs_uuid=boot\npath=x\n[b]\ntype=efi\nfs_uuid=boot\npath=y\ndefault=c\n",
        "[a]\ntype=efi\nfs_uuid=boot\npath=x\n[a]\ntype=efi\nfs_uuid=boot\npath=y\n",
        "[a]\ntype=efi\nfs_uuid=boot\npath=caf\xc3\xa9\n",
    };
    size_t i;
    for (i = 0; i < sizeof(cases) / sizeof(cases[0]); ++i) {
        ml_config config;
        ml_config_error error;
        assert(!ml_config_parse(cases[i], strlen(cases[i]), &config, &error));
        assert(error.message[0] != '\0');
    }
}

int main(void)
{
    parses_entries_and_default();
    rejects_bad_configs();
    puts("config parser tests passed");
    return 0;
}
