The ZFS positive-read fixture is `zol-0.6.2.tar.bz2` from the OpenZFS
reference pool collection at <https://github.com/openzfs/zfs-images>. It
contains a four-vdev RAID-Z pool created by ZoL 0.6.2. The test extracts the
archive into a temporary directory and reads `fs@/L3F1` through MiniLoader's
read-only ZFS adapter. The test-only fixture is not linked into the EFI image.
