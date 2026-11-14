import hashlib
from dataclasses import dataclass, replace
from pathlib import Path


class CorpusManifestError(Exception):
    pass


@dataclass(frozen=True)
class ImageRef:
    path: Path
    md5: str
    family: str
    ver: str
    sku: str
    tier: int
    path_rel: Path | None = None


def _ref(path: str, md5: str, family: str, ver: str, sku: str, tier: int) -> ImageRef:
    return ImageRef(path=Path(path), md5=md5, family=family, ver=ver, sku=sku, tier=tier, path_rel=Path(path))


T1 = [
    _ref("refs/fw/cx-4/fw-ConnectX4-rel-12_28_4706-MCX456A-ECA_Ax-UEFI-14.21.21-FlexBoot-3.6.103.bin", "1289bec02c2774e1df2f801097a4f6ed", "cx4", "12_28_4706", "MCX456A-ECA", 1),
    _ref("refs/fw/cx-4/fw-ConnectX4Lx-rel-14_32_1900-MCX4131A-GCA_Ax-UEFI-14.25.17-FlexBoot-3.6.502.bin", "3bd3230b1deae0cf74a08e31d59021d9", "cx4lx", "14_32_1900", "MCX4131A-GCA", 1),
    _ref("refs/fw/cx-4/fw-ConnectX4Lx-rel-14_32_1912-MCX4121A-ACA_Ax-UEFI-14.25.17-FlexBoot-3.6.502.bin", "942dd252545aba822cfd6eca524980f0", "cx4lx", "14_32_1912", "MCX4121A-ACA", 1),
    _ref("refs/fw/cx-5-6/fw-ConnectX5-rel-16_35_4030-MCX516A-CDA_Ax_Bx-UEFI-14.29.15-FlexBoot-3.6.902.bin", "a8c60c90473078288b01009c7cad471b", "cx5", "16_35_4030", "MCX516A-CDA", 1),
    _ref("refs/fw/cx-5-6/fw-ConnectX5-rel-16_35_8008-MCX512A-ACA_Ax_Bx-UEFI-14.29.15-FlexBoot-3.6.902.bin", "7dce14844bb0aad995f9c4379836e0b7", "cx5", "16_35_8008", "MCX512A-ACA", 1),
    _ref("refs/fw/cx-5-6/fw-ConnectX5-rel-16_19_1200-MCX556A-ECA_Ax-FlexBoot-3.5.110.bin", "ab4c5ac04bbbdeec6772611f79014d13", "cx5", "16_19_1200", "MCX556A-ECA", 1),
    _ref("refs/fw/cx-5-6/fw-ConnectX6-rel-20_43_1014-MCX654105A-HCA_Ax-UEFI-14.36.16-FlexBoot-3.7.500.bin", "b0d7b8aecb19667790e954e7e588a757", "cx6", "20_43_1014", "MCX654105A-HCA", 1),
    _ref("refs/fw/cx-5-6/fw-ConnectX6Dx-rel-22_50_1002-MCX623435AC-CDA_Ax-UEFI-14.43.10-FlexBoot-3.9.101.signed.bin", "35cb50eaefc8ac7da5e5c6c4e68870a6", "cx6dx", "22_50_1002", "MCX623435AC-CDA", 1),
    _ref("refs/fw/cx-5-6/fw-ConnectX6Dx-rel-22_47_3576-MCX683105AN-HDA_Ax-UEFI-14.40.10-FlexBoot-3.8.201.bin", "e9d26101da6c624bc9a58fcef96d7e9f", "cx6dx", "22_47_3576", "MCX683105AN-HDA", 1),
    _ref("refs/fw/cx-5-6/fw-ConnectX6Lx-rel-26_50_1002-MCX631435AE-GDA_Ax-UEFI-14.43.10-FlexBoot-3.9.101.bin", "c1cbe6c30556bcc330e18ae3b843db9b", "cx6lx", "26_50_1002", "MCX631435AE-GDA", 1),
]

T2 = [
    _ref("refs/fw/cx-4/fw-ConnectX4-rel-12_28_4706-MCX413A-BCA_Ax-UEFI-14.21.21-FlexBoot-3.6.103.bin", "a54be2b6e35da892752d8f2d6c5242bd", "cx4", "12_28_4706", "MCX413A-BCA", 2),
    _ref("refs/fw/cx-4/fw-ConnectX4-rel-12_28_4706-MCX413A-GCA_Ax-UEFI-14.21.21-FlexBoot-3.6.103.bin", "3b700e9a9f8dfff956d8994ed9f227a0", "cx4", "12_28_4706", "MCX413A-GCA", 2),
    _ref("refs/fw/cx-4/fw-ConnectX4-rel-12_28_4706-MCX414A-BCA_Ax-UEFI-14.21.21-FlexBoot-3.6.103.bin", "c945d056c7eb2c169d875fcbe9d4ba73", "cx4", "12_28_4706", "MCX414A-BCA", 2),
    _ref("refs/fw/cx-4/fw-ConnectX4-rel-12_28_4706-MCX414A-GCA_Ax-UEFI-14.21.21-FlexBoot-3.6.103.bin", "9d0d4068cdb2862d9e27bbfc0b7194a5", "cx4", "12_28_4706", "MCX414A-GCA", 2),
    _ref("refs/fw/cx-4/fw-ConnectX4-rel-12_28_4706-MCX416A-CCA_Ax-UEFI-14.21.21-FlexBoot-3.6.103.bin", "a6b633e13333329613f5229a719e555a", "cx4", "12_28_4706", "MCX416A-CCA", 2),
    _ref("refs/fw/cx-4/fw-ConnectX4-rel-12_28_4706-MCX456A-ECA_Ax-UEFI-14.21.21-FlexBoot-3.6.103.bin", "1289bec02c2774e1df2f801097a4f6ed", "cx4", "12_28_4706", "MCX456A-ECA", 2),
    _ref("refs/fw/cx-4/fw-ConnectX4-rel-12_28_4706-MCX456A-FCA_Ax-UEFI-14.21.21-FlexBoot-3.6.103.bin", "64ea3c6de943e84e8d63076451a2680d", "cx4", "12_28_4706", "MCX456A-FCA", 2),
    _ref("refs/fw/cx-4/fw-ConnectX4Lx-rel-14_32_1912-MCX4111A-ACA_Ax-UEFI-14.25.17-FlexBoot-3.6.502.bin", "6beb5aaf167c28fbff280bc3c3c2d02f", "cx4lx", "14_32_1912", "MCX4111A-ACA", 2),
    _ref("refs/fw/cx-4/fw-ConnectX4Lx-rel-14_32_1912-MCX4111A-ACUT_Ax-UEFI-14.25.17-FlexBoot-3.6.502.bin", "00dec4ed682cda22ac29201e8d658045", "cx4lx", "14_32_1912", "MCX4111A-ACUT", 2),
    _ref("refs/fw/cx-4/fw-ConnectX4Lx-rel-14_32_1912-MCX4111A-XCA_Ax-UEFI-14.25.17-FlexBoot-3.6.502.bin", "467ec70dc78237516d6cd7e5605a5d68", "cx4lx", "14_32_1912", "MCX4111A-XCA", 2),
    _ref("refs/fw/cx-4/fw-ConnectX4Lx-rel-14_32_1912-MCX4121A-ACA_Ax-UEFI-14.25.17-FlexBoot-3.6.502.bin", "942dd252545aba822cfd6eca524980f0", "cx4lx", "14_32_1912", "MCX4121A-ACA", 2),
    _ref("refs/fw/cx-4/fw-ConnectX4Lx-rel-14_32_1912-MCX4131A-BCA_Ax-UEFI-14.25.17-FlexBoot-3.6.502.bin", "e3f6620528c7c824d9671271da645794", "cx4lx", "14_32_1912", "MCX4131A-BCA", 2),
    _ref("refs/fw/cx-4/fw-ConnectX4Lx-rel-14_32_1912-MCX4131A-GCA_Ax-UEFI-14.25.17-FlexBoot-3.6.502.bin", "098fa9c079cdd195c1974df84a598cbd", "cx4lx", "14_32_1912", "MCX4131A-GCA", 2),
    _ref("refs/fw/cx-5-6/fw-ConnectX5-rel-16_35_1012-MCX512A-ACA_Ax_Bx-UEFI-14.28.15-FlexBoot-3.6.804.bin", "4a42ef86f04fce6b8f519d5d3b7e0c1e", "cx5", "16_35_1012", "MCX512A-ACA", 2),
    _ref("refs/fw/cx-5-6/fw-ConnectX5-rel-16_35_1012-MCX512A-ADA_Ax_Bx-UEFI-14.28.15-FlexBoot-3.6.804.bin", "cd95e4febf6b8bbe6768c66665aab3e7", "cx5", "16_35_1012", "MCX512A-ADA", 2),
    _ref("refs/fw/cx-5-6/fw-ConnectX5-rel-16_35_1012-MCX516A-CDA_Ax_Bx-UEFI-14.28.15-FlexBoot-3.6.804.bin", "79d4ed9c338307507192b1aa4a8e9d67", "cx5", "16_35_1012", "MCX516A-CDA", 2),
    _ref("refs/fw/cx-5-6/fw-ConnectX5-rel-16_35_1012-MCX545A-ECA_Ax_Bx-UEFI-14.28.15-FlexBoot-3.6.804.bin", "80f7333085a4adc2fc7959a809197be4", "cx5", "16_35_1012", "MCX545A-ECA", 2),
    _ref("refs/fw/cx-5-6/fw-ConnectX5-rel-16_35_1012-MCX545B-ECA_Ax_Bx-UEFI-14.28.15-FlexBoot-3.6.804.bin", "9d0c4f4fd03bce8a1fb4c3938519e2b3", "cx5", "16_35_1012", "MCX545B-ECA", 2),
    _ref("refs/fw/cx-5-6/fw-ConnectX5-rel-16_35_1012-MCX546A-EDAN_Ax-UEFI-14.28.15-FlexBoot-3.6.804.bin", "d957bc88c104097362d5fa07221cedb2", "cx5", "16_35_1012", "MCX546A-EDAN", 2),
    _ref("refs/fw/cx-5-6/fw-ConnectX5-rel-16_35_1012-MCX556A-ECA_Ax-UEFI-14.28.15-FlexBoot-3.6.804.bin", "275fb8d3a58dc6c3ef429d7b003d80f9", "cx5", "16_35_1012", "MCX556A-ECA", 2),
    _ref("refs/fw/cx-5-6/fw-ConnectX5-rel-16_35_1012-MCX556A-ECU_Ax_Bx-UEFI-14.28.15-FlexBoot-3.6.804.bin", "0d2596ea4d676f15d741372e845bfd14", "cx5", "16_35_1012", "MCX556A-ECU", 2),
    _ref("refs/fw/cx-5-6/fw-ConnectX5-rel-16_35_1012-MCX556A-EDA_Ax_Bx-UEFI-14.28.15-FlexBoot-3.6.804.bin", "fb3a2a00fd8d34e6ff5ee886b1041ed3", "cx5", "16_35_1012", "MCX556A-EDA", 2),
    _ref("refs/fw/cx-5-6/fw-ConnectX5-rel-16_35_8008-872726-B21_Ax_Bx-UEFI-14.29.15-FlexBoot-3.6.902.signed.bin", "5435fda94e2ed75160c1696464e67357", "cx5", "16_35_8008", "872726-B21", 2),
    _ref("refs/fw/cx-5-6/fw-ConnectX5-rel-16_35_8008-MCX512A-ACA_Ax_Bx-UEFI-14.29.15-FlexBoot-3.6.902.bin", "7dce14844bb0aad995f9c4379836e0b7", "cx5", "16_35_8008", "MCX512A-ACA", 2),
    _ref("refs/fw/cx-5-6/fw-ConnectX5-rel-16_35_8008-MCX512A-ADA_Ax_Bx-UEFI-14.29.15-FlexBoot-3.6.902.bin", "1ea11b892e5951b31f1c99897a05a5e0", "cx5", "16_35_8008", "MCX512A-ADA", 2),
    _ref("refs/fw/cx-5-6/fw-ConnectX5-rel-16_35_8008-MCX512F-ACA_Ax_Bx-UEFI-14.29.15-FlexBoot-3.6.902.bin", "3a053d03c5ddd93957beb8a403af0219", "cx5", "16_35_8008", "MCX512F-ACA", 2),
    _ref("refs/fw/cx-5-6/fw-ConnectX5-rel-16_35_8008-MCX546A-BCAN_Ax-UEFI-14.29.15-FlexBoot-3.6.902.bin", "5bc2d50ee03763c8ddfd1f12de52f36b", "cx5", "16_35_8008", "MCX546A-BCAN", 2),
    _ref("refs/fw/cx-5-6/fw-ConnectX5-rel-16_35_8008-MCX546A-CDAN_Ax-UEFI-14.29.15-FlexBoot-3.6.902.bin", "f5726f47dcf241ab1273ef9a8639e8dd", "cx5", "16_35_8008", "MCX546A-CDAN", 2),
    _ref("refs/fw/cx-5-6/fw-ConnectX5-rel-16_35_8008-MCX556A-ECA_Ax-UEFI-14.29.15-FlexBoot-3.6.902.bin", "d80c5b311ff85b9d0260b5b079a9a21a", "cx5", "16_35_8008", "MCX556A-ECA", 2),
    _ref("refs/fw/cx-5-6/fw-ConnectX5-rel-16_35_8008-MCX556A-EDA_Ax_Bx-UEFI-14.29.15-FlexBoot-3.6.902.bin", "6720815d3c8308b6d805f7b28555199b", "cx5", "16_35_8008", "MCX556A-EDA", 2),
    _ref("refs/fw/cx-5-6/fw-ConnectX5-rel-16_35_4030-872726-B21_Ax_Bx-UEFI-14.29.15-FlexBoot-3.6.902.signed.bin", "54e56ade2bc0754ecbc9098ab2b429ee", "cx5", "16_35_4030", "872726-B21", 2),
    _ref("refs/fw/cx-5-6/fw-ConnectX5-rel-16_35_4030-MCX516A-CDA_Ax_Bx-UEFI-14.29.15-FlexBoot-3.6.902.bin", "a8c60c90473078288b01009c7cad471b", "cx5", "16_35_4030", "MCX516A-CDA", 2),
    _ref("refs/fw/cx-5-6/fw-ConnectX5-rel-16_35_4030-MCX516A-GCA_Ax-UEFI-14.29.15-FlexBoot-3.6.902.bin", "7dc0e2380deab3611cceeeb7b2eff106", "cx5", "16_35_4030", "MCX516A-GCA", 2),
    _ref("refs/fw/cx-5-6/fw-ConnectX5-rel-16_35_4030-MCX566M-GDA_Ax_Bx-UEFI-14.29.15-FlexBoot-3.6.902.bin", "ff244f5f745f4da13e561a312b6de41e", "cx5", "16_35_4030", "MCX566M-GDA", 2),
    _ref("refs/fw/cx-5-6/fw-ConnectX6-rel-20_43_1014-MCX613106A-CCA_Ax-UEFI-14.36.16-FlexBoot-3.7.500.bin", "e1585a352868737f8d4976ba69fdc51e", "cx6", "20_43_1014", "MCX613106A-CCA", 2),
    _ref("refs/fw/cx-5-6/fw-ConnectX6-rel-20_43_1014-MCX614106A-CCA_Ax-UEFI-14.36.16-FlexBoot-3.7.500.bin", "bb5109bbbb3604f034e9dd6b0300c982", "cx6", "20_43_1014", "MCX614106A-CCA", 2),
    _ref("refs/fw/cx-5-6/fw-ConnectX6-rel-20_43_1014-MCX653106A-ECA_Ax-UEFI-14.36.16-FlexBoot-3.7.500.bin", "1476b276ce9d9a47504ade5ab461a32c", "cx6", "20_43_1014", "MCX653106A-ECA", 2),
    _ref("refs/fw/cx-5-6/fw-ConnectX6-rel-20_43_1014-MCX654105A-HCA_Ax-UEFI-14.36.16-FlexBoot-3.7.500.bin", "b0d7b8aecb19667790e954e7e588a757", "cx6", "20_43_1014", "MCX654105A-HCA", 2),
    _ref("refs/fw/cx-5-6/fw-ConnectX6-rel-20_43_1014-MCX654106A-ECA_Ax-UEFI-14.36.16-FlexBoot-3.7.500.bin", "e331697ad18c2b071c4117927b90cff0", "cx6", "20_43_1014", "MCX654106A-ECA", 2),
    _ref("refs/fw/cx-5-6/fw-ConnectX6Dx-rel-22_50_1002-MCX621102AC-ADA_Ax-UEFI-14.43.10-FlexBoot-3.9.101.signed.bin", "0e42df21cae9924264e8a67ce8f27fce", "cx6dx", "22_50_1002", "MCX621102AC-ADA", 2),
    _ref("refs/fw/cx-5-6/fw-ConnectX6Dx-rel-22_50_1002-MCX623105AC-CDA_Ax-UEFI-14.43.10-FlexBoot-3.9.101.signed.bin", "0ae988a23d6ac6264baa32a00e44b785", "cx6dx", "22_50_1002", "MCX623105AC-CDA", 2),
    _ref("refs/fw/cx-5-6/fw-ConnectX6Dx-rel-22_50_1002-MCX623432AC-ADA_Ax-UEFI-14.43.10-FlexBoot-3.9.101.signed.bin", "09c516ce9b6be4edb26b0da498683c72", "cx6dx", "22_50_1002", "MCX623432AC-ADA", 2),
    _ref("refs/fw/cx-5-6/fw-ConnectX6Dx-rel-22_50_1002-MCX623435AC-CDA_Ax-UEFI-14.43.10-FlexBoot-3.9.101.signed.bin", "35cb50eaefc8ac7da5e5c6c4e68870a6", "cx6dx", "22_50_1002", "MCX623435AC-CDA", 2),
    _ref("refs/fw/cx-5-6/fw-ConnectX6Dx-rel-22_50_1002-MCX623435AC-VDA_Ax-UEFI-14.43.10-FlexBoot-3.9.101.signed.bin", "af53944192edd41d850abf27e94dc8e1", "cx6dx", "22_50_1002", "MCX623435AC-VDA", 2),
    _ref("refs/fw/cx-5-6/fw-ConnectX6Dx-rel-22_50_1002-MCX623435AE-CDA_Ax-UEFI-14.43.10-FlexBoot-3.9.101.bin", "10e1ce1e952dd02963bd511e1efac23c", "cx6dx", "22_50_1002", "MCX623435AE-CDA", 2),
    _ref("refs/fw/cx-5-6/fw-ConnectX6Dx-rel-22_50_1002-MCX623435AN-CDA_Ax-UEFI-14.43.10-FlexBoot-3.9.101.bin", "322372d890e35383170b8e206ca9b87e", "cx6dx", "22_50_1002", "MCX623435AN-CDA", 2),
    _ref("refs/fw/cx-5-6/fw-ConnectX6Dx-rel-22_50_1002-MCX623435AN-VDA_Ax-UEFI-14.43.10-FlexBoot-3.9.101.bin", "bf71109f941009f8aeddd2e9cd52d23f", "cx6dx", "22_50_1002", "MCX623435AN-VDA", 2),
    _ref("refs/fw/cx-5-6/fw-ConnectX6Dx-rel-22_50_1002-MCX623436AC-CDA_Ax-UEFI-14.43.10-FlexBoot-3.9.101.signed.bin", "9d7354538c873a00fcb4e0345747eafd", "cx6dx", "22_50_1002", "MCX623436AC-CDA", 2),
    _ref("refs/fw/cx-5-6/fw-ConnectX6Dx-rel-22_50_1002-MCX623436AS-CDA_Ax-UEFI-14.43.10-FlexBoot-3.9.101.signed.bin", "7673ecd6b2b8bc889a043eb5cb28f77c", "cx6dx", "22_50_1002", "MCX623436AS-CDA", 2),
    _ref("refs/fw/cx-5-6/fw-ConnectX6Dx-rel-22_50_1002-MCX683105AN-HDA_Ax-UEFI-14.43.10-FlexBoot-3.9.101.bin", "36c60c0220d1bf4f2f75d977ff256cca", "cx6dx", "22_50_1002", "MCX683105AN-HDA", 2),
    _ref("refs/fw/cx-5-6/fw-ConnectX6Lx-rel-26_50_1002-MCX631435AE-GDA_Ax-UEFI-14.43.10-FlexBoot-3.9.101.bin", "c1cbe6c30556bcc330e18ae3b843db9b", "cx6lx", "26_50_1002", "MCX631435AE-GDA", 2),
]

T3 = [
    _ref("refs/fw/cx-4/fw-ConnectX4-rel-12_28_2302-MCX455A-ECA_Ax-UEFI-14.21.17-FlexBoot-3.6.102.bin", "b37620c06d8041bd5b4ddfe9836d4ebf", "cx4", "12_28_2302", "MCX455A-ECA", 3),
    _ref("refs/fw/cx-5-6/fw-ConnectX5-rel-16_27_6120-09FTMY_071C1T_Ax-UEFI-14.20.27-FlexBoot-3.5.903.signed.bin", "b10998ffbfe187ee67301059e253772c", "cx5", "16_27_6120", "09FTMY_071C1T", 3),
    _ref("refs/fw/cx-5-6/PG171_Ax_NVD0000000014_rel-20_43.8002.bin", "c72fa726e35d3f388531465dcffa0a6f", "cx6", "20_43_8002", "PG171-NVD", 3),
    _ref("refs/fw/cx-5-6/fw-ConnectX6-rel-20_43_8002-MCX654105A-HCA_Ax-UEFI-14.37.50-FlexBoot-3.7.500.bin", "2ade8a0571ba69bb5285ba3178e92d3d", "cx6", "20_43_8002", "MCX654105A-HCA", 3),
    _ref("refs/fw/cx-5-6/fw-ConnectX6-rel-20_43_8016-MCX654105A-HCA_Ax-UEFI-14.37.50-FlexBoot-3.7.500.bin", "c5d8e04cf4b19064f5be122276956643", "cx6", "20_43_8016", "MCX654105A-HCA", 3),
    _ref("refs/fw/cx-7/dumps/cx7_firmware_dumps/28.33.0751/orig_firmware.bin", "4308c08e034d6f763a8f327430102a13", "cx7", "28_33_0751", "MCX713106AC-VEA", 3),
    _ref("refs/fw/cx-7/dumps/cx7_firmware_dumps/28.33.0800.bin", "828b3ce6975166b9c35484d0921f66dd", "cx7", "28_33_0800", "MCX753106ASHEA_DK", 3),
]

IMAGE_TO_PROFILE = {
    "cx4/12_28_4706": "cx4-1228",
    "cx4lx/14_32": "cx4lx",
    "cx5/16_35": "cx5",
    "cx5/16_19_1200": "cx5",
    "cx6/20_43": "cx6-2043",
    "cx6dx/22_50": "cx6dx",
    "cx6dx/22_47": "cx6dx",
    "cx6lx/26_50": "cx6lx-2650",
    "cx7/28_33": "cx7",
}


def verify_md5(ref: ImageRef) -> None:
    path = ref.path
    if not path.is_file():
        raise CorpusManifestError(f"missing image: {path}")
    digest = hashlib.md5(path.read_bytes()).hexdigest()
    if digest != ref.md5:
        raise CorpusManifestError(
            f"md5 drift: {path}: pinned {ref.md5}, found {digest}"
        )


def resolve_images(refs_root: Path, include_t3: bool = False) -> list[ImageRef]:
    refs = T1 + T2 + (T3 if include_t3 else [])
    resolved = []
    seen = set()
    for ref in refs:
        if str(ref.path) in seen:
            continue
        seen.add(str(ref.path))
        full = replace(ref, path=refs_root / ref.path)
        verify_md5(full)
        resolved.append(full)
    return resolved
