// swift-tools-version:5.9
// The swift-tools-version declares the minimum version of Swift required to build this package.

import PackageDescription

// This doesn't work when cross-compiling: the privacy manifest will be included in the Bundle and
// Foundation will be linked. This is, however, strictly better than unconditionally adding the
// resource.
#if canImport(Darwin)
let privacyManifestExclude: [String] = []
let privacyManifestResource: [PackageDescription.Resource] = [.copy("PrivacyInfo.xcprivacy")]
#else
// Exclude on other platforms to avoid build warnings.
let privacyManifestExclude: [String] = ["PrivacyInfo.xcprivacy"]
let privacyManifestResource: [PackageDescription.Resource] = []
#endif

// For Swift prior to 6.0 enable noncopyable and strict concurrency features
#if swift(>=6.0)
let buildSettings: [PackageDescription.SwiftSetting] = [
    .interoperabilityMode(.Cxx),
]
#else
let buildSettings: [PackageDescription.SwiftSetting] = [
    .enableExperimentalFeature("StrictConcurrency"),
    .enableExperimentalFeature("MoveOnly"),
    .interoperabilityMode(.Cxx),
]
#endif

let package = Package(
    name: "swift-bignum",
    products: [
        // Products define the executables and libraries produced by a package, and make them visible to other packages.
        .library(name: "BigNum", targets: ["BigNum"]),
        /* This target is used only for symbol mangling. It's added and removed automatically because it emits build warnings. MANGLE_START
            .library(name: "CBigNumBoringSSL", type: .static, targets: ["CBigNumBoringSSL"]),
        MANGLE_END */
    ],
    dependencies: [],
    targets: [
        .target(
            name: "BigNum",
            dependencies: ["CBigNumBoringSSL"],
            swiftSettings: buildSettings
        ),
        .target(
            name: "CBigNumBoringSSL",
            exclude: privacyManifestExclude + [
                "hash.txt",
            ],
            sources: [
                "crypto",
                "gen/bcm",
                "gen/crypto",
                "third_party/fiat",
            ],
            resources: privacyManifestResource,
            publicHeadersPath: "include",
            cxxSettings: [
                .define("_HAS_EXCEPTIONS", to: "0", .when(platforms: [.windows])),
                .define("WIN32_LEAN_AND_MEAN", .when(platforms: [.windows])),
                .define("NOMINMAX", .when(platforms: [.windows])),
                .define("_CRT_SECURE_NO_WARNINGS", .when(platforms: [.windows])),
                /*
                 * These defines are required on Wasm/WASI, to disable use of pthread.
                 */
                .define(
                    "OPENSSL_NO_THREADS_CORRUPT_MEMORY_AND_LEAK_SECRETS_IF_THREADED",
                    .when(platforms: [.wasi])
                ),
                .define("OPENSSL_NO_ASM", .when(platforms: [.wasi])),
                .define("_XOPEN_SOURCE", to: "700", .when(platforms: [.linux])),
                .define("BORINGSSL_IMPLEMENTATION"),
            ]
        ),
        .testTarget(name: "BigNumTests", dependencies: ["BigNum"], swiftSettings: buildSettings),
    ],
    cxxLanguageStandard: .cxx17
)
