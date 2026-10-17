// swift-tools-version:5.9
// Test-only build of the platform-independent core. The app target in
// Spoofy.xcodeproj compiles the same files directly; run tests with `make test`.
import PackageDescription

let package = Package(
    name: "SpoofyCore",
    platforms: [.macOS(.v13), .iOS(.v16)],
    targets: [
        .target(
            name: "SpoofyCore",
            path: ".",
            // The target path is the repo root, so everything that isn't core
            // source is excluded explicitly (otherwise SwiftPM warns about it).
            exclude: [
                "Spoofy", "Spoofy.xcodeproj", "Tests", "Docs", "plans", "altstore", "build",
                "LICENSE", "Makefile", "README.md", "config.yml", "docker-compose.yml",
                "redis.conf", "icon.png", "icon_macos.png",
            ],
            sources: ["Proxy", "TLS", "DNS", "Shadowsocks", "Shared"]
        ),
        .testTarget(
            name: "SpoofyCoreTests",
            dependencies: ["SpoofyCore"],
            path: "Tests/SpoofyCoreTests"
        ),
    ]
)
