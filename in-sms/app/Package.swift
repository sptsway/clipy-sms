// swift-tools-version: 5.9
import PackageDescription

let package = Package(
    name: "OTPForwarder",
    platforms: [.macOS(.v13)],
    targets: [
        .executableTarget(
            name: "OTPForwarder",
            path: "Sources/OTPForwarder",
            exclude: ["Resources/Info.plist"],
            linkerSettings: [
                // Embeds Info.plist directly into the binary's __TEXT,__info_plist
                // section, the same mechanism a real .app bundle's Contents/Info.plist
                // provides. This lets LSUIElement (no Dock icon) take effect even when
                // running as a plain `swift run` executable during development, ahead of
                // the real .app packaging in Milestone 5. Path is relative to this
                // package's root directory, which is where `swift build` invokes the
                // linker from.
                .unsafeFlags([
                    "-Xlinker", "-sectcreate",
                    "-Xlinker", "__TEXT",
                    "-Xlinker", "__info_plist",
                    "-Xlinker", "Sources/OTPForwarder/Resources/Info.plist",
                ])
            ]
        )
    ]
)
