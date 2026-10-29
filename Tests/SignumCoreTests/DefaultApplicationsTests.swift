#if os(macOS)
import XCTest
import UniformTypeIdentifiers
@testable import SignumApp

@MainActor final class DefaultApplicationsTests: XCTestCase {
    final class FakeAccess: DefaultApplicationAccess {
        var current: [String: URL] = [:]
        var requests: [String] = []
        var errors = Set<String>(), unchanged = Set<String>()
        func currentApplication(for type: UTType) -> URL? { current[type.identifier] }
        func setApplication(_ app: URL, for type: UTType) async throws {
            requests.append(type.identifier)
            if errors.contains(type.identifier) { throw NSError(domain: "SyntheticDenied", code: 7, userInfo: [NSLocalizedDescriptionKey: "Consenso negato (fixture)"]) }
            if !unchanged.contains(type.identifier) { current[type.identifier] = app }
        }
    }
    let target = URL(fileURLWithPath: "/synthetic/Signum.app")
    func type(_ extensionName: String) -> String { SignumDocumentAssociation.formats.first { $0.id == extensionName }!.contentType.identifier }
    func testOpeningOrCancellingDoesNotWriteAndOptionalFormatsAreUnchecked() {
        let access = FakeAccess()
        let model = DefaultApplicationsModel(access: access, validateBundle: { self.target })
        XCTAssertEqual(model.selected, ["p7m", "p7s", "asics", "asice"])
        XCTAssertFalse(model.selected.contains("pdf")); XCTAssertFalse(model.selected.contains("xml"))
        model.selected.removeAll(); model.refresh()
        XCTAssertTrue(access.requests.isEmpty)
    }
    func testOnlyExplicitSelectionIsAppliedAndActualStateIsRefreshed() async {
        let access = FakeAccess()
        access.current[type("pdf")] = URL(fileURLWithPath: "/synthetic/Preview.app")
        let model = DefaultApplicationsModel(access: access, validateBundle: { self.target })
        model.selected = ["p7m", "asice"]
        await model.apply()
        XCTAssertEqual(access.requests, [type("p7m"), type("asice")])
        XCTAssertEqual(model.applications["p7m"], target)
        XCTAssertEqual(model.applications["pdf"]?.lastPathComponent, "Preview.app")
        XCTAssertTrue(model.failures.isEmpty); XCTAssertTrue(model.selected.isEmpty); XCTAssertFalse(model.applying)
        // An optional type changes only when the user explicitly selects it.
        model.selected = ["pdf"]; await model.apply()
        XCTAssertEqual(model.applications["pdf"], target)
        XCTAssertFalse(access.requests.contains(type("xml")))
    }
    func testPerFormatDenialAndUnchangedReadbackDoNotPreventOtherFormats() async {
        let access = FakeAccess()
        access.errors = [type("p7s")]; access.unchanged = [type("asics")]
        let old = URL(fileURLWithPath: "/synthetic/Other.app")
        access.current[type("p7s")] = old; access.current[type("asics")] = old
        let model = DefaultApplicationsModel(access: access, validateBundle: { self.target })
        await model.apply()
        XCTAssertEqual(model.failures, ["p7s", "asics"])
        XCTAssertTrue(model.outcomes["p7s"]!.contains("Consenso negato"))
        XCTAssertTrue(model.outcomes["asics"]!.contains("non modificata"))
        XCTAssertEqual(model.applications["p7s"], old); XCTAssertEqual(model.applications["asics"], old)
        XCTAssertEqual(model.applications["p7m"], target); XCTAssertEqual(model.applications["asice"], target)
        XCTAssertEqual(model.selected, ["p7s", "asics"])
    }
    func testAlreadyDefaultSignedTypeIsNotPreselectedAndEmptyApplyDoesNothing() async {
        let access = FakeAccess(); access.current[type("p7m")] = target
        let model = DefaultApplicationsModel(access: access, validateBundle: { self.target })
        XCTAssertFalse(model.selected.contains("p7m"))
        model.selected = []; await model.apply(); XCTAssertTrue(access.requests.isEmpty)
    }
    func testMissingOrRemovedAppBundlePreventsEveryWrite() async {
        let access = FakeAccess()
        var valid = true
        let model = DefaultApplicationsModel(access: access, validateBundle: {
            if !valid { throw NSError(domain: "Fixture", code: 1, userInfo: [NSLocalizedDescriptionKey: "Bundle rimosso"]) }
            return self.target
        })
        valid = false; await model.apply()
        XCTAssertTrue(access.requests.isEmpty); XCTAssertEqual(model.bundleError, "Bundle rimosso")
        XCTAssertFalse(model.applying)
        XCTAssertThrowsError(try DefaultApplicationsModel.applicationBundle(Bundle(for: Self.self)))
        let invalid = DefaultApplicationsModel(access: access, validateBundle: { throw NSError(domain: "Fixture", code: 2) })
        XCTAssertNotNil(invalid.bundleError); XCTAssertTrue(invalid.selected.isEmpty)
    }
}
#endif
