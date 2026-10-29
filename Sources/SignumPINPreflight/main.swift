import Foundation
import SignumCore

#if os(macOS)
import Darwin
struct PINPublicInventory: Encodable {
    struct Entry: Encodable {
        let providerName: String
        let candidatePath: String
        let canonicalPath: String?
        let identity: MiddlewareFileIdentity?
        let reportedVersion: String?
        let detectionStatus: String
        let token: SignumToken?
        let snapshot: PINStatusSnapshot?
        let failure: String?
    }
    let schema = "signum-pin-public-inventory-v1"
    let acquiredAt = Date()
    let entries: [Entry]
    let limitations = [
        "Letture pubbliche soltanto. Nessun PIN/PUK richiesto, login, cambio, reset o sblocco.",
        "Versioni comunicate dal modulo, non attestazioni dell'installazione o autenticità del produttore.",
        "Driver, applet, AID, auth ID e domini PIN non qualificati da PKCS#11: non determinati.",
        "Nessun contatore tentativi inventato. Nessuna capacità mutante abilitata.",
        "La barriera copre processi Signum aggiornati; software terzo e vecchie build non cooperano."
    ]
}
// This target has no credential argument, environment override, write command,
// backend injection, retry, generic tool invocation or PKCS#15 probe.
guard CommandLine.arguments.count == 1 else {
    FileHandle.standardError.write(Data("Questo strumento non accetta argomenti o credenziali.\n".utf8)); exit(2)
}
let discovered = MiddlewareDiscovery().discover()
let generation = UUID()
var entries: [PINPublicInventory.Entry] = []
for provider in discovered {
    let inspection = provider.inspection
    if provider.tokens.isEmpty {
        entries.append(.init(providerName: provider.definition.name, candidatePath: provider.candidatePath,
            canonicalPath: inspection?.canonicalPath, identity: inspection?.identity, reportedVersion: provider.version,
            detectionStatus: provider.status.rawValue, token: nil, snapshot: nil, failure: nil))
    }
    for observed in provider.tokens {
        var snapshot: PINStatusSnapshot?, failure: String?
        if let inspection {
            let context = PINManagementContext(provider: inspection.canonicalPath, inspection: inspection,
                automatic: provider.origin == .known, token: observed.token, discoveryID: generation)
            do { snapshot = try PINManagementCoordinator.readStatus(context: context) }
            catch { failure = (error as? PINManagementFailure)?.rawValue ?? "publicReadFailed" }
        } else { failure = "moduleIdentityUnavailable" }
        entries.append(.init(providerName: provider.definition.name, candidatePath: provider.candidatePath,
            canonicalPath: inspection?.canonicalPath, identity: inspection?.identity, reportedVersion: provider.version,
            detectionStatus: provider.status.rawValue, token: observed.token, snapshot: snapshot, failure: failure))
    }
}
let encoder = JSONEncoder(); encoder.outputFormatting = [.prettyPrinted, .sortedKeys]; encoder.dateEncodingStrategy = .iso8601
do { FileHandle.standardOutput.write(try encoder.encode(PINPublicInventory(entries: entries))) }
catch { FileHandle.standardError.write(Data("Inventario pubblico non disponibile.\n".utf8)); exit(2) }
#else
FileHandle.standardError.write(Data("Il preflight richiede macOS e i middleware installati.\n".utf8))
exit(2)
#endif
