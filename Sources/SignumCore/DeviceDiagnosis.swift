#if os(macOS)
import Foundation

/// A plain-language finding about why no certificate can be used for signing,
/// and the one thing the user can do about it. Signum ships no drivers and keeps
/// no list of supported cards: it explains what it observed.
public struct DeviceFinding: Equatable, Sendable {
    public enum Severity: Sendable { case problem, warning }
    public enum Action: Sendable { case installSoftware, configure, refresh, none }
    public let severity: Severity
    public let title: String
    public let detail: String
    public let action: Action
    public init(_ severity: Severity, _ title: String, _ detail: String, action: Action) {
        self.severity = severity; self.title = title; self.detail = detail; self.action = action
    }
}

public enum DeviceDiagnosis {
    /// OpenSC is free software; Signum loads it from its standard install path.
    public static let openSCReleases = URL(string: "https://github.com/OpenSC/OpenSC/releases")!

    public static func findings(for selection: DeviceSelection, at date: Date = Date()) -> [DeviceFinding] {
        guard !selection.isSearching, !selection.providers.isEmpty else { return [] }
        return findings(providers: selection.providers, certificates: selection.certificates,
                        readers: selection.readers, at: date)
    }

    public static func findings(providers: [DiscoveredMiddleware], certificates: [DeviceCertificate],
                                readers: SmartCardReaderObservation?, at date: Date = Date()) -> [DeviceFinding] {
        let routes = certificates.flatMap(\.routes)
        var result: [DeviceFinding] = []
        let observed = readers?.availability == .observed ? readers : nil
        if let mute = observed?.mute, !mute.isEmpty {
            result.append(.init(.warning, "La tessera non risponde",
                "La tessera in \(list(mute.map(\.name))) è inserita ma non risponde. Estraila e reinseriscila nel verso giusto; se succede ancora potrebbe essere danneggiata o non adatta a questo lettore.",
                action: .refresh))
        }
        guard !routes.contains(where: { $0.assessment.permitsSigning }) else { return result }

        let tokens = providers.flatMap(\.tokens)
        if tokens.isEmpty {
            if let primary = noDevice(providers: providers, readers: observed) { result.insert(primary, at: 0) }
            return result
        }
        if routes.isEmpty {
            result.insert(noCertificates(tokens), at: 0)
            return result
        }
        result.insert(ineligible(routes, at: date), at: 0)
        return result
    }

    private static func noDevice(providers: [DiscoveredMiddleware], readers: SmartCardReaderObservation?) -> DeviceFinding? {
        let installed = providers.filter { ![.missing, .duplicate, .cancelled].contains($0.status) }
        let withCard = readers?.withCard.map(\.name) ?? []
        if let readers, readers.readers.isEmpty {
            return .init(.problem, "Nessun lettore o chiavetta collegati",
                "macOS non vede lettori di smart card né chiavette di firma. Collega il lettore con la tessera inserita, oppure la chiavetta, poi aggiorna i dispositivi.",
                action: .refresh)
        }
        if installed.isEmpty {
            let start = withCard.isEmpty ? "" : "\(list(withCard).capitalizedFirst) è collegato e pronto, ma manca il software per leggerlo. "
            return .init(.problem, "Manca il software per leggere la tessera",
                start + "Signum usa OpenSC, gratuito, oppure il software PKCS#11 del fornitore della tessera o della chiavetta. Installane uno e aggiorna i dispositivi. Se è installato in un’altra cartella, indicalo da Configura dispositivo.",
                action: .installSoftware)
        }
        if let readers, withCard.isEmpty, readers.mute.isEmpty, !readers.empty.isEmpty {
            return .init(.warning, "Lettore senza tessera",
                "\(list(readers.empty.map(\.name)).capitalizedFirst) è collegato ma non contiene una tessera. Inserisci la tessera e aggiorna i dispositivi.",
                action: .refresh)
        }
        let names = list(Array(Set(installed.map(\.definition.name))).sorted())
        if installed.allSatisfy({ $0.status == .unsafe }) {
            return .init(.problem, "Software del dispositivo non caricato",
                "\(names.capitalizedFirst) è installato, ma il file o la sua cartella possono essere modificati da altri utenti, quindi Signum non lo carica. Reinstalla il software o correggi i permessi, poi aggiorna.",
                action: .configure)
        }
        if installed.allSatisfy({ $0.status == .unsafe || $0.status == .communicationError }) {
            return .init(.problem, "Il software del dispositivo non risponde",
                "\(names.capitalizedFirst) non ha risposto. Ricollega il dispositivo e aggiorna; se il problema resta, reinstalla il software.",
                action: .refresh)
        }
        if !withCard.isEmpty {
            return .init(.problem, "Dispositivo non riconosciuto",
                "\(list(withCard).capitalizedFirst) è collegato e pronto, ma \(names) non lo riconosce. Probabilmente serve il software del fornitore della tessera o della chiavetta: installalo e, se Signum non lo trova, indicalo da Configura dispositivo.",
                action: .configure)
        }
        return .init(.warning, "Nessun dispositivo di firma rilevato",
            "\(names.capitalizedFirst) è installato ma non vede tessere o chiavette. Collega il dispositivo e aggiorna.",
            action: .refresh)
    }

    private static func noCertificates(_ tokens: [DiscoveredToken]) -> DeviceFinding {
        if tokens.contains(where: { $0.certificateState == .authenticationRequired }) {
            return .init(.warning, "I certificati si leggono solo con il PIN",
                "Il dispositivo è riconosciuto, ma mostra i certificati solo dopo l’autenticazione. Signum non invia il PIN durante la ricerca, quindi non può proporre un certificato da questo dispositivo.",
                action: .none)
        }
        if tokens.allSatisfy({ $0.certificateState == .empty }) {
            return .init(.problem, "Nessun certificato sul dispositivo",
                "Il dispositivo è riconosciuto ma non contiene certificati. Potrebbe essere una tessera non ancora attivata o senza firma digitale.",
                action: .none)
        }
        return .init(.warning, "Certificati non letti",
            "Il dispositivo è riconosciuto, ma i certificati non sono stati letti. Ricollega il dispositivo e aggiorna.",
            action: .refresh)
    }

    private static func ineligible(_ routes: [DeviceCertificateRoute], at date: Date) -> DeviceFinding {
        var seen = Set<String>()
        let assessments = routes.map(\.assessment).filter { seen.insert($0.certificateSHA256).inserted }
        // A CNS-style certificate: client authentication, no non-repudiation or
        // document-signing purpose (digitalSignature alone does not make it a signing one).
        let authenticationOnly: (CertificateEligibility.Assessment) -> Bool = {
            $0.clientAuthentication && !$0.contentCommitment && !$0.documentSigning
        }
        let signing = assessments.filter { !authenticationOnly($0) }
        if signing.isEmpty {
            return .init(.problem, "Il dispositivo ha solo un certificato di autenticazione",
                "Il certificato serve per accedere ai servizi online, come per la CNS o la Tessera Sanitaria, non per la firma digitale. Per firmare serve un dispositivo con un certificato di firma.",
                action: .none)
        }
        let candidates = signing.isEmpty ? assessments : signing
        let expired = candidates.compactMap(\.notAfter).filter { $0 <= date }
        if !expired.isEmpty, expired.count == candidates.count, let last = expired.max() {
            return .init(.problem, "Certificato di firma scaduto",
                "Il certificato è scaduto il \(day(last)). Per firmare serve un certificato rinnovato: rivolgiti a chi lo ha emesso.",
                action: .none)
        }
        let future = candidates.compactMap(\.notBefore).filter { $0 > date }
        if !future.isEmpty, future.count == candidates.count, let first = future.min() {
            return .init(.problem, "Certificato non ancora valido",
                "Il certificato sarà valido dal \(day(first)). Controlla anche data e ora del Mac.",
                action: .none)
        }
        return .init(.problem, "Nessun certificato idoneo alla firma",
            "I certificati presenti non superano i controlli per la firma. Il motivo è indicato sotto ciascun certificato.",
            action: .none)
    }

    static func list(_ names: [String]) -> String {
        let quoted = names.map { "«\($0)»" }
        guard quoted.count > 1 else { return quoted.first ?? "" }
        return quoted.dropLast().joined(separator: ", ") + " e " + quoted.last!
    }
    static func day(_ date: Date) -> String {
        let formatter = DateFormatter()
        formatter.locale = Locale(identifier: "it_IT"); formatter.dateStyle = .long; formatter.timeStyle = .none
        return formatter.string(from: date)
    }
}

private extension String {
    /// "«X» è collegato": quoted names already start the sentence correctly.
    var capitalizedFirst: String { prefix(1).uppercased() + dropFirst() }
}
#endif
