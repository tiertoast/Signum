#if os(macOS)
/// One declaration shared by settings, visible consent and the immutable job.
/// The preference controls the new CAdES SignerInfo only; it never removes
/// attributes from an existing signature or changes supported XML/PDF profiles.
public enum SigningTimePolicy {
    public static let preferenceTitle = "Includi data e ora dichiarate nel CAdES (CMS signingTime)"
    public static let preferenceExplanation = "L’opzione riguarda solo CMS signingTime nelle nuove firme CAdES. XAdES e ASiC includono sempre XML SigningTime; PAdES include sempre PDF /M. Sono date dichiarate, non una marca temporale, e non provano l’ora della firma."
    public static func declaration(for format: SigningFormat, includeCMS: Bool) -> String {
        let policy: String
        switch format {
        case .cades, .cadesDetached, .cadesCoSign, .cadesCounterSign:
            policy = "Data dichiarata: CMS signingTime " + (includeCMS ? "incluso" : "omesso") + " nella nuova firma CAdES."
        case .xades, .asics, .asice:
            policy = "Data dichiarata: XML SigningTime sempre incluso. L’opzione CAdES non si applica."
        case .pades:
            policy = "Data dichiarata: PDF /M sempre incluso. L’opzione CAdES non si applica."
        }
        let existing = format == .cadesCoSign || format == .cadesCounterSign ? " Le date delle firme già presenti restano invariate." : ""
        return policy + existing + " Non è una marca temporale e non prova l’ora della firma."
    }
}
#endif
