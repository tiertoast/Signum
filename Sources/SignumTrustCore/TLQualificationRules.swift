import Foundation

/// nil facts mean unavailable, an empty set means a parsed, absent extension/attribute.
public protocol TLQualificationMaterial {
    var policies: Set<String> { get }
    var keyUsage: [String: Bool] { get }
    var subjectAttributes: Set<String>? { get }
    var extendedKeyUsage: Set<String>? { get }
}
public extension TLQualificationMaterial {
    var subjectAttributes: Set<String>? { nil }
    var extendedKeyUsage: Set<String>? { nil }
}
public enum TLCriterionMatch: String, Sendable { case matches, doesNotMatch, unsupported }
public enum TLDeviceEvidence: String, Sendable { case yes, no, indeterminate }

public enum TLQualificationRules {
    public static let tl = "http://uri.etsi.org/02231/v2#"
    public static let sie = "http://uri.etsi.org/TrstSvc/SvcInfoExt/eSigDir-1999-93-EC-TrustedList/#"
    public static let additional = "http://uri.etsi.org/02231/v2/additionaltypes#"
    public static let xades = "http://uri.etsi.org/01903/v1.3.2#"
    public static let prefix = "http://uri.etsi.org/TrstSvc/TrustedList/SvcInfoExt/"
    public static let regulationStart = Date(timeIntervalSince1970:1467324000)
    private static let known = Set(["QCStatement","NotQualified","QCForESig","QCForESeal","QCForWSA","QCForLegalPerson",
        "QCWithQSCD","QCNoQSCD","QCQSCDStatusAsInCert","QCQSCDManagedOnBehalf",
        "QCWithSSCD","QCNoSSCD","QCSSCDStatusAsInCert"].map { prefix+$0 })
    private static let bits = Set(["digitalSignature","nonRepudiation","keyEncipherment","dataEncipherment","keyAgreement","keyCertSign","crlSign","encipherOnly","decipherOnly"])
    /// Syntax-only validation never evaluates a fabricated certificate or asserts a qualifier.
    public static func supports(_ extensions: [TLServiceExtension]) -> Bool { evaluateImpl(extensions,material:nil) != nil }
    public static func evaluate<M: TLQualificationMaterial>(_ extensions: [TLServiceExtension], material: M) -> Set<String>? {
        evaluateImpl(extensions,material:material)
    }
    private static func inconsistent(_ values: Set<String>) -> Bool {
        let has: (String)->Bool = { values.contains(prefix+$0) }
        if has("QCStatement") && has("NotQualified") { return true }
        for family in [["QCWithSSCD","QCNoSSCD","QCSSCDStatusAsInCert"],["QCWithQSCD","QCNoQSCD","QCQSCDStatusAsInCert"]] {
            if family.filter(has).count > 1 { return true }
        }
        if has("QCQSCDManagedOnBehalf") && (has("QCNoQSCD") || has("QCQSCDStatusAsInCert")) { return true }
        if (has("QCNoSSCD") && has("QCWithQSCD")) || (has("QCNoQSCD") && has("QCWithSSCD")) { return true }
        return false
    }
    private static func evaluateImpl(_ extensions: [TLServiceExtension], material: (any TLQualificationMaterial)?) -> Set<String>? {
        var output = Set<String>(), purposes = Set<String>()
        for ext in extensions {
            guard ext.namespace == tl, ext.name == "Extension", ext.children.count == 1,
                  ["true","false","1","0"].contains(ext.attributes["Critical"] ?? "") else { return nil }
            let child = ext.children[0]
            if child.namespace == sie && child.name == "Qualifications" {
                guard !child.children.isEmpty else { return nil }
                for rule in child.children {
                    guard rule.namespace == sie, rule.name == "QualificationElement", rule.children.count == 2,
                          rule.children[0].namespace == sie, rule.children[0].name == "Qualifiers",
                          rule.children[1].namespace == sie, rule.children[1].name == "CriteriaList",
                          let applies = criteriaImpl(rule.children[1],material:material,depth:0) else { return nil }
                    var values = Set<String>()
                    for q in rule.children[0].children {
                        guard q.namespace == sie, q.name == "Qualifier", q.children.isEmpty, let uri = q.attributes["uri"], known.contains(uri) else { return nil }
                        values.insert(uri)
                    }
                    guard !values.isEmpty, !inconsistent(values) else { return nil }
                    if material != nil && applies { output.formUnion(values) }
                }
            } else if child.namespace == tl && child.name == "AdditionalServiceInformation" {
                guard child.children.count == 1, child.children[0].namespace == tl, child.children[0].name == "URI",
                      ["ForeSignatures", "ForeSeals"].map({ prefix + $0 }).contains(child.children[0].text) else { return nil }
                purposes.insert(child.children[0].text)
            } else if ["true","1"].contains(ext.attributes["Critical"] ?? "") { return nil }
        }
        guard purposes.isEmpty || purposes.contains(prefix + "ForeSignatures") else { return nil }
        return inconsistent(output) ? nil : output
    }
    public static func criteriaResult<M: TLQualificationMaterial>(_ node: TLServiceExtension, material: M) -> TLCriterionMatch {
        guard let value = criteria(node,material:material,depth:0) else { return .unsupported }
        return value ? .matches : .doesNotMatch
    }
    public static func criteria<M: TLQualificationMaterial>(_ node: TLServiceExtension, material: M, depth: Int) -> Bool? {
        criteriaImpl(node,material:material,depth:depth)
    }
    /// Canonical numeric or urn:oid form, with no national OID registry.
    private static func oid(_ node: TLServiceExtension) -> String? {
        guard node.namespace == xades, node.name == "Identifier", node.children.isEmpty,
              node.attributes["Qualifier"] == nil || ["OIDAsURI","OIDAsURN"].contains(node.attributes["Qualifier"]!) else { return nil }
        if node.attributes["Qualifier"] == "OIDAsURN" && !node.text.hasPrefix("urn:oid:") { return nil }
        let text = node.text.hasPrefix("urn:oid:") ? String(node.text.dropFirst(8)) : node.text
        let arcs = text.split(separator:".",omittingEmptySubsequences:false)
        guard text.count <= 256, arcs.count >= 2, arcs.allSatisfy({ !$0.isEmpty && $0.allSatisfy { $0 >= "0" && $0 <= "9" } && ($0.count == 1 || $0.first != "0") && UInt64($0) != nil }),
              let first = UInt64(arcs[0]), let second = UInt64(arcs[1]), first <= 2, first == 2 || second < 40 else { return nil }
        return text
    }
    private static func identifiers(_ node: TLServiceExtension, wrapper: String, namespace: String) -> Set<String>? {
        guard !node.children.isEmpty, node.text.isEmpty else { return nil }
        var result = Set<String>()
        for p in node.children {
            guard p.namespace == namespace, p.name == wrapper, p.text.isEmpty, let id = p.children.first,
                  let value = oid(id), p.children.dropFirst().allSatisfy({ $0.namespace == xades && ["Description","DocumentationReferences"].contains($0.name) }) else { return nil }
            result.insert(value)
        }
        return result
    }
    private static func criteriaImpl(_ node: TLServiceExtension, material: (any TLQualificationMaterial)?, depth: Int) -> Bool? {
        guard depth <= 12, node.namespace == sie, node.name == "CriteriaList", node.text.isEmpty, let assertion = node.attributes["assert"], ["all","atLeastOne","none"].contains(assertion) else { return nil }
        var matches = [Bool]()
        for child in node.children {
            guard child.namespace == sie else { return nil }
            switch child.name {
            case "CriteriaList":
                guard let value = criteriaImpl(child,material:material,depth:depth+1) else { return nil }; matches.append(value)
            case "Description": guard child.children.isEmpty else { return nil }
            case "KeyUsage":
                guard !child.children.isEmpty else { return nil }
                var seen = Set<String>(), ok = true
                for bit in child.children {
                    guard bit.namespace == sie, bit.name == "KeyUsageBit", bit.children.isEmpty, let name = bit.attributes["name"], bits.contains(name), seen.insert(name).inserted,
                          ["true","1","false","0"].contains(bit.text) else { return nil }
                    if let material { ok = ok && material.keyUsage[name] == ["true","1"].contains(bit.text) }
                }
                matches.append(ok)
            case "PolicySet":
                guard let required = identifiers(child,wrapper:"PolicyIdentifier",namespace:sie) else { return nil }
                matches.append(material.map { required.isSubset(of:$0.policies) } ?? false)
            case "otherCriteriaList":
                guard !child.children.isEmpty else { return nil }
                // The extension container groups criteria; each assertion contributes to
                // the parent's all/atLeastOne/none operation, never an implicit match.
                for other in child.children {
                    guard other.namespace == additional else { return nil }
                    let required: Set<String>?
                    let actual: Set<String>?
                    switch other.name {
                    case "CertSubjectDNAttribute": required = identifiers(other,wrapper:"AttributeOID",namespace:additional); actual = material?.subjectAttributes
                    case "ExtendedKeyUsage": required = identifiers(other,wrapper:"KeyPurposeId",namespace:additional); actual = material?.extendedKeyUsage
                    default: return nil
                    }
                    guard let required else { return nil }
                    if material != nil && actual == nil { return nil }
                    matches.append(actual.map { required.isSubset(of:$0) } ?? false)
                }
            default: return nil
            }
        }
        guard !matches.isEmpty else { return nil }
        switch assertion { case "all": return matches.allSatisfy { $0 }; case "atLeastOne": return matches.contains(true); default: return !matches.contains(true) }
    }
    /// SSCD is evaluated only in its Directive regime, never renamed globally to QSCD.
    public static func deviceEvidence(qualifiers: Set<String>, sscd: Bool, policies: Set<String>, at: Date) -> TLDeviceEvidence {
        guard !inconsistent(qualifiers) else { return .indeterminate }
        let has: (String)->Bool = { qualifiers.contains(prefix+$0) }
        let legacy = at < regulationStart
        let wrongRegime = legacy ? ["QCWithQSCD","QCNoQSCD","QCQSCDStatusAsInCert","QCQSCDManagedOnBehalf"] : ["QCWithSSCD","QCNoSSCD","QCSSCDStatusAsInCert"]
        guard !wrongRegime.contains(where:has), !has("QCQSCDManagedOnBehalf") else { return .indeterminate }
        let positive = has(legacy ? "QCWithSSCD" : "QCWithQSCD")
        let negative = has(legacy ? "QCNoSSCD" : "QCNoQSCD")
        let inCertificate = sscd || (legacy && policies.contains("0.4.0.1456.1.1"))
        if negative { return inCertificate ? .indeterminate : .no }
        return positive || inCertificate ? .yes : .no
    }
}
