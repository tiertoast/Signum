import Foundation

/// Certificate facts supplied by the existing X.509/QCStatements decoder.
public protocol TLQualificationMaterial {
    var policies: Set<String> { get }
    var keyUsage: [String: Bool] { get }
}

public enum TLQualificationRules {
    public static let tl = "http://uri.etsi.org/02231/v2#"
    public static let sie = "http://uri.etsi.org/TrstSvc/SvcInfoExt/eSigDir-1999-93-EC-TrustedList/#"
    public static let xades = "http://uri.etsi.org/01903/v1.3.2#"
    public static let prefix = "http://uri.etsi.org/TrstSvc/TrustedList/SvcInfoExt/"
    public static func evaluate<M: TLQualificationMaterial>(_ extensions: [TLServiceExtension], material: M) -> Set<String>? {
        var output = Set<String>()
        let known = Set(["QCStatement","NotQualified","QCForESig","QCForESeal","QCForWSA","QCWithQSCD","QCNoQSCD","QCQSCDStatusAsInCert","QCQSCDManagedOnBehalf"].map { prefix+$0 })
        for ext in extensions {
            guard ext.namespace == tl, ext.name == "Extension", ext.children.count == 1,
                  ["true","false","1","0"].contains(ext.attributes["Critical"] ?? "") else { return nil }
            let child = ext.children[0]
            if child.namespace == sie && child.name == "Qualifications" {
                guard !child.children.isEmpty else { return nil }
                for rule in child.children {
                    guard rule.namespace == sie, rule.name == "QualificationElement", rule.children.count == 2,
                          rule.children[0].namespace == sie, rule.children[0].name == "Qualifiers",
                          rule.children[1].namespace == sie, rule.children[1].name == "CriteriaList" else { return nil }
                    guard let applies = criteria(rule.children[1],material:material,depth:0) else { return nil }
                    var values = [String]()
                    for q in rule.children[0].children {
                        guard q.namespace == sie, q.name == "Qualifier", q.children.isEmpty, let uri = q.attributes["uri"], known.contains(uri) else { return nil }; values.append(uri)
                    }
                    guard !values.isEmpty else { return nil }
                    if applies { output.formUnion(values) }
                }
            } else if child.namespace == tl && child.name == "AdditionalServiceInformation" {
                guard child.children.count == 1, child.children[0].namespace == tl, child.children[0].name == "URI",
                      child.children[0].text == prefix+"ForeSignatures" else { return nil }
            } else if ["true","1"].contains(ext.attributes["Critical"] ?? "") { return nil }
        }
        if output.contains(prefix+"QCQSCDStatusAsInCert") && ["QCWithQSCD","QCNoQSCD","QCQSCDManagedOnBehalf"].contains(where: { output.contains(prefix+$0) }) { return nil }
        return output
    }
    public static func criteria<M: TLQualificationMaterial>(_ node: TLServiceExtension, material: M, depth: Int) -> Bool? {
        guard depth <= 12, node.namespace == sie, node.name == "CriteriaList", let assertion = node.attributes["assert"], ["all","atLeastOne","none"].contains(assertion) else { return nil }
        var matches = [Bool]()
        for child in node.children {
            guard child.namespace == sie else { return nil }
            switch child.name {
            case "CriteriaList": guard let r = criteria(child,material:material,depth:depth+1) else { return nil }; matches.append(r)
            case "Description": continue
            case "KeyUsage":
                guard !child.children.isEmpty, !material.keyUsage.isEmpty else { return nil }
                var bits = Set<String>(), ok = true
                for bit in child.children {
                    guard bit.namespace == sie, bit.name == "KeyUsageBit", let name = bit.attributes["name"], let actual = material.keyUsage[name], bits.insert(name).inserted, ["true","1","false","0"].contains(bit.text) else { return nil }
                    ok = ok && actual == ["true","1"].contains(bit.text)
                }; matches.append(ok)
            case "PolicySet":
                guard !child.children.isEmpty else { return nil }
                var policies = [String]()
                for p in child.children {
                    guard p.namespace == sie, p.name == "PolicyIdentifier", let id = p.children.first,
                          id.namespace == xades, id.name == "Identifier", id.attributes["Qualifier"] == "OIDAsURI", id.text.hasPrefix("urn:oid:") else { return nil }
                    policies.append(String(id.text.dropFirst(8)))
                }
                matches.append(policies.allSatisfy { material.policies.contains($0) })
            default: return nil
            }
        }
        guard !matches.isEmpty else { return nil }
        switch assertion { case "all": return matches.allSatisfy { $0 }; case "atLeastOne": return matches.contains(true); default: return !matches.contains(true) }
    }
}
