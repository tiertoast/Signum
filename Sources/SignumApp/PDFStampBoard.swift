#if os(macOS)
import Foundation
import CryptoKit
import SignumCore

/// Single owner of the visible PAdES stamps of the current signing session.
///
/// Rules (each covered by PDFStampBoardTests):
/// - A stamp is *confirmed* when its preview was displayed without errors; only
///   confirmed stamps can be approved.
/// - The *template* is the stamp the user last confirmed with “Conferma
///   anteprima”; merely displaying a preview never changes it.
/// - The PDF open in the editor is never overwritten by a copy.
/// - "Applica a tutti" copies the template to every other pending PDF and turns
///   on *follow* mode: PDFs added later, PDFs switched to PAdES, a new
///   certificate and later edits of the template are propagated automatically
///   to every copy. A copy edited by hand becomes a stamp of its own.
/// - Nothing changes while the batch is frozen (approval or signing); after a
///   declined or cancelled approval everything is available again.
/// - Removing the template's document promotes the most recent other stamp.
@MainActor final class PDFStampBoard: ObservableObject {
    @Published private(set) var placements: [UUID: PAdESPlacement] = [:]
    @Published private(set) var confirmed: Set<UUID> = []
    @Published private(set) var templateID: UUID?
    @Published private(set) var followsTemplate = false
    @Published private(set) var isWorking = false
    @Published private(set) var notice = ""
    /// Draft each copy was made from; a different draft means a manual edit.
    private var copiedFrom: [UUID: PAdESAppearanceConfiguration] = [:]
    private var copyVersion: [UUID: UUID] = [:]
    private var templateVersion = UUID()
    private var manualOrder: [UUID] = []
    private var certificateDER: Data?
    private var knownPDFs: Set<UUID> = []
    private var requests: [String: UUID] = [:] // "copy" and "certificate" run independently.
    private var frozen = false
    /// Off-main rendering seam; tests may run it synchronously.
    var renderer: @Sendable (_ work: @escaping @Sendable () -> [(UUID, Result<RenderedPAdESAppearance, Error>)]) async -> [(UUID, Result<RenderedPAdESAppearance, Error>)] = { work in
        await Task.detached(priority: .userInitiated) { work() }.value
    }

    // MARK: Queries
    func placement(_ id: UUID) -> PAdESPlacement? { placements[id] }
    func isConfirmed(_ id: UUID) -> Bool { confirmed.contains(id) }
    func isCopy(_ id: UUID) -> Bool { copiedFrom[id] != nil }
    func confirmedAppearance(_ id: UUID) -> RenderedPAdESAppearance? { confirmed.contains(id) ? placements[id]?.appearance : nil }
    var appearances: [UUID: RenderedPAdESAppearance] { placements.compactMapValues { $0.appearance } }
    var template: (id: UUID, configuration: PAdESAppearanceConfiguration)? {
        guard let templateID, confirmed.contains(templateID), let value = placements[templateID],
              let config = value.draft ?? value.appearance?.configuration, config.visible else { return nil }
        return (templateID, config)
    }

    // MARK: Editor callbacks
    /// Every edit from the placement pane (drafts and rendered results).
    func edit(_ value: PAdESPlacement?, for id: UUID) {
        guard !frozen else { return }
        placements[id] = value
    }
    /// Document currently open in the stamp editor (set by the window).
    private(set) var editingID: UUID?
    func setEditing(_ id: UUID?, in documents: [BatchDocument]) {
        guard editingID != id else { return }
        editingID = id
        if id == nil, followsTemplate, !frozen { propagate(in: documents) } // A closed editor may need its copy.
    }

    /// The pane reports whether the current stamp is displayed without errors.
    func previewReady(_ id: UUID, _ ready: Bool) {
        guard !frozen else { return }
        if ready, placements[id]?.appearance != nil { confirmed.insert(id) } else { confirmed.remove(id) }
    }

    /// “Conferma anteprima”: an edited or new stamp becomes the template; an
    /// unchanged copy stays a copy.
    func confirmStamp(_ id: UUID, in documents: [BatchDocument]) {
        guard !frozen, confirmed.contains(id), let value = placements[id],
              let draft = value.draft ?? value.appearance?.configuration else { return }
        if let source = copiedFrom[id], source == draft { return }
        copiedFrom[id] = nil; copyVersion[id] = nil
        let changedTemplate = templateID != id || template?.configuration != draft
        manualOrder.removeAll { $0 == id }; manualOrder.append(id)
        templateID = id
        if changedTemplate {
            templateVersion = UUID()
            if followsTemplate { propagate(in: documents) }
        }
    }

    // MARK: Actions
    /// Copy the template to every other pending PDF and follow it from now on.
    func applyToAll(in documents: [BatchDocument]) {
        guard !frozen, template != nil else { return }
        followsTemplate = true; notice = ""
        templateVersion = UUID()
        propagate(in: documents, includingManual: true)
    }

    /// Reconcile with the batch after any change: added/removed documents,
    /// format changes, approval freeze/unfreeze, certificate changes.
    func sync(documents: [BatchDocument], frozen isFrozen: Bool, certificateDER der: Data?) {
        frozen = isFrozen
        guard !isFrozen else { requests = [:]; isWorking = false; return }
        let pdfs = Set(documents.filter { $0.format == .pades && !$0.state.isTerminal }.map(\.id))
        knownPDFs = pdfs
        let templateRemoved = templateID.map { !pdfs.contains($0) } ?? false
        for id in Set(placements.keys).union(confirmed).subtracting(pdfs) { forget(id) }
        // Only a removed document loses the template role; editing it does not.
        if templateRemoved {
            // Prefer the latest hand-made stamp; otherwise promote a copy (same
            // position by construction), so "Applica a tutti" stays available.
            let promoted = manualOrder.last { pdfs.contains($0) && confirmed.contains($0) && copiedFrom[$0] == nil }
                ?? documents.first { pdfs.contains($0.id) && confirmed.contains($0.id) && copiedFrom[$0.id] != nil }?.id
            self.templateID = promoted
            if let promoted, copiedFrom[promoted] != nil {
                copiedFrom[promoted] = nil; copyVersion[promoted] = nil; manualOrder.append(promoted)
            }
            templateVersion = UUID()
        }
        if templateID == nil { followsTemplate = false }
        if pdfs.isEmpty { notice = "" }
        let certificateChanged = der != certificateDER
        certificateDER = der
        if certificateChanged { templateVersion = UUID(); rerenderManualStamps(in: documents) }
        if followsTemplate { propagate(in: documents) }
    }

    func forget(_ id: UUID) {
        placements[id] = nil; confirmed.remove(id); copiedFrom[id] = nil; copyVersion[id] = nil
        manualOrder.removeAll { $0 == id }
        if templateID == id { templateID = nil }
    }

    func reset() {
        requests = [:]
        placements = [:]; confirmed = []; templateID = nil; followsTemplate = false
        isWorking = false; notice = ""; copiedFrom = [:]; copyVersion = [:]; editingID = nil
        manualOrder = []; knownPDFs = []; frozen = false; templateVersion = UUID()
    }

    // MARK: Rendering
    private func pending(_ documents: [BatchDocument]) -> [BatchDocument] {
        documents.filter { $0.format == .pades && !$0.state.isTerminal && !$0.snapshot.isRetired }
    }

    private func propagate(in documents: [BatchDocument], includingManual: Bool = false) {
        guard let template, let der = certificateDER,
              let source = documents.first(where: { $0.id == template.id })?.snapshot else { return }
        let version = templateVersion
        let targets = pending(documents).filter { entry in
            entry.id != template.id && entry.id != editingID && (includingManual || copiedFrom[entry.id] != nil || !confirmed.contains(entry.id)) &&
            (includingManual || copyVersion[entry.id] != version)
        }.map(\.snapshot)
        guard !targets.isEmpty else { return }
        let config = template.configuration
        run("copy", work: {
            let templatePDF: Data
            do { templatePDF = try source.verifiedBytes() }
            catch { return targets.map { ($0.identity.id, .failure(error)) } }
            return targets.map { target in
                (target.identity.id, Result { try PAdESPlacementPropagation.appearance(
                    from: config, templatePDF: templatePDF,
                    targetPDF: target.verifiedBytes(isCancelled: { target.isRetired }), certificateDER: der) })
            }
        }, apply: { id, rendered in
            self.placements[id] = PAdESPlacement(pageIndex: rendered.configuration.pageIndex,
                rectangle: rendered.configuration.rectangle, appearance: rendered, draft: rendered.configuration)
            self.confirmed.insert(id); self.copiedFrom[id] = rendered.configuration; self.copyVersion[id] = version
        }, valid: { self.templateVersion == version && self.certificateDER == der }, names: documents)
    }

    /// Hand-made stamps follow a certificate change without reopening each PDF.
    private func rerenderManualStamps(in documents: [BatchDocument]) {
        guard let der = certificateDER else { return }
        let fingerprint = SHA256.hash(data: der).map { String(format: "%02x", $0) }.joined()
        let targets = pending(documents).compactMap { entry -> (DocumentSnapshot, PAdESAppearanceConfiguration)? in
            guard confirmed.contains(entry.id), copiedFrom[entry.id] == nil,
                  placements[entry.id]?.appearance?.certificateSHA256 != fingerprint,
                  let value = placements[entry.id], let draft = value.draft ?? value.appearance?.configuration,
                  draft.visible else { return nil }
            return (entry.snapshot, draft)
        }
        guard !targets.isEmpty else { return }
        run("certificate", work: {
            targets.map { snapshot, config in
                (snapshot.identity.id, Result { try PAdESPlacementPropagation.rerender(
                    config, pdf: snapshot.verifiedBytes(isCancelled: { snapshot.isRetired }), certificateDER: der) })
            }
        }, apply: { id, rendered in
            guard let draft = self.placements[id]?.draft ?? self.placements[id]?.appearance?.configuration else { return }
            self.placements[id] = PAdESPlacement(pageIndex: draft.pageIndex, rectangle: draft.rectangle,
                                                 appearance: rendered, draft: draft)
        }, valid: { self.certificateDER == der }, names: documents, silent: true)
    }

    private func run(_ kind: String, work: @escaping @Sendable () -> [(UUID, Result<RenderedPAdESAppearance, Error>)],
                     apply: @escaping (UUID, RenderedPAdESAppearance) -> Void, valid: @escaping () -> Bool,
                     names documents: [BatchDocument], silent: Bool = false) {
        let token = UUID(); requests[kind] = token; isWorking = true
        let names = Dictionary(uniqueKeysWithValues: documents.map { ($0.id, $0.snapshot.originalURL.lastPathComponent) })
        Task { @MainActor in
            let results = await renderer(work)
            guard requests[kind] == token else { return }
            requests[kind] = nil; isWorking = !requests.isEmpty
            guard !frozen, valid() else { return }
            var applied = 0, failed: [String] = []
            for (id, result) in results where knownPDFs.contains(id) && id != editingID {
                switch result {
                case .success(let rendered): apply(id, rendered); applied += 1
                case .failure(let error):
                    confirmed.remove(id)
                    failed.append((names[id] ?? "PDF") + " (" + error.localizedDescription + ")")
                }
            }
            if !failed.isEmpty {
                notice = "Timbro non applicabile a: \(failed.joined(separator: "; ")). Posizionalo con “Modifica aspetto…”."
            } else if !silent, applied > 0 {
                notice = applied == 1 ? "Timbro applicato a 1 PDF." : "Timbro applicato a \(applied) PDF."
            }
        }
    }
}
#endif
