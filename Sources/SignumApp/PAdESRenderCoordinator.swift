#if os(macOS)
import Foundation
import Combine
import CoreGraphics
import SignumCore

/// One in-flight operation and one replaceable pending value per pane. No global
/// serial worker, unbounded queue, retry, PDFDocument or credentials.
@MainActor final class PAdESRenderCoordinator: ObservableObject {
    typealias Renderer = @Sendable (PAdESAppearanceConfiguration, Data, CGRect, @Sendable () -> Bool) throws -> RenderedPAdESAppearance
    private struct Request {
        let id: UUID, configuration: PAdESAppearanceConfiguration, der: Data, crop: CGRect
        let receive: (Result<RenderedPAdESAppearance,Error>) -> Void
    }
    private let renderer: Renderer
    private var active: Task<Void,Never>?
    private var cancellation: SigningOperation?
    private var pending: Request?
    private var generation = UUID()
    private(set) var started = 0
    private(set) var discarded = 0
    private(set) var published = 0
    var isIdle: Bool { active == nil && pending == nil }
    init(renderer: @escaping Renderer = { config,der,crop,cancelled in
        try PAdESAppearanceRenderer.render(config,certificateDER:der,cropBox:crop,isCancelled:cancelled)
    }) { self.renderer = renderer }
    func submit(_ configuration:PAdESAppearanceConfiguration, der:Data, crop:CGRect,
                receive:@escaping (Result<RenderedPAdESAppearance,Error>)->Void) {
        let request = Request(id:UUID(),configuration:configuration,der:der,crop:crop,receive:receive)
        generation = request.id
        if active != nil { cancellation?.requestCancellation(); pending = request }
        else { start(request) }
    }
    func cancel() {
        generation = UUID(); pending = nil; cancellation?.requestCancellation()
    }
    private func start(_ request:Request) {
        started += 1
        let cancellation = SigningOperation(), renderer = self.renderer
        self.cancellation = cancellation
        active = Task { @MainActor [weak self] in
            let result = await Task.detached(priority:.userInitiated) {
                Result { try renderer(request.configuration,request.der,request.crop,{ cancellation.isCancellationRequested }) }
            }.value
            guard let self else { return }
            self.active = nil; self.cancellation = nil
            if self.generation == request.id, !cancellation.isCancellationRequested {
                self.published += 1; request.receive(result)
            } else { self.discarded += 1 }
            if let next = self.pending { self.pending = nil; self.start(next) }
        }
    }
}
#endif
