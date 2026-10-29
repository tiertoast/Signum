#if os(macOS)
import Foundation
import Combine
import CoreGraphics
import CryptoKit
import SignumCore

/// One in-flight operation and one replaceable pending value per pane. No global
/// serial worker, unbounded queue, retry, PDFDocument or credentials.
@MainActor final class PAdESRenderCoordinator: ObservableObject {
    typealias Renderer = @Sendable (PAdESAppearanceConfiguration, Data, CGRect, @Sendable () -> Bool) throws -> RenderedPAdESAppearance
    private struct Request {
        let id: UUID, configuration: PAdESAppearanceConfiguration, der: Data, crop: CGRect
        let pageRotation: Int?
        let previous: RenderedPAdESAppearance?
        let receive: (Result<RenderedPAdESAppearance,Error>) -> Void
    }
    private let renderer: (@Sendable (PAdESAppearanceConfiguration, Data, CGRect, Int?, @Sendable () -> Bool) throws -> RenderedPAdESAppearance)
    private var active: Task<Void,Never>?
    private var cancellation: SigningOperation?
    private var pending: Request?
    private var generation = UUID()
    private var suspended = false
    func suspend() { suspended = true; cancel() }
    func resume() { suspended = false }
    private var idleObservers: [() -> Void] = []
    func whenIdle(_ receive: @escaping () -> Void) {
        if isIdle { receive() } else { idleObservers.append(receive) }
    }
    private(set) var started = 0
    private(set) var discarded = 0
    private(set) var published = 0
    var isIdle: Bool { active == nil && pending == nil }
    init(renderer: Renderer? = nil) {
        self.renderer = { config,der,crop,rotation,cancelled in
            if let renderer { return try renderer(config,der,crop,cancelled) }
            return try PAdESAppearanceRenderer.render(config,certificateDER:der,cropBox:crop,pageRotation:rotation,isCancelled:cancelled)
        }
    }
    func submit(_ configuration:PAdESAppearanceConfiguration, der:Data, crop:CGRect, pageRotation:Int? = nil,
                previous:RenderedPAdESAppearance? = nil,
                receive:@escaping (Result<RenderedPAdESAppearance,Error>)->Void) {
        guard !suspended else { return }
        let request = Request(id:UUID(),configuration:configuration,der:der,crop:crop,
                              pageRotation:pageRotation,previous:previous,receive:receive)
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
        // Keep the UI callback in the MainActor request. Only immutable artwork
        // values and the lock-protected cancellation token enter the worker.
        let configuration=request.configuration, der=request.der, crop=request.crop
        let rotation=request.pageRotation, previous=request.previous
        active = Task { @MainActor [weak self] in
            let result = await Task.detached(priority:.userInitiated) {
                Result {
                    if let previous,let rotation,
                       previous.certificateSHA256 == SHA256.hash(data:der).map({ String(format:"%02x",$0) }).joined(),
                       previous.canReorient(to:configuration,pageRotation:rotation) {
                        return try previous.reoriented(configuration,cropBox:crop,pageRotation:rotation,
                                                       isCancelled:{cancellation.isCancellationRequested})
                    }
                    return try renderer(configuration,der,crop,rotation,{ cancellation.isCancellationRequested })
                }
            }.value
            guard let self else { return }
            self.active = nil; self.cancellation = nil
            if self.generation == request.id, !cancellation.isCancellationRequested {
                self.published += 1; request.receive(result)
            } else { self.discarded += 1 }
            if let next = self.pending { self.pending = nil; self.start(next) }
            if self.isIdle { let callbacks = self.idleObservers; self.idleObservers = []; callbacks.forEach { $0() } }
        }
    }
}
#endif
