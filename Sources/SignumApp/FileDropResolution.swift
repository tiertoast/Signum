#if os(macOS)
import Foundation
import UniformTypeIdentifiers

/// All mutable collector fields are lock-protected; completion is Sendable and
/// invoked once outside the lock. Provider registration remains on MainActor;
/// no NSItemProvider crosses an executor. Bounded collection: late/duplicate callbacks cannot reorder the user's list
/// or resume a continuation twice. A broken external drag source cannot keep
/// the interface waiting indefinitely.
final class FileDropResolution: @unchecked Sendable {
    private let lock = NSLock()
    private var values: [URL?]
    private var received = Set<Int>()
    private var completion: (@Sendable ([URL]) -> Void)?
    init(count: Int, completion: @escaping @Sendable ([URL]) -> Void) {
        values = Array(repeating: nil, count: count); self.completion = completion
    }
    func receive(index: Int, url: URL?) {
        lock.lock()
        guard completion != nil, values.indices.contains(index), received.insert(index).inserted else { lock.unlock(); return }
        values[index] = url?.isFileURL == true ? url : nil
        let done = received.count == values.count
        lock.unlock()
        if done { finish() }
    }
    func finish() {
        lock.lock()
        let callback = completion, result = values.compactMap { $0 }
        completion = nil
        lock.unlock()
        callback?(result)
    }
    /// Registers cancellation before starting any provider; a callback may be
    /// synchronous, duplicated, late, or absent. All converge on finish once.
    private final class Cancellation: @unchecked Sendable {
        private let lock = NSLock()
        private var result: FileDropResolution?
        private var cancelled = false
        func install(_ result: FileDropResolution) {
            lock.lock(); self.result = result; let stop = cancelled; lock.unlock()
            if stop { result.finish() }
        }
        func cancel() {
            lock.lock(); cancelled = true; let current = result; lock.unlock()
            current?.finish()
        }
    }
    typealias Loader = @MainActor (@escaping @Sendable (URL?) -> Void) -> Void
    @MainActor static func resolve(_ items: [NSItemProvider], timeout: TimeInterval = 10) async -> [URL] {
        guard timeout.isFinite, timeout > 0 else { return [] }
        let loaders: [Loader] = items.map { item in { receive in
            item.loadItem(forTypeIdentifier: UTType.fileURL.identifier, options: nil) { value, _ in
                let url = (value as? URL) ?? (value as? Data).flatMap { URL(dataRepresentation: $0, relativeTo: nil) }
                receive(url)
            }
        } }
        return await resolve(loaders: loaders, scheduleTimeout: { finish in
            DispatchQueue.global().asyncAfter(deadline: .now() + min(30, max(0.01, timeout)), execute: finish)
        })
    }
    @MainActor static func resolve(loaders: [Loader], scheduleTimeout: (@escaping @Sendable () -> Void) -> Void) async -> [URL] {
        guard !loaders.isEmpty, loaders.count <= 32, !Task.isCancelled else { return [] }
        let cancellation = Cancellation()
        let urls = await withTaskCancellationHandler(operation: {
            await withCheckedContinuation { continuation in
                let result = FileDropResolution(count: loaders.count) { continuation.resume(returning: $0) }
                cancellation.install(result)
                scheduleTimeout { result.finish() }
                for (index, load) in loaders.enumerated() where !Task.isCancelled {
                    load { result.receive(index: index, url: $0) }
                }
            }
        }, onCancel: { cancellation.cancel() })
        return Task.isCancelled ? [] : urls
    }
}
#endif
