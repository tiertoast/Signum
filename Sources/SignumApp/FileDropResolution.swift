#if os(macOS)
import Foundation
import UniformTypeIdentifiers

/// Bounded collection: late/duplicate callbacks cannot reorder the user's list
/// or resume a continuation twice. A broken external drag source cannot keep
/// the interface waiting indefinitely.
final class FileDropResolution: @unchecked Sendable {
    private let lock = NSLock()
    private var values: [URL?]
    private var received = Set<Int>()
    private var completion: (([URL]) -> Void)?
    init(count: Int, completion: @escaping ([URL]) -> Void) {
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
    static func resolve(_ items: [NSItemProvider]) async -> [URL] {
        guard !items.isEmpty else { return [] }
        return await withCheckedContinuation { continuation in
            let result = FileDropResolution(count: items.count) { continuation.resume(returning: $0) }
            DispatchQueue.global().asyncAfter(deadline: .now() + 10) { result.finish() }
            for (index, item) in items.enumerated() {
                item.loadItem(forTypeIdentifier: UTType.fileURL.identifier, options: nil) { value, _ in
                    let url: URL?
                    if let file = value as? URL { url = file }
                    else if let data = value as? Data { url = URL(dataRepresentation: data, relativeTo: nil) }
                    else { url = nil }
                    result.receive(index: index, url: url)
                }
            }
        }
    }
}
#endif
