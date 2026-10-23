#if os(macOS)
import Foundation
import SignumCore

/// Public discovery only; the existing worker and Core selection stay authoritative.
struct DeviceRefreshLifecycle {
    private(set) var requestID: UUID?
    mutating func begin(selection: inout DeviceSelection, blocked: Bool) -> UUID? {
        guard !blocked, requestID == nil, !selection.isSearching else { return nil }
        let id = selection.beginDiscovery()
        requestID = id
        return id
    }
    mutating func accept(_ result: DeviceDiscoveryResult, request: UUID,
                         selection: inout DeviceSelection) -> Bool {
        guard requestID == request, selection.accept(result, request: request) else { return false }
        requestID = nil
        return true
    }
    mutating func cancel() { requestID = nil }
}
#endif
