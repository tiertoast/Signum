#if os(macOS)
import Foundation
import CSmartCardReaders

/// What macOS reports about smart card readers through PC/SC. Independent of any
/// PKCS#11 software: it is how Signum tells "no reader" from "no card" from
/// "card present, but no software can read it".
public struct SmartCardReaderObservation: Sendable, Equatable {
    public enum CardState: String, Sendable { case empty, present, mute, unknown }
    public struct Reader: Sendable, Equatable {
        public let name: String
        public let card: CardState
        public init(name: String, card: CardState) { self.name = name; self.card = card }
    }
    public enum Availability: Sendable, Equatable { case observed, serviceUnavailable, failed }
    public let availability: Availability
    public let readers: [Reader]
    public init(availability: Availability, readers: [Reader]) { self.availability = availability; self.readers = readers }

    public var withCard: [Reader] { readers.filter { $0.card == .present } }
    public var mute: [Reader] { readers.filter { $0.card == .mute } }
    public var empty: [Reader] { readers.filter { $0.card == .empty } }

    /// Public observation only: no card connection, APDU or vendor code.
    public static func current() -> SmartCardReaderObservation {
        var buffer = [SGReader](repeating: SGReader(), count: 16)
        var count = 0
        let status = buffer.withUnsafeMutableBufferPointer { sg_readers($0.baseAddress, $0.count, &count) }
        switch Int32(status) {
        case Int32(SG_READERS_OK):
            let readers = buffer.prefix(count).map { item -> Reader in
                var raw = item
                let name = withUnsafeBytes(of: &raw.name) { bytes in
                    String(decoding: bytes.prefix { $0 != 0 }, as: UTF8.self)
                }
                let card: CardState
                switch item.state {
                case Int32(SG_READER_EMPTY): card = .empty
                case Int32(SG_READER_PRESENT): card = .present
                case Int32(SG_READER_MUTE): card = .mute
                default: card = .unknown
                }
                return Reader(name: name, card: card)
            }
            return .init(availability: .observed, readers: readers)
        case Int32(SG_READERS_NO_SERVICE): return .init(availability: .serviceUnavailable, readers: [])
        default: return .init(availability: .failed, readers: [])
        }
    }
}
#endif
