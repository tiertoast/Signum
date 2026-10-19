#if os(macOS)
import Foundation
import CoreGraphics

/// Manual angles are CLOCKWISE relative to the viewer's normal reading direction.
/// Automatic and degrees0 have the same visual result, but distinct consent values.
public enum PAdESAppearanceOrientation: String, CaseIterable, Sendable {
    case automatic, degrees0, degrees90, degrees180, degrees270
    public var title: String {
        switch self {
        case .automatic: return "Automatico"
        case .degrees0: return "0°"
        case .degrees90: return "90°"
        case .degrees180: return "180°"
        case .degrees270: return "270°"
        }
    }
    public func resolve(pageRotation: Int) throws -> PAdESAppearanceResolution {
        let normalized = ((pageRotation % 360) + 360) % 360
        guard normalized % 90 == 0 else { throw SignumError.module("Rotazione pagina non supportata: serve un multiplo di 90°.") }
        let clockwise: Int
        switch self {
        case .automatic, .degrees0: clockwise = 0
        case .degrees90: clockwise = 90
        case .degrees180: clockwise = 180
        case .degrees270: clockwise = 270
        }
        return .init(pageRotation: normalized, viewerClockwiseDegrees: clockwise,
                     artworkCounterclockwiseDegrees: (normalized-clockwise+360)%360)
    }
}

public struct PAdESAppearanceResolution: Equatable, Sendable {
    public let pageRotation: Int
    public let viewerClockwiseDegrees: Int
    public let artworkCounterclockwiseDegrees: Int
    public var swapsAxes: Bool { artworkCounterclockwiseDegrees % 180 == 90 }
    public func contentSize(forFootprint size: CGSize) -> CGSize {
        swapsAxes ? CGSize(width:size.height,height:size.width) : size
    }
    public func footprintSize(forContent size: CGSize) -> CGSize { contentSize(forFootprint:size) }
    /// Exact quarter turns in raw PDF coordinates. Translation encloses the whole
    /// artwork in a zero-origin footprint; no stretching, clipping or page rotation.
    public func transform(contentSize s: CGSize) -> CGAffineTransform {
        switch artworkCounterclockwiseDegrees {
        case 90: return .init(a:0,b:1,c:-1,d:0,tx:s.height,ty:0)
        case 180: return .init(a:-1,b:0,c:0,d:-1,tx:s.width,ty:s.height)
        case 270: return .init(a:0,b:-1,c:1,d:0,tx:0,ty:s.width)
        default: return .identity
        }
    }
}

extension PAdESAppearanceConfiguration {
    public func contentSize(pageRotation: Int) throws -> CGSize {
        try orientation.resolve(pageRotation:pageRotation).contentSize(forFootprint:rectangle.size)
    }
    /// Preserve the artwork's logical width/height and center when orientation
    /// or page changes. Clamp translation only. Never silently shrink the artwork.
    public func reoriented(to orientation: PAdESAppearanceOrientation, fromPageRotation: Int,
                           toPageRotation: Int, cropBox: CGRect) throws -> Self {
        let size = try contentSize(pageRotation:fromPageRotation)
        var next = self; next.orientation = orientation
        return try next.resized(contentSize:size,pageRotation:toPageRotation,cropBox:cropBox)
    }
    public func resized(contentSize: CGSize, pageRotation: Int, cropBox: CGRect) throws -> Self {
        let size = try orientation.resolve(pageRotation:pageRotation).footprintSize(forContent:contentSize)
        guard size.width <= cropBox.width, size.height <= cropBox.height else {
            throw SignumError.module("Il timbro orientato non rientra nella pagina. Riduci larghezza o altezza.")
        }
        var next = self
        next.rectangle = CGRect(x:min(max(rectangle.midX-size.width/2,cropBox.minX),cropBox.maxX-size.width),
                                y:min(max(rectangle.midY-size.height/2,cropBox.minY),cropBox.maxY-size.height),width:size.width,height:size.height)
        try next.validate(cropBox:cropBox,pageRotation:pageRotation)
        return next
    }
    public func resized(toward point: CGPoint, pageRotation: Int, cropBox: CGRect) throws -> Self {
        let resolved = try orientation.resolve(pageRotation:pageRotation)
        let minimum = resolved.footprintSize(forContent:CGSize(width:80,height:40))
        let maximum = resolved.footprintSize(forContent:CGSize(width:800,height:500))
        var next = self
        next.rectangle.size = CGSize(width:min(max(minimum.width,point.x-rectangle.minX),min(maximum.width,cropBox.maxX-rectangle.minX)),
                                     height:min(max(minimum.height,point.y-rectangle.minY),min(maximum.height,cropBox.maxY-rectangle.minY)))
        try next.validate(cropBox:cropBox,pageRotation:pageRotation)
        return next
    }
}
#endif
