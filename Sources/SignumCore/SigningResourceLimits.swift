/// Bounded in-memory implementation. Documents never travel through worker IPC.
/// A streaming CMS/snapshot design is required before raising the session budget.
public enum SigningResourceLimits {
    public static let maximumDocumentBytes = 100 * 1024 * 1024
    public static let maximumSessionBytes = 128 * 1024 * 1024
    public static let maximumOutputBytes = 132 * 1024 * 1024
}
