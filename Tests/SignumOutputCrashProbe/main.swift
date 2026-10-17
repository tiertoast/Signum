// Offline test fixture only. Kills itself after staging, before publication.
import Foundation
import Darwin
import SignumCore

if CommandLine.arguments.count == 3, CommandLine.arguments[1] == "snapshot-crash" {
    let snapshot = try DocumentSnapshot.capture(source: URL(fileURLWithPath: CommandLine.arguments[2]), format: .cades)
    print(snapshot.fileURL.path)
    fflush(stdout)
    // Parent observes the active private copy before releasing this crash barrier.
    var signal: UInt8 = 0
    _ = Darwin.read(STDIN_FILENO, &signal, 1)
    kill(getpid(), SIGKILL)
    exit(5)
}
guard CommandLine.arguments.count == 2 else { exit(2) }
try SignumFileOutput.writeNew(Data("Synthetic crash fixture".utf8),
                              to: URL(fileURLWithPath: CommandLine.arguments[1])) { _ in
    kill(getpid(), SIGKILL)
    exit(3)
}
exit(4)
