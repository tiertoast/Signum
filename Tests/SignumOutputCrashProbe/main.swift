// Offline test fixture only. Kills itself after staging, before publication.
import Foundation
import Darwin
import SignumCore

guard CommandLine.arguments.count == 2 else { exit(2) }
try SignumFileOutput.writeNew(Data("Synthetic crash fixture".utf8),
                              to: URL(fileURLWithPath: CommandLine.arguments[1])) { _ in
    kill(getpid(), SIGKILL)
    exit(3)
}
exit(4)
