#if os(macOS)
import SwiftUI
import SignumCore

struct BatchConsentView: View {
    let approval: BatchApproval
    var body: some View {
        VStack(alignment: .leading, spacing: 10) {
            ScrollView {
                VStack(alignment: .leading, spacing: 12) {
                    ForEach(approval.jobs, id: \.id) { job in
                        VStack(alignment: .leading, spacing: 3) {
                            Text(job.snapshot.originalURL.lastPathComponent).font(.headline)
                            Text(job.formatDescription).font(.callout.bold())
                            Text(job.signingTimeDeclaration).font(.caption).fixedSize(horizontal: false, vertical: true)
                            Text("Origine: " + BatchDisplay.sourceLabel(job.snapshot.originalURL, among: approval.jobs.map { $0.snapshot.originalURL })).font(.caption)
                            Text("Destinazione: " + BatchDisplay.destinationLabel(job.destination, among: approval.jobs.map(\.destination))).font(.caption).textSelection(.enabled)
                        }
                    }
                }.frame(maxWidth: .infinity, alignment: .leading)
            }
            DisclosureGroup("Dettagli tecnici") {
                ScrollView { Text(approval.technicalDetails).font(.caption2).textSelection(.enabled) }
                    .frame(maxHeight: 110)
            }
            Text("Saranno firmate queste copie. Le successive modifiche agli originali non saranno incluse.")
                .font(.caption).foregroundStyle(.secondary)
        }.padding(4)
    }
}
#endif
