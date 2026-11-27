#if os(macOS)
import AppKit

struct SignumUpdatePreferences {
    enum Keys {
        static let checkAtLaunch = "signum.updates.checkAtLaunch.v1"
        static let installAutomatically = "signum.updates.installAutomatically.v1"
    }
    let defaults: UserDefaults
    init(defaults: UserDefaults = .standard) { self.defaults = defaults }
    var checkAtLaunch: Bool {
        get { defaults.object(forKey: Keys.checkAtLaunch) == nil || defaults.bool(forKey: Keys.checkAtLaunch) }
        nonmutating set { defaults.set(newValue, forKey: Keys.checkAtLaunch) }
    }
    var installAutomatically: Bool {
        get { defaults.object(forKey: Keys.installAutomatically) == nil || defaults.bool(forKey: Keys.installAutomatically) }
        nonmutating set { defaults.set(newValue, forKey: Keys.installAutomatically) }
    }
}

/// Launch check, download, staging and install-at-quit. Never interrupts a
/// sheet (PIN entry, approvals): automatic notices wait until none is open.
@MainActor final class SignumUpdateController {
    static let shared = SignumUpdateController()

    private let transport = SignumUpdateHTTPS()
    private var installer = SignumUpdateInstaller()
    private let preferences = SignumUpdatePreferences()
    private var running = false
    private var staged: (offer: SignumUpdateOffer, app: URL)?
    private var relaunchAfterInstall = false
    private var announcedThisLaunch: Set<Int> = []

    var currentBuild: Int { Int(Bundle.main.infoDictionary?["CFBundleVersion"] as? String ?? "") ?? 0 }
    var window: () -> NSWindow? = { NSApp.mainWindow ?? NSApp.windows.first { $0.isVisible } }
    /// Set by the app lifecycle: true when no signing work is running or draining.
    var isSigningIdle: () -> Bool = { true }

    func launchCheck() {
        guard preferences.checkAtLaunch, currentBuild > 0 else { return }
        Task { try? await Task.sleep(nanoseconds: 4_000_000_000); await run(userInitiated: false) }
    }
    @objc func checkNow() { Task { await run(userInitiated: true) } }

    func run(userInitiated: Bool) async {
        guard !running else { return }
        if let staged { if userInitiated { presentReady(staged.offer) }; return }
        running = true; defer { running = false }
        do {
            let checker = SignumUpdateChecker(transport: transport)
            guard let offer = try await checker.check(currentBuild: currentBuild) else {
                if userInitiated {
                    present(title: "Signum è aggiornata", message: "Stai usando la build più recente (\(currentBuild)).",
                            buttons: ["OK"], automatic: false) { _ in }
                }
                return
            }
            guard userInitiated || !announcedThisLaunch.contains(offer.build) else { return }
            announcedThisLaunch.insert(offer.build)
            let location = SignumUpdateInstaller.installability(of: Bundle.main.bundleURL, bundleIdentifier: Bundle.main.bundleIdentifier)
            guard offer.verified != nil, location == .installable else {
                var reason = "Questa versione non può essere installata automaticamente: scaricala dalla pagina della release."
                if case .unavailable(let why) = location { reason = why + " Puoi scaricarla dalla pagina della release." }
                presentManual(offer, reason: reason, automatic: !userInitiated); return
            }
            if preferences.installAutomatically { try await prepare(offer, userInitiated: userInitiated) }
            else {
                present(title: "È disponibile \(offer.title)",
                        message: "Signum può scaricarla, verificarne la firma e installarla alla chiusura.",
                        buttons: ["Installa", "Più tardi", "Note di rilascio"], automatic: !userInitiated) { [weak self] choice in
                    if choice == 0 { Task { try? await self?.prepare(offer, userInitiated: true) } }
                    if choice == 2 { NSWorkspace.shared.open(offer.page) }
                }
            }
        } catch {
            if userInitiated {
                present(title: "Controllo aggiornamenti non riuscito", message: error.localizedDescription,
                        buttons: ["OK"], automatic: false) { _ in }
            }
        }
    }

    private func prepare(_ offer: SignumUpdateOffer, userInitiated: Bool) async throws {
        guard let verified = offer.verified else { return }
        do {
            let data = try await transport.fetch(verified.dmg, limit: min(verified.manifest.dmg.bytes, SignumUpdatePolicy.dmgLimit))
            let installer = self.installer
            let app = try await Task.detached(priority: .utility) {
                try installer.stage(dmg: try installer.store(data, for: verified.manifest), manifest: verified.manifest)
            }.value
            staged = (offer, app)
            presentReady(offer)
        } catch {
            presentManual(offer, reason: "Preparazione non riuscita: \(error.localizedDescription)", automatic: !userInitiated)
        }
    }

    private func presentReady(_ offer: SignumUpdateOffer) {
        present(title: "\(offer.title) è pronta",
                message: "La firma dell’aggiornamento è verificata. Verrà installata alla chiusura di Signum; puoi anche riavviare adesso.",
                buttons: ["Riavvia e aggiorna", "Alla chiusura", "Note di rilascio"], automatic: true) { [weak self] choice in
            guard let self else { return }
            if choice == 0, self.isSigningIdle() { self.relaunchAfterInstall = true; NSApp.terminate(nil) }
            if choice == 2 { NSWorkspace.shared.open(offer.page) }
        }
    }

    private func presentManual(_ offer: SignumUpdateOffer, reason: String, automatic: Bool) {
        present(title: "È disponibile \(offer.title)", message: reason,
                buttons: ["Apri la pagina della release", "Più tardi"], automatic: automatic) { choice in
            if choice == 0 { NSWorkspace.shared.open(offer.page) }
        }
    }

    /// Called from `applicationWillTerminate`: hands the staged bundle to the swap helper.
    func installStagedUpdateAtExit() {
        guard let staged else { return }
        _ = try? SignumUpdateInstaller.launchSwap(staged: staged.app, destination: Bundle.main.bundleURL,
                                                  relaunch: relaunchAfterInstall)
        self.staged = nil
    }

    private func present(title: String, message: String, buttons: [String], automatic: Bool,
                         attempt: Int = 0, completion: @escaping (Int) -> Void) {
        let target = window()
        if automatic, target?.attachedSheet != nil || NSApp.modalWindow != nil || !isSigningIdle() {
            guard attempt < 120 else { return }
            DispatchQueue.main.asyncAfter(deadline: .now() + 15) { [weak self] in
                self?.present(title: title, message: message, buttons: buttons, automatic: true,
                              attempt: attempt + 1, completion: completion)
            }
            return
        }
        let alert = NSAlert()
        alert.messageText = title; alert.informativeText = message
        buttons.forEach { alert.addButton(withTitle: $0) }
        let index: (NSApplication.ModalResponse) -> Int = { $0.rawValue - NSApplication.ModalResponse.alertFirstButtonReturn.rawValue }
        if let target, target.attachedSheet == nil {
            alert.beginSheetModal(for: target) { completion(index($0)) }
        } else {
            completion(index(alert.runModal()))
        }
    }
}
#endif
