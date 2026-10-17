import AVFoundation
import UIKit
import os.log

/// Plays silence in a loop so iOS keeps the app, and the proxy, running in the background.
///
/// Anything that stops the audio lets iOS suspend the app, so it is restarted after (U11):
/// - an interruption (a phone call, Siri, an alarm). `shouldResume` is ignored: it's a hint for
///   audible playback, and this player is silent.
/// - a media-services reset, which invalidates the session and every player, so both are rebuilt.
/// - the app becoming active, as a fallback for an interruption whose `.ended` never arrives.
///
/// Called on the main thread (by `ProxyManager`); the observers run on the main queue too.
final class BackgroundAudioPlayer {
    private static let logger = Logger(subsystem: "com.rnglol.Spoofy", category: "BackgroundAudioPlayer")

    private var player: AVAudioPlayer?
    /// Between `start()` and `stop()`: the audio should be playing.
    private var isActive = false
    private var observers: [NSObjectProtocol] = []

    init() {
        let center = NotificationCenter.default
        observers = [
            center.addObserver(forName: AVAudioSession.interruptionNotification, object: nil, queue: .main) { [weak self] note in
                self?.handleInterruption(note)
            },
            center.addObserver(forName: AVAudioSession.mediaServicesWereResetNotification, object: nil, queue: .main) { [weak self] _ in
                guard let self, self.isActive else { return }
                Self.logger.warning("Media services were reset, rebuilding the audio player")
                self.player = nil
                self.play()
            },
            center.addObserver(forName: UIApplication.didBecomeActiveNotification, object: nil, queue: .main) { [weak self] _ in
                guard let self, self.isActive, self.player?.isPlaying != true else { return }
                Self.logger.info("Background audio was not playing on activation, resuming")
                self.play()
            },
        ]
    }

    deinit {
        observers.forEach(NotificationCenter.default.removeObserver)
    }

    func start() {
        isActive = true
        play()
    }

    func stop() {
        isActive = false
        player?.stop()
        player = nil

        do {
            try AVAudioSession.sharedInstance().setActive(false, options: .notifyOthersOnDeactivation)
        } catch {
            Self.logger.error("Failed to deactivate audio session: \(error.localizedDescription)")
        }

        Self.logger.info("Background audio stopped")
    }

    private func handleInterruption(_ note: Notification) {
        guard isActive,
              let raw = note.userInfo?[AVAudioSessionInterruptionTypeKey] as? UInt,
              let type = AVAudioSession.InterruptionType(rawValue: raw) else { return }
        switch type {
        case .began:
            Self.logger.info("Background audio interrupted")
        case .ended:
            Self.logger.info("Audio interruption ended, resuming")
            play()
        @unknown default:
            break
        }
    }

    /// Activates the session and plays, reusing the player when it still works.
    private func play() {
        let session = AVAudioSession.sharedInstance()
        do {
            try session.setCategory(.playback, options: .mixWithOthers)
            try session.setActive(true)
        } catch {
            Self.logger.error("Failed to configure audio session: \(error.localizedDescription)")
            return
        }

        if let player, player.play() {
            Self.logger.info("Background audio resumed")
            return
        }

        let wavData = Self.generateSilentWAV(durationSeconds: 10, sampleRate: 8000)
        do {
            let audioPlayer = try AVAudioPlayer(data: wavData)
            audioPlayer.numberOfLoops = -1 // loop forever
            audioPlayer.volume = 0.0
            guard audioPlayer.play() else {
                Self.logger.error("Audio player refused to play")
                return
            }
            self.player = audioPlayer
        } catch {
            Self.logger.error("Failed to start audio player: \(error.localizedDescription)")
            return
        }

        Self.logger.info("Background audio started")
    }

    /// Generates a minimal silent WAV file in memory.
    private static func generateSilentWAV(durationSeconds: Int, sampleRate: Int) -> Data {
        let numSamples = sampleRate * durationSeconds
        let bitsPerSample = 16
        let numChannels = 1
        let byteRate = sampleRate * numChannels * (bitsPerSample / 8)
        let blockAlign = numChannels * (bitsPerSample / 8)
        let dataSize = numSamples * numChannels * (bitsPerSample / 8)
        let fileSize = 36 + dataSize

        var data = Data()

        // RIFF header
        data.append(contentsOf: [0x52, 0x49, 0x46, 0x46]) // "RIFF"
        data.append(contentsOf: withUnsafeBytes(of: UInt32(fileSize).littleEndian) { Array($0) })
        data.append(contentsOf: [0x57, 0x41, 0x56, 0x45]) // "WAVE"

        // fmt subchunk
        data.append(contentsOf: [0x66, 0x6D, 0x74, 0x20]) // "fmt "
        data.append(contentsOf: withUnsafeBytes(of: UInt32(16).littleEndian) { Array($0) }) // subchunk size
        data.append(contentsOf: withUnsafeBytes(of: UInt16(1).littleEndian) { Array($0) }) // PCM format
        data.append(contentsOf: withUnsafeBytes(of: UInt16(numChannels).littleEndian) { Array($0) })
        data.append(contentsOf: withUnsafeBytes(of: UInt32(sampleRate).littleEndian) { Array($0) })
        data.append(contentsOf: withUnsafeBytes(of: UInt32(byteRate).littleEndian) { Array($0) })
        data.append(contentsOf: withUnsafeBytes(of: UInt16(blockAlign).littleEndian) { Array($0) })
        data.append(contentsOf: withUnsafeBytes(of: UInt16(bitsPerSample).littleEndian) { Array($0) })

        // data subchunk
        data.append(contentsOf: [0x64, 0x61, 0x74, 0x61]) // "data"
        data.append(contentsOf: withUnsafeBytes(of: UInt32(dataSize).littleEndian) { Array($0) })
        data.append(Data(count: dataSize)) // silent samples (all zeros)

        return data
    }
}
