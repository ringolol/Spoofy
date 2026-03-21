import AVFoundation
import os.log

final class BackgroundAudioPlayer {
    private static let logger = Logger(subsystem: "com.rnglol.Spoofy", category: "BackgroundAudioPlayer")

    private var player: AVAudioPlayer?

    func start() {
        let session = AVAudioSession.sharedInstance()
        do {
            try session.setCategory(.playback, options: .mixWithOthers)
            try session.setActive(true)
        } catch {
            Self.logger.error("Failed to configure audio session: \(error.localizedDescription)")
            return
        }

        let wavData = Self.generateSilentWAV(durationSeconds: 10, sampleRate: 8000)

        do {
            let audioPlayer = try AVAudioPlayer(data: wavData)
            audioPlayer.numberOfLoops = -1 // loop forever
            audioPlayer.volume = 0.0
            audioPlayer.play()
            self.player = audioPlayer
        } catch {
            Self.logger.error("Failed to start audio player: \(error.localizedDescription)")
            return
        }

        Self.logger.info("Background audio started")
    }

    func stop() {
        player?.stop()
        player = nil

        do {
            try AVAudioSession.sharedInstance().setActive(false, options: .notifyOthersOnDeactivation)
        } catch {
            Self.logger.error("Failed to deactivate audio session: \(error.localizedDescription)")
        }

        Self.logger.info("Background audio stopped")
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
