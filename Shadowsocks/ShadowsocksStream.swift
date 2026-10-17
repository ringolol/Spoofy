import Foundation
import Network
import os.log

/// A connection to an Outline/Shadowsocks server that looks like a plain connection to the
/// target: `send` encrypts and `receive` decrypts, so `ConnectionRelay` can pipe through it.
/// The framing is `ShadowsocksAEADCodec`; this class only does the I/O. All calls run on `queue`
/// (the session queue).
final class ShadowsocksStream: ConnectionProtocol {
    private static let logger = Logger(subsystem: "com.rnglol.Spoofy", category: "Shadowsocks")

    /// outline-sdk's `ClientDataWait`: how long the address header waits for client data to
    /// ride along with it before it goes out alone (N4).
    static let defaultClientDataWait: TimeInterval = 0.010

    private let underlying: any ConnectionProtocol
    private let queue: DispatchQueue
    private var encoder: ShadowsocksAEADCodec.Encoder
    private var decoder: ShadowsocksAEADCodec.Decoder
    /// The address header, until it has been sent.
    private var pendingHeader: Data?
    private var headerFlush: DispatchWorkItem?
    private var pendingDecrypted = Data()

    /// Starts the header timer at once: a server-first protocol (SMTP, some chat protocols)
    /// sends nothing until the server learns the target, so the header can't wait for the client.
    init(underlying: any ConnectionProtocol, cipher: ShadowsocksCipher, masterKey: Data, salt: Data,
         addressHeader: Data, queue: DispatchQueue, clientDataWait: TimeInterval = defaultClientDataWait) {
        self.underlying = underlying
        self.queue = queue
        encoder = ShadowsocksAEADCodec.Encoder(cipher: cipher, masterKey: masterKey, salt: salt)
        decoder = ShadowsocksAEADCodec.Decoder(cipher: cipher, masterKey: masterKey)
        pendingHeader = addressHeader

        let flush = DispatchWorkItem { [weak self] in self?.flushHeader() }
        headerFlush = flush
        queue.asyncAfter(deadline: .now() + clientDataWait, execute: flush)
    }

    /// The master key is always EVP_BytesToKey(password), as in outline-sdk and shadowbox for
    /// these ciphers. The password is not a base64 key, even though Outline passwords look like
    /// one (N3); the pre-4f code decoded it when it happened to be 32 bytes of base64.
    static func masterKey(for config: OutlineServerConfig) -> Data {
        ShadowsocksCrypto.masterKey(from: config.password, keyLen: ShadowsocksCrypto.keyLength(for: config.cipher))
    }

    /// Dials the Outline server through `dialer` (shared timeout and `.waiting` handling, N1).
    /// Runs on `session.queue`; on success the stream is ready for the relay.
    static func connect(
        config: OutlineServerConfig,
        targetHost: String,
        targetPort: UInt16,
        dialer: Dialing,
        session: SessionScope,
        completion: @escaping (ShadowsocksStream?) -> Void
    ) {
        guard let addressHeader = ShadowsocksAEADCodec.addressHeader(host: targetHost, port: targetPort) else {
            logger.error("Target host too long for Shadowsocks address header: \(targetHost.utf8.count) bytes")
            return completion(nil)
        }
        let salt: Data
        do {
            salt = try ShadowsocksAEADCodec.makeSalt(cipher: config.cipher, prefix: config.prefix)
        } catch {
            // A key saved before N2 was checked at parse time.
            logger.error("Outline prefix is \(config.prefix?.count ?? 0) bytes, longer than the salt; paste the access key again")
            return completion(nil)
        }

        dialer.dial(DialTarget(host: config.host, port: config.port), resolver: nil, session: session) { result in
            switch result {
            case .success(let conn):
                logger.info("Connected to Outline server for \(targetHost):\(targetPort)")
                completion(ShadowsocksStream(underlying: conn, cipher: config.cipher, masterKey: masterKey(for: config),
                                             salt: salt, addressHeader: addressHeader, queue: session.queue))
            case .failure(let error):
                logger.error("Failed to connect to Outline server: \(error.description)")
                completion(nil)
            }
        }
    }

    // MARK: - Send

    func send(content: Data?, contentContext: NWConnection.ContentContext,
              isComplete: Bool, completion: NWConnection.SendCompletion) {
        let plaintext = content ?? Data()
        // The first client data carries the header with it; an empty send still flushes it.
        let payload = takeHeader() + plaintext
        guard !payload.isEmpty else {
            return underlying.send(content: nil, contentContext: contentContext, isComplete: isComplete, completion: completion)
        }
        do {
            let sealed = try encoder.seal(payload)
            underlying.send(content: sealed, contentContext: contentContext, isComplete: isComplete, completion: completion)
        } catch {
            Self.logger.error("Shadowsocks encrypt error: \(error.localizedDescription)")
            cancel()
            if case .contentProcessed(let handler) = completion {
                handler(NWError.posix(.EIO))
            }
        }
    }

    private func flushHeader() {
        guard pendingHeader != nil else { return }
        send(content: nil, contentContext: .defaultMessage, isComplete: false, completion: .contentProcessed { error in
            if let error { Self.logger.debug("Shadowsocks header write failed: \(error.localizedDescription)") }
        })
    }

    private func takeHeader() -> Data {
        guard let header = pendingHeader else { return Data() }
        pendingHeader = nil
        headerFlush?.cancel()
        headerFlush = nil
        return header
    }

    // MARK: - Receive

    func receive(minimumIncompleteLength: Int, maximumLength: Int,
                 completion: @escaping @Sendable (Data?, NWConnection.ContentContext?, Bool, NWError?) -> Void) {
        if !pendingDecrypted.isEmpty {
            return completion(takeDecrypted(maximumLength), .defaultMessage, false, nil)
        }
        underlying.receive(minimumIncompleteLength: 1, maximumLength: 32768) { [self] data, ctx, isComplete, error in
            if let error {
                return completion(nil, ctx, isComplete, error)
            }
            do {
                pendingDecrypted += try decoder.feed(data ?? Data())
            } catch {
                Self.logger.error("Shadowsocks decrypt failure (\(String(describing: error))), closing stream")
                completion(nil, nil, true, NWError.posix(.EIO))
                return cancel()
            }
            if !pendingDecrypted.isEmpty {
                completion(takeDecrypted(maximumLength), .defaultMessage, false, nil)
            } else if isComplete {
                completion(nil, ctx, true, nil)
            } else {
                receive(minimumIncompleteLength: minimumIncompleteLength, maximumLength: maximumLength, completion: completion)
            }
        }
    }

    private func takeDecrypted(_ maximumLength: Int) -> Data {
        let chunk = Data(pendingDecrypted.prefix(maximumLength))
        pendingDecrypted = Data(pendingDecrypted.dropFirst(chunk.count))
        return chunk
    }

    // MARK: - Cancel

    func cancel() {
        headerFlush?.cancel()
        headerFlush = nil
        underlying.cancel()
    }
}
