(function() {
  function log(message) {
    if (typeof console !== "undefined" && console.log) {
      console.log(message);
    }
  }

  function logError(message, error) {
    if (typeof console !== "undefined" && console.error) {
      console.error(message, error || "");
    }
  }

  function parseCertHashes(raw) {
    if (!raw) {
      return [];
    }

    const entries = raw.split(/[;,]+/);
    const hashes = [];

    for (const entry of entries) {
      const trimmed = entry.trim();
      if (!trimmed) {
        continue;
      }

      const hex = trimmed.replace(/[^0-9a-fA-F]/g, "");
      if (!hex || (hex.length % 2) !== 0) {
        continue;
      }

      const value = new Uint8Array(hex.length / 2);
      for (let i = 0; i < value.length; i++) {
        value[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
      }

      hashes.push({
        algorithm: "sha-256",
        value
      });
    }

    return hashes;
  }

  function getDatagramLimit(datagrams) {
    if (!datagrams) {
      return 0;
    }

    const limit = Number(datagrams.maxDatagramSize);
    return Number.isFinite(limit) && limit > 0 ? limit : 0;
  }

  function canSendDatagram(limit, bytes, scope) {
    if (!limit || !bytes || bytes.byteLength <= limit) {
      return true;
    }

    logError(scope + " datagram exceeds maxDatagramSize", {
      attempted: bytes.byteLength,
      maxDatagramSize: limit
    });
    return false;
  }

  function normalizeAddress(address, defaultPath) {
    const input = (address || "").trim();
    if (!input) {
      return null;
    }

    try {
      let urlString = input;

      if (!/^[a-zA-Z][a-zA-Z0-9+.-]*:\/\//.test(urlString)) {
        urlString = "https://" + urlString;
      } else {
        urlString = urlString
          .replace(/^wt:\/\//i, "https://")
          .replace(/^webtransport:\/\//i, "https://");
      }

      const url = new URL(urlString);
      const path = (defaultPath && defaultPath.length) ? defaultPath : "/quake3";

      url.protocol = "https:";
      if (!url.port) {
        url.port = "27960";
      }
      if (!url.pathname || url.pathname === "/") {
        url.pathname = path;
      }

      return {
        url: url.toString(),
        label: url.host,
        port: Number(url.port) || 27960
      };
    } catch (error) {
      logError("NET_WT: invalid address", error);
      return null;
    }
  }

  const state = {
    inbound: [],
    clientRoutes: new Map(),
    client: null,
    server: null,
    nextPeerId: 1,

    isNode() {
      return typeof process !== "undefined" && !!(process.versions && process.versions.node);
    },

    isSupported() {
      if (this.isNode()) {
        return true;
      }

      return typeof WebTransport === "function";
    },

    normalizeAddress,

    registerClientRoute(id, url, label, port, certHashes) {
      this.clientRoutes.set(id, {
        id,
        url,
        label,
        port,
        certHashes
      });
    },

    async ensureClient(routeId) {
      const route = this.clientRoutes.get(routeId);
      if (!route) {
        return null;
      }

      if (this.client && this.client.routeId === routeId) {
        return this.client;
      }

      if (this.client) {
        this.closeClient(this.client);
      }

      if (typeof WebTransport !== "function") {
        logError("NET_WT: browser does not expose WebTransport");
        return null;
      }

      const options = {};
      const certHashes = parseCertHashes(route.certHashes);
      if (certHashes.length > 0) {
        options.serverCertificateHashes = certHashes;
      }

      let transport;
      try {
        transport = new WebTransport(route.url, options);
      } catch (error) {
        logError("NET_WT: failed to create client transport", error);
        return null;
      }

      const client = {
        routeId,
        route,
        transport,
        writer: null,
        maxDatagramSize: 0,
        pending: [],
        closed: false
      };

      this.client = client;

      transport.ready.then(async () => {
        if (this.client !== client) {
          return;
        }

        try {
          const writable = transport.datagrams.writable || transport.datagrams.createWritable();
          client.maxDatagramSize = getDatagramLimit(transport.datagrams);
          client.writer = writable.getWriter();
          this.flushClient(client);
          this.readClientDatagrams(client);
          if (client.maxDatagramSize) {
            log("NET_WT: client maxDatagramSize " + client.maxDatagramSize);
          }
          log("NET_WT: connected " + route.url);
        } catch (error) {
          logError("NET_WT: failed to initialize client datagrams", error);
        }
      }).catch((error) => {
        if (this.client === client) {
          this.client = null;
        }
        client.closed = true;
        logError("NET_WT: client ready failed", error);
      });

      transport.closed.then(() => {
        if (this.client === client) {
          this.client = null;
        }
        client.closed = true;
        log("NET_WT: client transport closed");
      }).catch((error) => {
        if (this.client === client) {
          this.client = null;
        }
        client.closed = true;
        logError("NET_WT: client transport closed with error", error);
      });

      return client;
    },

    flushClient(client) {
      if (!client || !client.writer) {
        return;
      }

      while (client.pending.length > 0) {
        const packet = client.pending.shift();
        if (!canSendDatagram(client.maxDatagramSize, packet, "NET_WT: client")) {
          continue;
        }
        client.writer.write(packet).catch((error) => {
          logError("NET_WT: client datagram write failed", error);
        });
      }
    },

    async readClientDatagrams(client) {
      const reader = client.transport.datagrams.readable.getReader();

      try {
        while (this.client === client) {
          const { done, value } = await reader.read();
          if (done) {
            break;
          }

          this.inbound.push({
            peerId: client.routeId,
            port: client.route.port || 27960,
            label: client.route.label,
            data: new Uint8Array(value)
          });
        }
      } catch (error) {
        if (this.client === client) {
          logError("NET_WT: client datagram read failed", error);
        }
      } finally {
        try {
          reader.releaseLock();
        } catch (error) {
          void error;
        }
      }
    },

    closeClient(client) {
      if (!client || client.closed) {
        return;
      }

      client.closed = true;

      try {
        if (client.writer) {
          client.writer.releaseLock();
        }
      } catch (error) {
        void error;
      }

      try {
        client.transport.close({
          closeCode: 0,
          reason: "ioq3 shutdown"
        });
      } catch (error) {
        void error;
      }
    },

    async startServer(config) {
      if (!this.isNode()) {
        logError("NET_WT: dedicated server runtime requires Node");
        return;
      }

      this.stop();

      const serverState = {
        config,
        peers: new Map(),
        sessionReader: null,
        server: null
      };
      this.server = serverState;

      try {
        const [{ Http3Server }, fs, crypto] = await Promise.all([
          import("@fails-components/webtransport"),
          import("node:fs"),
          import("node:crypto")
        ]);

        if (this.server !== serverState) {
          return;
        }

        const cert = fs.readFileSync(config.certFile, "utf8");
        const privKey = fs.readFileSync(config.keyFile, "utf8");
        const host = config.host || "0.0.0.0";
        const port = Number(config.port) || 27960;
        const path = (config.path && config.path.length) ? config.path : "/quake3";
        const certificate = new crypto.X509Certificate(cert);
        const publicKeyType =
          certificate.publicKey && certificate.publicKey.asymmetricKeyType
            ? certificate.publicKey.asymmetricKeyType
            : "unknown";

        if (config.allowedOrigins) {
          log("NET_WT: sv_wt_allowed_origins is not enforced yet");
        }

        if (publicKeyType === "rsa") {
          throw new Error(
            "NET_WT: RSA certificates are not supported for WebTransport. " +
            "Use an ECDSA certificate, for example prime256v1."
          );
        }

        serverState.server = new Http3Server({
          port,
          host,
          secret: "ioq3-webtransport",
          cert,
          privKey
        });

        const fingerprint = certificate.fingerprint256;
        log("NET_WT: certificate fingerprint sha-256 " + fingerprint);
        log("NET_WT: certificate key type " + publicKeyType);

        const sessionStream = await serverState.server.sessionStream(path);
        serverState.sessionReader = sessionStream.getReader();
        serverState.server.startServer();

        log("NET_WT: listening on https://" + host + ":" + port + path);
        this.acceptServerSessions(serverState);
      } catch (error) {
        if (this.server === serverState) {
          this.server = null;
        }
        logError("NET_WT: failed to start server", error);
      }
    },

    async acceptServerSessions(serverState) {
      try {
        while (this.server === serverState) {
          const { done, value } = await serverState.sessionReader.read();
          if (done) {
            break;
          }

          try {
            await value.ready;
          } catch (error) {
            logError("NET_WT: session handshake failed", error);
            continue;
          }

          if (this.server !== serverState) {
            break;
          }

          const peerId = this.nextPeerId++;
          const peer = {
            id: peerId,
            label: value.peerAddress || ("peer-" + peerId),
            port: 0,
            session: value,
            writer: (value.datagrams.writable || value.datagrams.createWritable()).getWriter(),
            maxDatagramSize: getDatagramLimit(value.datagrams)
          };

          serverState.peers.set(peerId, peer);
          if (peer.maxDatagramSize) {
            log("NET_WT: peer " + peerId + " maxDatagramSize " + peer.maxDatagramSize);
          }
          log("NET_WT: accepted session " + peerId + " from " + peer.label);

          value.closed.then(() => {
            if (serverState.peers.get(peerId) === peer) {
              serverState.peers.delete(peerId);
            }
          }).catch((error) => {
            if (serverState.peers.get(peerId) === peer) {
              serverState.peers.delete(peerId);
            }
            logError("NET_WT: session closed with error", error);
          });

          this.readServerDatagrams(serverState, peer);
        }
      } catch (error) {
        if (this.server === serverState) {
          logError("NET_WT: session accept loop failed", error);
        }
      }
    },

    async readServerDatagrams(serverState, peer) {
      const reader = peer.session.datagrams.readable.getReader();

      try {
        while (this.server === serverState && serverState.peers.get(peer.id) === peer) {
          const { done, value } = await reader.read();
          if (done) {
            break;
          }

          this.inbound.push({
            peerId: peer.id,
            port: peer.port,
            label: peer.label,
            data: new Uint8Array(value)
          });
        }
      } catch (error) {
        if (this.server === serverState) {
          logError("NET_WT: server datagram read failed", error);
        }
      } finally {
        try {
          reader.releaseLock();
        } catch (error) {
          void error;
        }
      }
    },

    dequeuePacket(maxLength) {
      const packet = this.inbound.shift();
      if (!packet) {
        return null;
      }

      const length = packet.data.byteLength;
      if (length > maxLength) {
        return {
          peerId: packet.peerId,
          port: packet.port || 0,
          label: packet.label || "",
          length
        };
      }

      return {
        peerId: packet.peerId,
        port: packet.port || 0,
        label: packet.label || "",
        length,
        data: packet.data
      };
    },

    sendPacket(peerId, bytes) {
      if (this.server && this.server.peers.has(peerId)) {
        const peer = this.server.peers.get(peerId);
        if (!canSendDatagram(peer.maxDatagramSize, bytes, "NET_WT: server")) {
          return false;
        }
        peer.writer.write(bytes).catch((error) => {
          logError("NET_WT: server datagram write failed", error);
        });
        return true;
      }

      const route = this.clientRoutes.get(peerId);
      if (!route) {
        return false;
      }

      this.ensureClient(peerId);

      if (!this.client || this.client.routeId !== peerId) {
        return false;
      }

      if (this.client.writer) {
        if (!canSendDatagram(this.client.maxDatagramSize, bytes, "NET_WT: client")) {
          return false;
        }
        this.client.writer.write(bytes).catch((error) => {
          logError("NET_WT: client datagram write failed", error);
        });
      } else {
        this.client.pending.push(bytes);
      }

      return true;
    },

    stop() {
      this.inbound.length = 0;

      if (this.client) {
        this.closeClient(this.client);
        this.client = null;
      }

      if (this.server) {
        for (const peer of this.server.peers.values()) {
          try {
            peer.writer.releaseLock();
          } catch (error) {
            void error;
          }

          try {
            peer.session.close({
              closeCode: 0,
              reason: "ioq3 shutdown"
            });
          } catch (error) {
            void error;
          }
        }

        if (this.server.sessionReader) {
          try {
            this.server.sessionReader.cancel();
          } catch (error) {
            void error;
          }
        }

        if (this.server.server) {
          try {
            this.server.server.stopServer();
          } catch (error) {
            void error;
          }
        }

        this.server = null;
      }
    }
  };

  Module.__ioq3WebTransport = state;
})();
