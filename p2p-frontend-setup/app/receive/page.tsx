"use client";

import { useEffect, useRef, useState } from "react";
import { useSearchParams } from "next/navigation";
import { Button } from "@/components/ui/button";
import { WifiAnimation } from "@/components/wifi-animation";
import { ThemeToggle } from "@/components/theme-toggle";
import {
  DownloadIcon,
  ArrowLeft,
  WifiIcon,
  Loader2Icon,
  CheckIcon,
  AlertCircleIcon,
} from "lucide-react";
import Link from "next/link";

export default function ReceivePage() {
  const searchParams = useSearchParams();
  const senderId = searchParams.get("id");

  const [isConnected, setIsConnected] = useState(false);
  const [isConnecting, setIsConnecting] = useState(false);
  const [fileMetadata, setFileMetadata] = useState<{
    name: string;
    size: number;
  } | null>(null);
  const [transferProgress, setTransferProgress] = useState(0);
  const [fileUrl, setFileUrl] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);

  const receivedBytes = useRef<number>(0);
  const fileSizeRef = useRef<number>(0);
  const wsRef = useRef<WebSocket | null>(null);
  const receivedChunksRef = useRef<ArrayBuffer[]>([]);
  const reconnectAttemptsRef = useRef(0);
  const MAX_RECONNECT_ATTEMPTS = 5;
  const RECONNECT_DELAY = 3000;

  // ── Encryption state ────────────────────────────────────────────────────────
  const sessionKeyRef = useRef<CryptoKey | null>(null);

  // ── Helpers ─────────────────────────────────────────────────────────────────

  /** Import the base64 key sent by the server into a WebCrypto CryptoKey */
  const importSessionKey = async (base64Key: string): Promise<CryptoKey> => {
    const raw = Uint8Array.from(atob(base64Key), (c) => c.charCodeAt(0));
    return crypto.subtle.importKey(
      "raw",
      raw,
      { name: "AES-GCM" },
      false,
      ["encrypt", "decrypt"]
    );
  };

  /**
   * Decrypt a binary chunk received from the server.
   * Expected layout: nonce (12 bytes) || AES-GCM ciphertext
   */
  const decryptChunk = async (payload: ArrayBuffer): Promise<ArrayBuffer> => {
    if (!sessionKeyRef.current) throw new Error("No session key");
    if (payload.byteLength < 12) throw new Error("Payload too short");

    const nonce = payload.slice(0, 12);
    const ciphertext = payload.slice(12);

    return crypto.subtle.decrypt(
      { name: "AES-GCM", iv: nonce },
      sessionKeyRef.current,
      ciphertext
    );
  };

  // ── File handling ────────────────────────────────────────────────────────────

  const handleFileInfo = (data: { name: string; size: number }) => {
    setFileMetadata({ name: data.name, size: data.size });
    fileSizeRef.current = data.size;
    receivedChunksRef.current = [];
    receivedBytes.current = 0;
    setTransferProgress(0);
    setError(null);
  };

  /** Called with the already-decrypted plaintext of each chunk */
  const handleDecryptedChunk = (plaintext: ArrayBuffer) => {
    if (!plaintext || plaintext.byteLength === 0) return;

    receivedChunksRef.current.push(plaintext);
    const newReceivedBytes = receivedBytes.current + plaintext.byteLength;
    receivedBytes.current = newReceivedBytes;

    if (fileSizeRef.current > 0) {
      const progress = Math.min(
        100,
        Math.floor((newReceivedBytes / fileSizeRef.current) * 100)
      );
      setTransferProgress(progress);
    }
  };

  // ── WebSocket ────────────────────────────────────────────────────────────────

  const connectWebSocket = () => {
    if (!senderId) return;

    setIsConnecting(true);
    setError(null);
    receivedChunksRef.current = [];
    receivedBytes.current = 0;
    setTransferProgress(0);

    const ws = new WebSocket(`ws://${window.location.hostname}:8000/ws`);
    wsRef.current = ws;

    ws.onopen = () => {
      reconnectAttemptsRef.current = 0;

      const connectionId =
        typeof crypto.randomUUID === "function"
          ? crypto.randomUUID()
          : "fallback" + Math.random().toString(36).substring(2, 15);

      ws.send(JSON.stringify({ type: "register", connectionId }));
      ws.send(
        JSON.stringify({
          target_id: senderId,
          type: "receiver-ready",
          senderId: connectionId,
        })
      );

      setIsConnected(true);
      setIsConnecting(false);
    };

    ws.onmessage = async (event) => {
      // ── Text / JSON messages ───────────────────────────────────────────────
      if (typeof event.data === "string") {
        try {
          const data = JSON.parse(event.data);

          // ── Receive session key from server ────────────────────────────────
          if (data.type === "session_key") {
            try {
              sessionKeyRef.current = await importSessionKey(data.key);
              console.log("Session key imported — channel is encrypted");
            } catch (e) {
              console.error("Failed to import session key:", e);
            }
            return;
          }

          if (data.type === "file-info") {
            handleFileInfo(data);
          } else if (data.type === "file-end") {
            const expectedSize = data.totalBytes || fileMetadata?.size || 0;
            window.setTimeout(() => {
              if (receivedBytes.current >= expectedSize * 0.95) {
                completeFileTransfer();
              }
            }, 500);
          }
        } catch (e) {
          console.error("Error processing message:", e);
        }
        return;
      }

      // ── Binary messages (encrypted chunks) ────────────────────────────────
      let raw: ArrayBuffer | null = null;

      if (event.data instanceof ArrayBuffer) {
        raw = event.data;
      } else if (event.data instanceof Blob) {
        raw = await event.data.arrayBuffer();
      }

      if (!raw) return;

      // ── Decrypt the chunk ──────────────────────────────────────────────────
      if (!sessionKeyRef.current) {
        console.error("Binary chunk arrived before session key — dropping");
        return;
      }

      try {
        const plaintext = await decryptChunk(raw);
        handleDecryptedChunk(plaintext);
      } catch (e) {
        console.error("Decryption failed for chunk:", e);
        setError("Decryption failed — file may be corrupted.");
      }
    };

    ws.onerror = (err) => {
      console.error("WebSocket error:", err);
      setIsConnecting(false);
    };

    ws.onclose = () => {
      setIsConnected(false);
      setIsConnecting(false);
      sessionKeyRef.current = null;

      if (reconnectAttemptsRef.current < MAX_RECONNECT_ATTEMPTS) {
        reconnectAttemptsRef.current++;
        window.setTimeout(connectWebSocket, RECONNECT_DELAY);
      }
    };
  };

  // ── Assemble file ────────────────────────────────────────────────────────────

  const completeFileTransfer = () => {
    try {
      if (receivedChunksRef.current.length === 0) {
        throw new Error("No data received — transfer failed");
      }

      const blob = new Blob(receivedChunksRef.current, {
        type: "application/octet-stream",
      });

      if (blob.size === 0) throw new Error("Received empty file");

      setFileUrl(URL.createObjectURL(blob));
      setError(null);
    } catch (e) {
      console.error("Error completing transfer:", e);
      setError(String(e));
    }
  };

  const downloadFile = () => {
    if (!fileUrl || !fileMetadata) return;
    const a = document.createElement("a");
    a.href = fileUrl;
    a.download = fileMetadata.name;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
  };

  // ── Cleanup ──────────────────────────────────────────────────────────────────

  useEffect(() => {
    return () => {
      wsRef.current?.close();
    };
  }, []);

  // ── Render ───────────────────────────────────────────────────────────────────

  return (
    <div className="min-h-screen flex flex-col">
      <header className="container flex items-center justify-between p-4">
        <Link href="/">
          <Button variant="ghost" size="icon">
            <ArrowLeft className="h-5 w-5" />
            <span className="sr-only">Back</span>
          </Button>
        </Link>
        <ThemeToggle />
      </header>

      <main className="flex-1 container flex flex-col items-center justify-center py-8 max-w-md">
        <div className="w-full space-y-8">
          {!senderId ? (
            <div className="text-center space-y-4">
              <div className="w-12 h-12 mx-auto rounded-full bg-secondary flex items-center justify-center">
                <WifiIcon className="h-6 w-6" />
              </div>
              <h1 className="text-2xl font-bold">No Transfer ID</h1>
              <p className="text-muted-foreground">
                You need a transfer ID to receive files. Ask the sender to
                generate a link.
              </p>
              <Link href="/" className="inline-block mt-2">
                <Button>Go to Home</Button>
              </Link>
            </div>
          ) : !isConnected && !isConnecting ? (
            <>
              <div className="text-center space-y-2">
                <h1 className="text-2xl font-bold">Ready to Receive</h1>
                <p className="text-muted-foreground">
                  Connect to the server to receive the file
                </p>
              </div>

              <div className="flex flex-col items-center my-6">
                <WifiAnimation active={false} />
                {error && (
                  <div className="w-full p-4 bg-red-100 dark:bg-red-900/30 rounded-lg flex items-start space-x-3">
                    <AlertCircleIcon className="h-5 w-5 text-red-600 dark:text-red-400 mt-0.5" />
                    <p className="text-sm text-red-800 dark:text-red-200">
                      {error}
                    </p>
                  </div>
                )}
              </div>

              <div className="text-center mb-6">
                <div className="inline-block px-4 py-2 rounded-lg bg-secondary text-sm">
                  Transfer ID: {senderId}
                </div>
              </div>

              <Button className="w-full" onClick={connectWebSocket}>
                Connect to Server
              </Button>
            </>
          ) : isConnecting ? (
            <div className="text-center space-y-4">
              <div className="w-12 h-12 mx-auto rounded-full bg-secondary flex items-center justify-center">
                <Loader2Icon className="h-6 w-6 animate-spin" />
              </div>
              <h1 className="text-2xl font-bold">Connecting...</h1>
              <p className="text-muted-foreground">
                Establishing secure WebSocket connection with the server
              </p>
            </div>
          ) : fileUrl ? (
            <>
              <div className="text-center space-y-4">
                <div className="w-12 h-12 mx-auto rounded-full bg-secondary flex items-center justify-center">
                  <CheckIcon className="h-6 w-6" />
                </div>
                <h1 className="text-2xl font-bold">Transfer Complete</h1>
                <p className="text-muted-foreground">
                  {fileMetadata?.name} (
                  {((fileMetadata?.size ?? 0) / 1024 / 1024).toFixed(2)} MB)
                </p>
              </div>

              <Button className="w-full" onClick={downloadFile}>
                <DownloadIcon className="mr-2 h-4 w-4" />
                Download File
              </Button>
            </>
          ) : (
            <>
              <div className="text-center space-y-2">
                <h1 className="text-2xl font-bold">Receiving File</h1>
                {fileMetadata && (
                  <p className="text-muted-foreground">
                    {fileMetadata.name} (
                    {(fileMetadata.size / 1024 / 1024).toFixed(2)} MB)
                  </p>
                )}
              </div>

              <div className="flex flex-col items-center my-6">
                <WifiAnimation active={true} />
              </div>

              <div className="w-full space-y-4">
                <div className="flex justify-between text-sm">
                  <span>Transferring...</span>
                  <span>{transferProgress}%</span>
                </div>
                <div className="progress-bar">
                  <div
                    className="progress-bar-fill"
                    style={{ width: `${transferProgress}%` }}
                  ></div>
                </div>

                <div className="flex items-center justify-center mt-4 text-sm text-muted-foreground p-3 rounded-lg bg-secondary">
                  <Loader2Icon className="h-4 w-4 animate-spin mr-2" />
                  <span>Please keep this window open</span>
                </div>
              </div>
            </>
          )}
        </div>
      </main>
    </div>
  );
}