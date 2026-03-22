"use client";

import type React from "react";

import { useState, useRef, useEffect } from "react";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { WifiAnimation } from "@/components/wifi-animation";
import { FileCard } from "@/components/file-card";
import { ThemeToggle } from "@/components/theme-toggle";
import {
  FileIcon,
  CopyIcon,
  CheckIcon,
  ArrowLeft,
  SendIcon,
  LinkIcon,
  Loader2Icon,
} from "lucide-react";
import { generateId } from "@/lib/utils";
import Link from "next/link";

export default function SendPage() {
  const [file, setFile] = useState<File | null>(null);
  const [fileSending, setFileSending] = useState(false);
  const [transferId, setTransferId] = useState<string | null>(null);
  const [copied, setCopied] = useState(false);
  const [isConnected, setIsConnected] = useState(false);
  const [transferProgress, setTransferProgress] = useState(0);
  const [isGeneratingLink, setIsGeneratingLink] = useState(false);
  const fileInputRef = useRef<HTMLInputElement>(null);
  const wsRef = useRef<WebSocket | null>(null);
  const recipientIdRef = useRef<string | null>(null);
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
   * Encrypt `plaintext` bytes with the session key.
   * Returns: nonce (12 bytes) || ciphertext
   */
  const encryptChunk = async (plaintext: Uint8Array): Promise<Uint8Array> => {
    if (!sessionKeyRef.current) throw new Error("No session key");

    const nonce = crypto.getRandomValues(new Uint8Array(12));
    const ciphertext = await crypto.subtle.encrypt(
      { name: "AES-GCM", iv: nonce },
      sessionKeyRef.current,
      plaintext.buffer as ArrayBuffer
    );

    const out = new Uint8Array(12 + ciphertext.byteLength);
    out.set(nonce, 0);
    out.set(new Uint8Array(ciphertext), 12);
    return out;
  };

  // ── File input ───────────────────────────────────────────────────────────────

  const handleFileSelect = (e: React.ChangeEvent<HTMLInputElement>) => {
    if (e.target.files && e.target.files.length > 0) {
      setFile(e.target.files[0]);
    }
  };

  const handleDrop = (e: React.DragEvent<HTMLDivElement>) => {
    e.preventDefault();
    if (e.dataTransfer.files && e.dataTransfer.files.length > 0) {
      setFile(e.dataTransfer.files[0]);
    }
  };

  const handleDragOver = (e: React.DragEvent<HTMLDivElement>) => {
    e.preventDefault();
  };

  // ── WebSocket ────────────────────────────────────────────────────────────────

  const connectWebSocket = () => {
    if (wsRef.current && wsRef.current.readyState === WebSocket.OPEN) {
      return wsRef.current;
    }

    const ws = new WebSocket(`ws://${window.location.hostname}:8000/ws`);
    wsRef.current = ws;

    ws.onopen = () => {
      reconnectAttemptsRef.current = 0;
      const connectionId = generateId(8);
      setTransferId(connectionId);
      setIsGeneratingLink(false);
      ws.send(
        JSON.stringify({
          type: "register",
          connectionId: connectionId,
        })
      );
    };

    ws.onmessage = async (event) => {
      if (typeof event.data === "string") {
        const data = JSON.parse(event.data);

        // ── Receive session key from server ──────────────────────────────────
        if (data.type === "session_key") {
          try {
            sessionKeyRef.current = await importSessionKey(data.key);
            console.log("Session key imported — channel is encrypted");
          } catch (e) {
            console.error("Failed to import session key:", e);
          }
          return;
        }

        if (data.type === "receiver-ready") {
          recipientIdRef.current = data.senderId;
          setIsConnected(true);
        } else if (data.type === "transfer-complete") {
          setTransferProgress(100);
        }
      }
    };

    ws.onerror = () => {
      setIsGeneratingLink(false);
    };

    ws.onclose = () => {
      setIsConnected(false);
      sessionKeyRef.current = null;

      if (reconnectAttemptsRef.current < MAX_RECONNECT_ATTEMPTS) {
        reconnectAttemptsRef.current++;
        window.setTimeout(connectWebSocket, RECONNECT_DELAY);
      }
    };

    return ws;
  };

  const generateReceiverLink = async () => {
    if (!file) return;
    setIsGeneratingLink(true);
    try {
      connectWebSocket();
    } catch {
      setIsGeneratingLink(false);
    }
  };

  // ── Copy link ────────────────────────────────────────────────────────────────

  const copyLink = () => {
    if (!transferId) return;
    const link = `${window.location.origin}/receive?id=${transferId}`;

    if (navigator.clipboard && window.isSecureContext) {
      navigator.clipboard
        .writeText(link)
        .then(() => {
          setCopied(true);
          window.setTimeout(() => setCopied(false), 2000);
        })
        .catch((err) => console.error("Clipboard copy failed:", err));
    } else {
      const textArea = document.createElement("textarea");
      textArea.value = link;
      textArea.style.position = "absolute";
      textArea.style.opacity = "0";
      document.body.appendChild(textArea);
      textArea.select();
      try {
        document.execCommand("copy");
        setCopied(true);
        window.setTimeout(() => setCopied(false), 2000);
      } catch (err) {
        console.error("Fallback copy failed:", err);
        alert("Failed to copy. Try manually selecting and copying the text.");
      }
      document.body.removeChild(textArea);
    }
  };

  // ── Send file (with encryption) ──────────────────────────────────────────────

  const sendFile = () => {
    if (!file || !wsRef.current || !recipientIdRef.current) return;

    // Guard: don't send if key hasn't arrived yet
    if (!sessionKeyRef.current) {
      console.error("Session key not ready — cannot send encrypted data");
      return;
    }

    setFileSending(true);
    const CHUNK_SIZE = 5 * 1024 * 1024; // 5 MB
    let offset = 0;
    let chunkCount = 0;

    // Send file metadata (plain JSON — no sensitive content)
    wsRef.current.send(
      JSON.stringify({
        target_id: recipientIdRef.current,
        type: "file-info",
        name: file.name,
        size: file.size,
        mimeType: file.type || "application/octet-stream",
      })
    );

    const reader = new FileReader();

    reader.onload = async (e) => {
      if (!e.target?.result) return;

      const plainChunk = new Uint8Array(e.target.result as ArrayBuffer);

      // ── Encrypt the chunk before sending ──────────────────────────────────
      let encryptedChunk: Uint8Array;
      try {
        encryptedChunk = await encryptChunk(plainChunk);
      } catch (err) {
        console.error("Encryption failed:", err);
        setFileSending(false);
        return;
      }

      // Send chunk metadata (JSON) then the encrypted binary payload
      wsRef.current?.send(
        JSON.stringify({
          target_id: recipientIdRef.current,
          type: "file-chunk",
          chunkNumber: chunkCount,
        })
      );
      wsRef.current?.send(encryptedChunk.buffer);

      offset += plainChunk.length;
      chunkCount++;

      const progress = Math.min(100, Math.floor((offset / file.size) * 100));
      setTransferProgress(progress);

      if (offset < file.size) {
        window.setTimeout(() => {
          const slice = file.slice(offset, offset + CHUNK_SIZE);
          reader.readAsArrayBuffer(slice);
        }, 0);
      } else {
        wsRef.current?.send(
          JSON.stringify({
            target_id: recipientIdRef.current,
            type: "file-end",
            chunkCount: chunkCount,
          })
        );
        setFileSending(false);
      }
    };

    reader.onerror = () => {
      setFileSending(false);
    };

    const slice = file.slice(offset, offset + CHUNK_SIZE);
    reader.readAsArrayBuffer(slice);
  };

  // ── Cleanup ──────────────────────────────────────────────────────────────────

  useEffect(() => {
    return () => {
      wsRef.current?.close();
    };
  }, []);

  // ── Render ───────────────────────────────────────────────────────────────────

  return (
    <div className="min-h-screen flex flex-col gradient-bg">
      <header className="container flex items-center justify-between p-4">
        <Link href="/">
          <Button
            variant="ghost"
            size="icon"
            className="rounded-full hover:bg-secondary/80"
          >
            <ArrowLeft className="h-5 w-5" />
            <span className="sr-only">Back</span>
          </Button>
        </Link>
        <ThemeToggle />
      </header>

      <main className="flex-1 container flex flex-col items-center justify-center py-8 max-w-md">
        <div className="w-full space-y-8">
          {!file && (
            <>
              <div className="text-center space-y-3">
                <h1 className="text-3xl font-bold">Send a File</h1>
                <p className="text-muted-foreground">
                  Select a file to share it securely via WebSocket
                </p>
              </div>

              <div
                className="w-full border-2 border-dashed border-border/50 rounded-xl p-10 text-center cursor-pointer hover:bg-secondary/50 transition-all group"
                onClick={() => fileInputRef.current?.click()}
                onDrop={handleDrop}
                onDragOver={handleDragOver}
              >
                <Input
                  type="file"
                  ref={fileInputRef}
                  onChange={handleFileSelect}
                  className="hidden"
                />
                <div className="w-16 h-16 mx-auto rounded-xl bg-secondary/80 flex items-center justify-center mb-4 group-hover:scale-105 transition-transform">
                  <FileIcon className="h-7 w-7" />
                </div>
                <p className="text-base font-medium mb-1">
                  Drag and drop your file here
                </p>
                <p className="text-sm text-muted-foreground">or click to browse</p>
              </div>
            </>
          )}

          {file && !transferId && (
            <>
              <div className="text-center space-y-3">
                <h1 className="text-3xl font-bold">File Selected</h1>
                <p className="text-muted-foreground mb-4">
                  Ready to generate a transfer link
                </p>
              </div>

              <FileCard file={file} className="mb-6" />

              <Button
                className="w-full py-6 rounded-xl hover-lift"
                onClick={generateReceiverLink}
                disabled={isGeneratingLink}
              >
                {isGeneratingLink ? (
                  <>
                    <Loader2Icon className="mr-2 h-5 w-5 animate-spin" />
                    Generating Link...
                  </>
                ) : (
                  <>
                    <LinkIcon className="mr-2 h-5 w-5" />
                    Generate Transfer Link
                  </>
                )}
              </Button>
            </>
          )}

          {file && transferId && (
            <>
              <div className="text-center space-y-3">
                <h1 className="text-3xl font-bold">Ready to Transfer</h1>
                <p className="text-muted-foreground mb-4">
                  Share this link with the recipient
                </p>
              </div>

              <div className="flex flex-col items-center mb-6">
                <WifiAnimation active={isConnected} />
              </div>

              <div className="flex w-full mb-6">
                <div className="relative flex-1">
                  <div className="flex">
                    <Input
                      value={`${window.location.origin}/receive?id=${transferId}`}
                      readOnly
                      className="pr-10 rounded-r-none border-r-0 focus-visible:ring-0 focus-visible:ring-offset-0"
                    />
                    <Button
                      variant="secondary"
                      size="icon"
                      className="rounded-l-none"
                      onClick={copyLink}
                    >
                      {copied ? (
                        <CheckIcon className="h-4 w-4 text-green-500" />
                      ) : (
                        <CopyIcon className="h-4 w-4" />
                      )}
                    </Button>
                  </div>
                </div>
              </div>

              <FileCard file={file} className="mb-6" />

              {isConnected ? (
                <div className="w-full space-y-4">
                  {transferProgress > 0 ? (
                    <div className="space-y-3">
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
                    </div>
                  ) : (
                    <Button
                      className="w-full py-6 rounded-xl hover-lift"
                      onClick={sendFile}
                      disabled={fileSending || !sessionKeyRef.current}
                    >
                      {fileSending ? (
                        <Loader2Icon className="mr-2 h-5 w-5 animate-spin" />
                      ) : (
                        <SendIcon className="mr-2 h-5 w-5" />
                      )}
                      Send File
                    </Button>
                  )}
                </div>
              ) : (
                <div className="flex items-center justify-center space-x-2 text-sm text-muted-foreground p-4 rounded-xl bg-secondary/50 glass">
                  <div className="dot-pulse"></div>
                  <span className="ml-6">Waiting for recipient to connect...</span>
                </div>
              )}
            </>
          )}
        </div>
      </main>
    </div>
  );
}