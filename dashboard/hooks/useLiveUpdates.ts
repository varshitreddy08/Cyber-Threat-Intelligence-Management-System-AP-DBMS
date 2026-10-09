"use client";
import { useEffect, useRef, useCallback } from "react";
import { wsUrl } from "@/lib/api";

type Handler = (event: string, data: unknown) => void;

export function useLiveUpdates(onMessage: Handler) {
  const wsRef  = useRef<WebSocket | null>(null);
  const pingRef = useRef<ReturnType<typeof setInterval> | null>(null);

  const connect = useCallback(() => {
    if (wsRef.current?.readyState === WebSocket.OPEN) return;

    const ws = new WebSocket(wsUrl("/ws/live"));
    wsRef.current = ws;

    ws.onmessage = (e) => {
      try {
        const { event, data } = JSON.parse(e.data);
        onMessage(event, data);
      } catch { /* ignore */ }
    };

    ws.onopen = () => {
      // Keep alive with a ping every 25 seconds
      pingRef.current = setInterval(() => {
        if (ws.readyState === WebSocket.OPEN) ws.send("ping");
      }, 25000);
    };

    ws.onclose = () => {
      if (pingRef.current) clearInterval(pingRef.current);
      // Reconnect after 3 seconds
      setTimeout(connect, 3000);
    };

    ws.onerror = () => ws.close();
  }, [onMessage]);

  useEffect(() => {
    connect();
    return () => {
      if (pingRef.current) clearInterval(pingRef.current);
      wsRef.current?.close();
    };
  }, [connect]);
}
