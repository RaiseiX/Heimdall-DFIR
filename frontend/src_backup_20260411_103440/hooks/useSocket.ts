import { useEffect, useRef, useState, useCallback } from 'react';
import { io, Socket } from 'socket.io-client';
import type { SocketHookReturn } from '../types/forensic';

const SOCKET_URL =
  typeof window !== 'undefined'
    ? `${window.location.protocol}//${window.location.host}`
    : 'http://localhost:4000';

export function useSocket(): SocketHookReturn {
  const socketRef = useRef<Socket | null>(null);
  const [isConnected, setIsConnected] = useState(false);
  const [socketId, setSocketId] = useState<string | null>(null);

  useEffect(() => {
    if (!localStorage.getItem('heimdall_token')) return;

    const socket = io(SOCKET_URL, {
      auth: (cb: (data: { token: string }) => void) => {
        cb({ token: localStorage.getItem('heimdall_token') ?? '' });
      },
      transports: ['polling', 'websocket'],
      reconnectionAttempts: 10,
      reconnectionDelay: 1000,
      reconnectionDelayMax: 10000,
    });

    socketRef.current = socket;

    socket.on('connect', () => {
      setIsConnected(true);
      setSocketId(socket.id ?? null);
    });

    socket.on('disconnect', () => {
      setIsConnected(false);
      setSocketId(null);
    });

    socket.on('connect_error', (err: Error) => {
      console.warn('[Socket.io] Erreur connexion:', err.message);
    });

    return () => {
      socket.disconnect();
      socketRef.current = null;
      setIsConnected(false);
      setSocketId(null);
    };
  }, []);

  return { socket: socketRef.current, isConnected, socketId };
}

export function useSocketEvent<T>(
  socket: Socket | null,
  event: string,
  callback: (data: T) => void
): void {
  const callbackRef = useRef(callback);
  callbackRef.current = callback;

  useEffect(() => {
    if (!socket) return;
    const handler = (data: T) => callbackRef.current(data);
    socket.on(event, handler);
    return () => { socket.off(event, handler); };
  }, [socket, event]);
}
